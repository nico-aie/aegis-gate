// Fast mock upstream for the prod-balanced 5k+ RPS stress test.
//
// Mirrors the public surface of the Python upstream (server.py) but
// uses Go's net/http which trivially handles 50k+ RPS on loopback.
// We use this when the WAF is the system under test and the upstream
// must NOT be the bottleneck.
//
// Build:    go build -o fast-upstream tests/hackathon/upstream/fast-upstream.go
// Run:      ./fast-upstream  (binds 127.0.0.1:9999)
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type Account struct {
	Password string `json:"-"`
	OTP      string `json:"-"`
	Balance  int    `json:"balance"`
}

var (
	users = map[string]Account{
		"alice":   {"P@ssw0rd1", "123456", 5000},
		"bob":     {"S3cureP@ss", "654321", 1200},
		"charlie": {"Ch@rlie99", "111222", 300},
	}
	loginTokens sync.Map // token -> username
	sessions    sync.Map // sid   -> username
)

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	acct, ok := users[in.Username]
	if !ok || acct.Password != in.Password {
		writeJSON(w, 401, map[string]string{"error": "bad_credentials"})
		return
	}
	tok := newToken()
	loginTokens.Store(tok, in.Username)
	writeJSON(w, 200, map[string]any{
		"login_token": tok,
		"need_otp":    true,
	})
}

func handleOTP(w http.ResponseWriter, r *http.Request) {
	var in struct{ LoginToken, OTPCode string }
	body, _ := decode(r)
	in.LoginToken, _ = body["login_token"].(string)
	in.OTPCode, _ = body["otp_code"].(string)
	uname, ok := loginTokens.Load(in.LoginToken)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "bad_token"})
		return
	}
	if users[uname.(string)].OTP != in.OTPCode {
		writeJSON(w, 401, map[string]string{"error": "bad_otp"})
		return
	}
	sid := newToken()
	sessions.Store(sid, uname)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
	writeJSON(w, 200, map[string]any{"session": sid, "user": uname})
}

func decode(r *http.Request) (map[string]any, error) {
	out := map[string]any{}
	err := json.NewDecoder(r.Body).Decode(&out)
	return out, err
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"user":        "alice",
		"display":     "Alice",
		"balance":     5000,
		"verified":    true,
		"role":        "user",
	})
}

func handleGameList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"games": []map[string]any{
			{"id": "g1", "name": "Game One", "min_bet": 1},
			{"id": "g2", "name": "Game Two", "min_bet": 5},
		},
	})
}

func handleGameById(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"id": "g1", "name": "Game One",
		"min_bet": 1, "max_bet": 100,
	})
}

func handleGamePlay(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"result": "win", "payout": 5,
	})
}

func handleTransactions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"transactions": []map[string]any{
			{"id": 1, "amount": 10, "type": "credit"},
			{"id": 2, "amount": -5, "type": "debit"},
		},
		"total": 2,
	})
}

func handleRewardsClaim(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"claimed": 25})
}

func handleFeedback(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "thanks"})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// WebSocket — minimal RFC 6455 echo, stdlib-only so this stays a
// single-file zero-dependency build (built via `go build fast-upstream.go`).
//
// Why this exists: the dev profile forwards WS routes (e.g. /ws/live) to
// this upstream at 127.0.0.1:9999. Without a WS handler the upstream
// accepts the 101 then EOFs immediately, so the WAF's ws bridge exits
// before any frame is relayed and ws_inspect never runs (client sees a
// bare 1006 close). Echoing frames keeps the bridge alive long enough for
// the inspector to see them. Unfragmented text/binary frames + ping/close
// only — enough for the WS attack/inspection tests; not a full WS stack.
// ---------------------------------------------------------------------------

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func isWSUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket: no hijack", http.StatusInternalServerError)
		return
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"); err != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	fmt.Printf("[ws] open path=%s\n", r.URL.Path)
	for {
		op, payload, err := wsRead(rw.Reader)
		if err != nil {
			break
		}
		switch op {
		case 0x8: // close → echo close, done
			_ = wsWrite(rw, 0x8, payload)
			_ = rw.Flush()
			fmt.Println("[ws] close")
			return
		case 0x9: // ping → pong
			_ = wsWrite(rw, 0xA, payload)
			_ = rw.Flush()
		case 0x1, 0x2: // text / binary → echo (text "bye" closes)
			if op == 0x1 && strings.TrimSpace(string(payload)) == "bye" {
				_ = wsWrite(rw, 0x1, []byte("bye"))
				_ = rw.Flush()
				return
			}
			if wsWrite(rw, op, payload) != nil || rw.Flush() != nil {
				return
			}
		}
	}
}

// wsRead reads one client frame (always masked per RFC 6455) and returns
// its opcode + unmasked payload. Assumes unfragmented frames.
func wsRead(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	h := make([]byte, 2)
	if _, err = io.ReadFull(r, h); err != nil {
		return
	}
	opcode = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := int(h[1] & 0x7F)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		n = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		n = int(binary.BigEndian.Uint64(ext))
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err = io.ReadFull(r, mask); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return
}

// wsWrite writes one unmasked server frame (FIN=1) — server→client frames
// are never masked.
func wsWrite(w *bufio.ReadWriter, opcode byte, payload []byte) error {
	b0 := byte(0x80) | opcode
	n := len(payload)
	var hdr []byte
	switch {
	case n < 126:
		hdr = []byte{b0, byte(n)}
	case n < 65536:
		hdr = []byte{b0, 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0], hdr[1] = b0, 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// Default catch-all for /. Returns a friendly landing JSON so
// `curl localhost:8080/` succeeds rather than 404'ing on the
// stub mux.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	// WS upgrade on any non-registered path (the dev catch-all routes
	// everything here) gets the same-port WebSocket echo.
	if isWSUpgrade(r) {
		handleWS(w, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, 200, map[string]any{
		"service": "aegis-fast-upstream",
		"status":  "ok",
		"hint":    "see /health, /game/list, /api/profile, /sitemap.xml",
	})
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, "// static asset placeholder\n")
}

func handlePublic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprint(w, "User-agent: *\nDisallow:\n")
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"requests_24h": 12345, "errors_24h": 23,
	})
}

func handleAbout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprint(w, "<html><body>About</body></html>\n")
}

func handleSitemap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	_, _ = fmt.Fprint(w, "<?xml version=\"1.0\"?><urlset/>\n")
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/otp", handleOTP)
	mux.HandleFunc("/api/profile", handleProfile)
	mux.HandleFunc("/api/transactions", handleTransactions)
	mux.HandleFunc("/api/rewards/claim", handleRewardsClaim)
	mux.HandleFunc("/api/feedback", handleFeedback)
	mux.HandleFunc("/api/public/stats", handleStats)
	mux.HandleFunc("/game/list", handleGameList)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/about", handleAbout)
	mux.HandleFunc("/sitemap.xml", handleSitemap)

	// Prefix-match routes
	mux.HandleFunc("/game/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/play") {
			handleGamePlay(w, r)
			return
		}
		handleGameById(w, r)
	})
	mux.HandleFunc("/static/", handleStatic)
	mux.HandleFunc("/public/", handlePublic)

	// /ws/ (and any WS-upgrade request) is handled by the catch-all via
	// isWSUpgrade → handleWS; no separate registration needed.

	bind := "127.0.0.1:9999"
	fmt.Printf("fast-upstream listening on %s (HTTP + WebSocket)\n", bind)
	srv := &http.Server{
		Addr:    bind,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("listen error:", err)
	}
}
