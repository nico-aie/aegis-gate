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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	bind := "127.0.0.1:9999"
	fmt.Printf("fast-upstream listening on %s\n", bind)
	srv := &http.Server{
		Addr:    bind,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("listen error:", err)
	}
}
