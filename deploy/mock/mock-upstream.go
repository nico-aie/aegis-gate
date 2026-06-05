// Multi-protocol mock upstream for Aegis-Gate fleet testing.
//
// One binary serving every protocol the WAF forwards, so each upstream
// path can be exercised end-to-end:
//
//	--http :9991   HTTP/1.1 + h2c   (echo + a small API surface)
//	--ws   :9992   WebSocket        (frame echo; "bye" closes)
//	--grpc :9993   gRPC (HTTP/2)    (echoes ANY method; see echo.proto)
//	--tcp  :9994   raw TCP          (byte echo; for scheme:tcp upstreams)
//
// Each flag is independent; pass "" to disable a listener. Every
// connection logs its protocol so you can confirm the WAF routed it.
//
// Build:  cd deploy/mock && go mod tidy && go build -o aegis-mock .
// See:    deploy/HACKATHON-DEPLOY.md §5, deploy/HACKATHON-FLEET.md §5.
//
// NOTE: this is the *coverage* mock (all protocols). For 5k-RPS HTTP
// throughput stress, use tests/hackathon/upstream/fast-upstream.go.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

func main() {
	httpAddr := flag.String("http", ":9991", "HTTP/1.1+h2c listen addr (\"\" disables)")
	wsAddr := flag.String("ws", ":9992", "WebSocket listen addr (\"\" disables)")
	grpcAddr := flag.String("grpc", ":9993", "gRPC listen addr (\"\" disables)")
	tcpAddr := flag.String("tcp", ":9994", "raw TCP echo listen addr (\"\" disables)")
	flag.Parse()

	var wg sync.WaitGroup
	start := func(name, addr string, fn func(string) error) {
		if addr == "" {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(addr); err != nil {
				log.Printf("[%s] stopped: %v", name, err)
			}
		}()
	}

	start("http", *httpAddr, serveHTTP)
	start("ws", *wsAddr, serveWS)
	start("grpc", *grpcAddr, serveGRPC)
	start("tcp", *tcpAddr, serveTCP)

	log.Printf("aegis-mock up — http=%q ws=%q grpc=%q tcp=%q", *httpAddr, *wsAddr, *grpcAddr, *tcpAddr)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// HTTP/1.1 + h2c — echo plus a tiny API surface mirroring fast-upstream so
// the WAF's detector/audit tests still have endpoints to hit.
// ---------------------------------------------------------------------------

func serveHTTP(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"products": []string{"alpha", "beta", "gamma"}})
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Accept anything; hand back a token (the WAF is the system under
		// test, not the auth logic).
		writeJSON(w, 200, map[string]any{"token": randHex(16)})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[http] %s %s proto=%s from=%s", r.Method, r.URL.Path, r.Proto, r.RemoteAddr)
		writeJSON(w, 200, map[string]any{
			"echo": r.URL.RequestURI(), "method": r.Method, "proto": r.Proto, "host": r.Host,
		})
	})
	// h2c so the WAF can forward cleartext HTTP/2 (scheme h2c) as well as
	// HTTP/1.1 to the same listener.
	srv := &http.Server{Addr: addr, Handler: h2c.NewHandler(mux, &http2.Server{})}
	log.Printf("[http] listening on %s (HTTP/1.1 + h2c)", addr)
	return srv.ListenAndServe()
}

// ---------------------------------------------------------------------------
// WebSocket — echo every frame; the text "bye" closes the connection.
// ---------------------------------------------------------------------------

var wsUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

func serveWS(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[ws] upgrade failed from=%s: %v", r.RemoteAddr, err)
			return
		}
		defer c.Close()
		log.Printf("[ws] open from=%s", r.RemoteAddr)
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				break
			}
			if strings.TrimSpace(string(msg)) == "bye" {
				_ = c.WriteMessage(websocket.TextMessage, []byte("bye"))
				break
			}
			if err := c.WriteMessage(mt, msg); err != nil {
				break
			}
		}
		log.Printf("[ws] close from=%s", r.RemoteAddr)
	})
	log.Printf("[ws] listening on %s", addr)
	return (&http.Server{Addr: addr, Handler: mux}).ListenAndServe()
}

// ---------------------------------------------------------------------------
// gRPC — echo ANY unary/streaming method without protoc/codegen.
//
// A raw passthrough codec + UnknownServiceHandler echoes the request bytes
// straight back. Because EchoReq/EchoResp (echo.proto) share the same field
// layout, `grpcurl -proto echo.proto -d '{"message":"hi"}' addr mock.Echo/Say`
// round-trips: grpcurl encodes the request to protobuf, the server echoes the
// bytes, grpcurl decodes them as the response.
// ---------------------------------------------------------------------------

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec.Marshal: expected []byte, got %T", v)
	}
	return b, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	p, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec.Unmarshal: expected *[]byte, got %T", v)
	}
	*p = append((*p)[:0], data...)
	return nil
}

// Name "proto" so the wire content-type stays application/grpc+proto.
func (rawCodec) Name() string { return "proto" }

func echoStream(_ any, ss grpc.ServerStream) error {
	method, _ := grpc.Method(ss.Context())
	log.Printf("[grpc] call %s", method)
	for {
		var msg []byte
		if err := ss.RecvMsg(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := ss.SendMsg(msg); err != nil {
			return err
		}
	}
}

func serveGRPC(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer(
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(echoStream),
	)
	log.Printf("[grpc] listening on %s (echoes any method)", addr)
	return s.Serve(ln)
}

// ---------------------------------------------------------------------------
// Raw TCP — byte echo (for scheme:tcp / CONNECT-tunnel upstreams).
// ---------------------------------------------------------------------------

func serveTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("[tcp] listening on %s (byte echo)", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			log.Printf("[tcp] open from=%s", c.RemoteAddr())
			_, _ = io.Copy(c, c)
			log.Printf("[tcp] close from=%s", c.RemoteAddr())
		}(conn)
	}
}

// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
