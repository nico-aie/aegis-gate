#!/usr/bin/env python3
"""
ws_probe.py — OPTIONAL WebSocket frame helper for run.sh.

curl can perform a WS *handshake* but cannot exchange frames after upgrade.
For cases that carry a `ws.frames` sequence (frame-injection / oversized
frame), run.sh pipes a JSON object on stdin:

    {"base_url": "http://localhost:8080", "sid": "...", "case": {<case obj>}}

We open the WebSocket with the case's handshake headers, send each frame,
read briefly, and print ONE verdict token on stdout:

    block      handshake rejected (non-101) OR server closed 1008/1009/1003
    allow      upgrade succeeded and frames were accepted without a policy close
    challenge  server returned 429-style close
    error      could not run (network / unexpected)

Requires: pip install websocket-client   (auto-skipped by run.sh if absent)
"""
import base64, json, sys

def main():
    try:
        import websocket  # websocket-client
    except Exception:
        print("error"); return
    try:
        data = json.load(sys.stdin)
    except Exception:
        print("error"); return

    base = data.get("base_url", "http://localhost:8080")
    sid = data.get("sid", "")
    case = data.get("case", {})
    ws = case.get("ws", {})
    path = ws.get("handshake_path", "/ws/live")
    headers = dict(ws.get("handshake_headers", {}))
    frames = ws.get("frames", [])

    ws_url = base.replace("http://", "ws://").replace("https://", "wss://").rstrip("/") + path
    # split headers into header list + cookie
    cookie = headers.pop("Cookie", None) or (f"sid={sid}" if sid else None)
    # drop hop headers the client library sets itself
    for k in list(headers):
        if k.lower() in ("upgrade", "connection", "sec-websocket-key",
                         "sec-websocket-version", "host"):
            headers.pop(k)
    hdr_list = [f"{k}: {v}" for k, v in headers.items()]

    try:
        conn = websocket.create_connection(
            ws_url, header=hdr_list, cookie=cookie, timeout=6,
            enable_multithread=False, suppress_origin=False)
    except websocket._exceptions.WebSocketBadStatusException as e:
        # handshake refused by the WAF (e.g. 403 on bad origin) => blocked
        code = getattr(e, "status_code", 0)
        print("challenge" if code == 429 else "block"); return
    except Exception:
        print("error"); return

    verdict = "allow"
    try:
        for fr in frames:
            payload = base64.b64decode(fr.get("payload_b64", "")) if fr.get("payload_b64") else b""
            op = fr.get("opcode", "text")
            opcode = {"text": websocket.ABNF.OPCODE_TEXT,
                      "binary": websocket.ABNF.OPCODE_BINARY,
                      "ping": websocket.ABNF.OPCODE_PING,
                      "close": websocket.ABNF.OPCODE_CLOSE}.get(op, websocket.ABNF.OPCODE_TEXT)
            conn.send_frame(websocket.ABNF.create_frame(payload, opcode))
        # read whatever the server says back (ack, or a policy close)
        conn.settimeout(3)
        try:
            opcode, frame = conn.recv_data(control_frame=True)
            if opcode == websocket.ABNF.OPCODE_CLOSE and frame:
                ccode = int.from_bytes(frame[:2], "big") if len(frame) >= 2 else 0
                if ccode in (1008, 1009, 1003):      # policy / too-big / unsupported
                    verdict = "block"
                elif ccode == 1013:                  # try again later
                    verdict = "challenge"
        except Exception:
            pass
    except Exception:
        verdict = "block"   # server tore the connection down on our frame
    finally:
        try: conn.close()
        except Exception: pass
    print(verdict)

if __name__ == "__main__":
    main()
