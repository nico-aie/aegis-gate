#!/usr/bin/env node
// ws-attack-client.mjs — zero-dependency RFC 6455 WebSocket client.
//
// Built for the 05-websocket-block demo: opens a WS connection through
// the WAF, sends exactly one text message, then reports what came back.
// No `npm install` — hand-rolls the HTTP/1.1 upgrade handshake and the
// masked client frame using only Node's built-in `net` + `crypto`.
//
// Usage:
//   node ws-attack-client.mjs <ws-url> <message>
//   node ws-attack-client.mjs ws://127.0.0.1:8080/ws "hello chat"
//
// Output (one machine-readable line, then a human line):
//   OUTCOME=echo|closed|timeout|handshake_failed CLOSE_CODE=<n|-> ECHO=<text|->
//
// Exit code is always 0 — the orchestrator interprets OUTCOME so a
// blocked frame (a "closed" outcome) is a PASS, not a script failure.

import net from "node:net";
import crypto from "node:crypto";

const [, , urlArg, messageArg] = process.argv;
if (!urlArg || messageArg === undefined) {
  console.error("usage: node ws-attack-client.mjs <ws-url> <message>");
  process.exit(2);
}

const url = new URL(urlArg);
const host = url.hostname;
const port = Number(url.port || 80);
const path = url.pathname + url.search || "/";
const RESPONSE_TIMEOUT_MS = 3000;

function report(outcome, { closeCode = "-", echo = "-" } = {}) {
  // One parseable line for the shell wrapper, then a friendly line.
  console.log(`OUTCOME=${outcome} CLOSE_CODE=${closeCode} ECHO=${echo}`);
  const human = {
    echo: `backend echoed the message — frame ALLOWED through the WAF`,
    closed: `WAF closed the socket with code ${closeCode} — frame BLOCKED`,
    timeout: `no echo and no close within ${RESPONSE_TIMEOUT_MS}ms`,
    handshake_failed: `WebSocket handshake did not return 101`,
  }[outcome];
  console.log(`  → ${human}`);
}

// Build a client→server text frame: FIN=1, opcode=0x1, MASK=1 (clients
// MUST mask, RFC 6455 §5.1), 4-byte random key XOR'd over the payload.
function encodeMaskedTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  const len = payload.length;
  const header = [];
  header.push(0x81); // FIN + text opcode
  if (len < 126) {
    header.push(0x80 | len);
  } else if (len <= 0xffff) {
    header.push(0x80 | 126, (len >> 8) & 0xff, len & 0xff);
  } else {
    header.push(0x80 | 127, 0, 0, 0, 0, (len >>> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff);
  }
  const mask = crypto.randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i & 3];
  return Buffer.concat([Buffer.from(header), mask, masked]);
}

// Parse one complete server→client frame from `buf`, or null if more
// bytes are needed. Server frames are unmasked.
function tryParseFrame(buf) {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0f;
  let len = buf[1] & 0x7f;
  let offset = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    offset = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }
  const masked = (buf[1] & 0x80) !== 0;
  if (masked) offset += 4; // unexpected from a server, but stay correct
  if (buf.length < offset + len) return null;
  const payload = buf.subarray(offset, offset + len);
  return { opcode, payload, total: offset + len };
}

const socket = net.connect(port, host);
let phase = "handshake";
let rxbuf = Buffer.alloc(0);
let done = false;

const timer = setTimeout(() => {
  if (!done) finish("timeout");
}, RESPONSE_TIMEOUT_MS + 1500);

function finish(outcome, extra) {
  if (done) return;
  done = true;
  clearTimeout(timer);
  report(outcome, extra);
  socket.destroy();
  process.exit(0);
}

socket.on("connect", () => {
  const key = crypto.randomBytes(16).toString("base64");
  const req =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}:${port}\r\n` +
    `Upgrade: websocket\r\n` +
    `Connection: Upgrade\r\n` +
    `Sec-WebSocket-Key: ${key}\r\n` +
    `Sec-WebSocket-Version: 13\r\n` +
    `\r\n`;
  socket.write(req);
});

socket.on("data", (chunk) => {
  rxbuf = Buffer.concat([rxbuf, chunk]);

  if (phase === "handshake") {
    const headEnd = rxbuf.indexOf("\r\n\r\n");
    if (headEnd === -1) return;
    const head = rxbuf.subarray(0, headEnd).toString("latin1");
    const statusLine = head.split("\r\n")[0] || "";
    if (!/\b101\b/.test(statusLine)) {
      return finish("handshake_failed", { echo: statusLine.trim() });
    }
    rxbuf = rxbuf.subarray(headEnd + 4);
    phase = "open";
    // Handshake done — send the single test frame and arm the
    // response window. An echo means ALLOWED; a Close means BLOCKED.
    socket.write(encodeMaskedTextFrame(messageArg));
    setTimeout(() => {
      if (!done) finish("timeout");
    }, RESPONSE_TIMEOUT_MS);
  }

  // Drain any complete frames the server sent.
  for (;;) {
    const frame = tryParseFrame(rxbuf);
    if (!frame) break;
    rxbuf = rxbuf.subarray(frame.total);
    if (frame.opcode === 0x8) {
      // Close frame — first 2 payload bytes are the status code.
      const code = frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : "-";
      return finish("closed", { closeCode: code });
    }
    if (frame.opcode === 0x1 || frame.opcode === 0x2) {
      return finish("echo", { echo: frame.payload.toString("utf8").slice(0, 80) });
    }
    // ping/pong/continuation — ignore, keep reading.
  }
});

socket.on("error", (e) => finish("handshake_failed", { echo: String(e.code || e.message) }));
socket.on("close", () => {
  if (!done) finish(phase === "handshake" ? "handshake_failed" : "closed");
});
