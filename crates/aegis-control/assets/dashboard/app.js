;
(function() {
  const { useState: useStateW, useEffect: useEffectW, useRef: useRefW, useMemo: useMemoW } = React;
  const I = {
    Shield: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" })),
    Activity: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("polyline", { points: "22 12 18 12 15 21 9 3 6 12 2 12" })),
    Siren: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M7 18v-6a5 5 0 0 1 10 0v6" }), /* @__PURE__ */ React.createElement("path", { d: "M5 21h14" }), /* @__PURE__ */ React.createElement("path", { d: "M21 12h1" }), /* @__PURE__ */ React.createElement("path", { d: "M2 12h1" }), /* @__PURE__ */ React.createElement("path", { d: "m4.93 4.93.7.7" }), /* @__PURE__ */ React.createElement("path", { d: "m18.36 4.93-.7.7" })),
    BarChart: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("line", { x1: "12", y1: "20", x2: "12", y2: "10" }), /* @__PURE__ */ React.createElement("line", { x1: "18", y1: "20", x2: "18", y2: "4" }), /* @__PURE__ */ React.createElement("line", { x1: "6", y1: "20", x2: "6", y2: "16" })),
    Book: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M4 19.5A2.5 2.5 0 0 1 6.5 17H20" }), /* @__PURE__ */ React.createElement("path", { d: "M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" })),
    Layers: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("polygon", { points: "12 2 2 7 12 12 22 7 12 2" }), /* @__PURE__ */ React.createElement("polyline", { points: "2 17 12 22 22 17" }), /* @__PURE__ */ React.createElement("polyline", { points: "2 12 12 17 22 12" })),
    Ban: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("circle", { cx: "12", cy: "12", r: "10" }), /* @__PURE__ */ React.createElement("line", { x1: "4.93", y1: "4.93", x2: "19.07", y2: "19.07" })),
    Check: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("polyline", { points: "20 6 9 17 4 12" })),
    Server: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("rect", { x: "2", y: "2", width: "20", height: "8", rx: "2" }), /* @__PURE__ */ React.createElement("rect", { x: "2", y: "14", width: "20", height: "8", rx: "2" }), /* @__PURE__ */ React.createElement("line", { x1: "6", y1: "6", x2: "6.01", y2: "6" }), /* @__PURE__ */ React.createElement("line", { x1: "6", y1: "18", x2: "6.01", y2: "18" })),
    Settings: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("circle", { cx: "12", cy: "12", r: "3" }), /* @__PURE__ */ React.createElement("path", { d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" })),
    Gauge: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "m12 14 4-4" }), /* @__PURE__ */ React.createElement("path", { d: "M3.34 19a10 10 0 1 1 17.32 0" })),
    Globe: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("circle", { cx: "12", cy: "12", r: "10" }), /* @__PURE__ */ React.createElement("line", { x1: "2", y1: "12", x2: "22", y2: "12" }), /* @__PURE__ */ React.createElement("path", { d: "M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" })),
    Search: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("circle", { cx: "11", cy: "11", r: "8" }), /* @__PURE__ */ React.createElement("line", { x1: "21", y1: "21", x2: "16.65", y2: "16.65" })),
    X: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("line", { x1: "18", y1: "6", x2: "6", y2: "18" }), /* @__PURE__ */ React.createElement("line", { x1: "6", y1: "6", x2: "18", y2: "18" })),
    Plus: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("line", { x1: "12", y1: "5", x2: "12", y2: "19" }), /* @__PURE__ */ React.createElement("line", { x1: "5", y1: "12", x2: "19", y2: "12" })),
    Pause: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("rect", { x: "6", y: "4", width: "4", height: "16" }), /* @__PURE__ */ React.createElement("rect", { x: "14", y: "4", width: "4", height: "16" })),
    Play: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("polygon", { points: "6 4 20 12 6 20 6 4" })),
    Download: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }), /* @__PURE__ */ React.createElement("polyline", { points: "7 10 12 15 17 10" }), /* @__PURE__ */ React.createElement("line", { x1: "12", y1: "15", x2: "12", y2: "3" })),
    Refresh: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("polyline", { points: "23 4 23 10 17 10" }), /* @__PURE__ */ React.createElement("path", { d: "M20.49 15a9 9 0 1 1-2.12-9.36L23 10" })),
    Edit: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" }), /* @__PURE__ */ React.createElement("path", { d: "M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" })),
    Trash: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("polyline", { points: "3 6 5 6 21 6" }), /* @__PURE__ */ React.createElement("path", { d: "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" })),
    Bell: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" }), /* @__PURE__ */ React.createElement("path", { d: "M13.73 21a2 2 0 0 1-3.46 0" })),
    Sparkles: (p) => /* @__PURE__ */ React.createElement("svg", { width: "14", height: "14", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" })),
    External: (p) => /* @__PURE__ */ React.createElement("svg", { width: "12", height: "12", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("path", { d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" }), /* @__PURE__ */ React.createElement("polyline", { points: "15 3 21 3 21 9" }), /* @__PURE__ */ React.createElement("line", { x1: "10", y1: "14", x2: "21", y2: "3" })),
    ArrowUp: (p) => /* @__PURE__ */ React.createElement("svg", { width: "10", height: "10", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "3", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("line", { x1: "12", y1: "19", x2: "12", y2: "5" }), /* @__PURE__ */ React.createElement("polyline", { points: "5 12 12 5 19 12" })),
    ArrowDown: (p) => /* @__PURE__ */ React.createElement("svg", { width: "10", height: "10", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "3", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("line", { x1: "12", y1: "5", x2: "12", y2: "19" }), /* @__PURE__ */ React.createElement("polyline", { points: "19 12 12 19 5 12" })),
    Cluster: (p) => /* @__PURE__ */ React.createElement("svg", { width: "16", height: "16", viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", ...p }, /* @__PURE__ */ React.createElement("circle", { cx: "6", cy: "6", r: "2" }), /* @__PURE__ */ React.createElement("circle", { cx: "18", cy: "6", r: "2" }), /* @__PURE__ */ React.createElement("circle", { cx: "6", cy: "18", r: "2" }), /* @__PURE__ */ React.createElement("circle", { cx: "18", cy: "18", r: "2" }), /* @__PURE__ */ React.createElement("circle", { cx: "12", cy: "12", r: "2" }), /* @__PURE__ */ React.createElement("line", { x1: "8", y1: "6", x2: "16", y2: "6" }), /* @__PURE__ */ React.createElement("line", { x1: "8", y1: "18", x2: "16", y2: "18" }), /* @__PURE__ */ React.createElement("line", { x1: "6", y1: "8", x2: "6", y2: "16" }), /* @__PURE__ */ React.createElement("line", { x1: "18", y1: "8", x2: "18", y2: "16" }))
  };
  function Sparkline({ data, w = 80, h = 22, color = "var(--brand-yellow)", fill = false, strokeWidth = 1.5 }) {
    if (!data || !data.length) return null;
    const max = Math.max(...data);
    const min = Math.min(...data);
    const range = max - min || 1;
    const step = w / Math.max(1, data.length - 1);
    const points = data.map((v, i) => {
      const x = i * step;
      const y = h - (v - min) / range * (h - 2) - 1;
      return [x, y];
    });
    const d = points.map((p, i) => i === 0 ? `M${p[0]},${p[1]}` : `L${p[0]},${p[1]}`).join(" ");
    const dFill = `${d} L${w},${h} L0,${h} Z`;
    return /* @__PURE__ */ React.createElement("svg", { width: w, height: h, className: "spark" }, fill && /* @__PURE__ */ React.createElement("path", { d: dFill, fill: color, opacity: "0.18" }), /* @__PURE__ */ React.createElement("path", { d, fill: "none", stroke: color, strokeWidth, strokeLinejoin: "round", strokeLinecap: "round" }));
  }
  function StatTile({ title, value, sub, icon, tone, sparkData, sparkColor }) {
    return /* @__PURE__ */ React.createElement("div", { className: `stat ${tone || ""}` }, /* @__PURE__ */ React.createElement("div", { className: "stat-head" }, /* @__PURE__ */ React.createElement("span", null, title), /* @__PURE__ */ React.createElement("span", { className: "stat-icon" }, icon)), /* @__PURE__ */ React.createElement("div", { className: "stat-value" }, value), /* @__PURE__ */ React.createElement("div", { className: "stat-sub" }, sub), sparkData && /* @__PURE__ */ React.createElement("div", { className: "stat-spark" }, /* @__PURE__ */ React.createElement(Sparkline, { data: sparkData, color: sparkColor || "var(--brand-yellow)", fill: true, w: 120, h: 36 })));
  }
  function TrafficChart({ series, w = 800, h = 220 }) {
    if (!series || series.length < 2) return null;
    const padL = 36, padR = 12, padT = 12, padB = 22;
    const innerW = w - padL - padR;
    const innerH = h - padT - padB;
    const max = Math.max(...series.map((s) => s.total), 10);
    const xs = (i) => padL + i / (series.length - 1) * innerW;
    const ys = (v) => padT + innerH - v / max * innerH;
    const totalPath = series.map((s, i) => `${i === 0 ? "M" : "L"}${xs(i)},${ys(s.total)}`).join(" ");
    const blockPath = series.map((s, i) => `${i === 0 ? "M" : "L"}${xs(i)},${ys(s.blocked)}`).join(" ");
    const totalFill = `${totalPath} L${xs(series.length - 1)},${ys(0)} L${xs(0)},${ys(0)} Z`;
    const yTicks = [0, max * 0.5, max].map((v) => Math.round(v));
    return /* @__PURE__ */ React.createElement("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", height: h, preserveAspectRatio: "none" }, yTicks.map((t, i) => /* @__PURE__ */ React.createElement("g", { key: i }, /* @__PURE__ */ React.createElement("line", { x1: padL, x2: w - padR, y1: ys(t), y2: ys(t), className: "gridline", strokeDasharray: "2 4" }), /* @__PURE__ */ React.createElement("text", { x: padL - 6, y: ys(t) + 3, textAnchor: "end", className: "axis-label" }, t))), /* @__PURE__ */ React.createElement("path", { d: totalFill, fill: "#3B82F6", opacity: "0.12" }), /* @__PURE__ */ React.createElement("path", { d: totalPath, fill: "none", stroke: "#3B82F6", strokeWidth: "1.6" }), /* @__PURE__ */ React.createElement("path", { d: blockPath, fill: "none", stroke: "#F6465D", strokeWidth: "1.6" }), series.length > 0 && /* @__PURE__ */ React.createElement("circle", { cx: xs(series.length - 1), cy: ys(series[series.length - 1].total), r: "3", fill: "#3B82F6", stroke: "#0B0E11", strokeWidth: "1.5" }, /* @__PURE__ */ React.createElement("animate", { attributeName: "r", values: "3;5;3", dur: "1.6s", repeatCount: "indefinite" })), /* @__PURE__ */ React.createElement("g", { transform: `translate(${padL},${padT - 2})` }, /* @__PURE__ */ React.createElement("circle", { cx: "4", cy: "6", r: "3", fill: "#3B82F6" }), /* @__PURE__ */ React.createElement("text", { x: "12", y: "9", className: "axis-label", fill: "#B7BDC6" }, "Total req/s"), /* @__PURE__ */ React.createElement("circle", { cx: "80", cy: "6", r: "3", fill: "#F6465D" }), /* @__PURE__ */ React.createElement("text", { x: "88", y: "9", className: "axis-label", fill: "#B7BDC6" }, "Blocked")));
  }
  function Donut({ slices, size = 180 }) {
    const total = slices.reduce((s, x) => s + x.value, 0) || 1;
    const r = size / 2 - 8;
    const inner = r * 0.6;
    const cx = size / 2, cy = size / 2;
    let acc = 0;
    return /* @__PURE__ */ React.createElement("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}` }, slices.map((s, i) => {
      const a0 = acc / total * Math.PI * 2 - Math.PI / 2;
      acc += s.value;
      const a1 = acc / total * Math.PI * 2 - Math.PI / 2;
      const large = a1 - a0 > Math.PI ? 1 : 0;
      const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      const xi0 = cx + inner * Math.cos(a0), yi0 = cy + inner * Math.sin(a0);
      const xi1 = cx + inner * Math.cos(a1), yi1 = cy + inner * Math.sin(a1);
      const d = `M${x0},${y0} A${r},${r} 0 ${large} 1 ${x1},${y1} L${xi1},${yi1} A${inner},${inner} 0 ${large} 0 ${xi0},${yi0} Z`;
      return /* @__PURE__ */ React.createElement("path", { key: i, d, fill: s.color });
    }), /* @__PURE__ */ React.createElement("text", { x: cx, y: cy - 4, textAnchor: "middle", fill: "#EAECEF", fontSize: "22", fontWeight: "700", fontFamily: "JetBrains Mono" }, total.toLocaleString()), /* @__PURE__ */ React.createElement("text", { x: cx, y: cy + 12, textAnchor: "middle", fill: "#707A8A", fontSize: "9", letterSpacing: "1.4", style: { textTransform: "uppercase" } }, "DETECTIONS \xB7 15m"));
  }
  function project(lat, lon, w, h) {
    return [(lon + 180) * (w / 360), (90 - lat) * (h / 180)];
  }
  function WorldMap({ blips = [], h = 320 }) {
    const w = 720;
    const [tick, setTick] = useStateW(0);
    useEffectW(() => {
      const id = setInterval(() => setTick((t) => t + 1), 1500);
      return () => clearInterval(id);
    }, []);
    const continents = [
      // North America
      "M85,68 L155,55 L195,68 L210,95 L195,120 L165,140 L130,158 L100,150 L85,125 Z",
      // Central / South America
      "M170,165 L195,160 L210,180 L210,225 L190,260 L170,275 L160,255 L155,210 L160,180 Z",
      // Europe
      "M345,68 L395,62 L420,80 L410,105 L375,115 L345,105 Z",
      // Africa
      "M345,125 L405,115 L435,150 L425,210 L385,245 L355,235 L340,195 Z",
      // Asia (broad)
      "M420,55 L555,50 L605,75 L620,110 L585,140 L515,145 L455,135 L420,110 Z",
      // South-east Asia / Indonesia
      "M540,150 L620,150 L640,170 L605,185 L555,180 Z",
      // Australia
      "M580,210 L645,205 L660,230 L630,255 L585,250 Z"
    ];
    return /* @__PURE__ */ React.createElement("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", height: h, style: { display: "block" } }, /* @__PURE__ */ React.createElement("defs", null, /* @__PURE__ */ React.createElement("radialGradient", { id: "bg-glow", cx: "50%", cy: "50%", r: "60%" }, /* @__PURE__ */ React.createElement("stop", { offset: "0%", stopColor: "#161A20" }), /* @__PURE__ */ React.createElement("stop", { offset: "100%", stopColor: "#0B0E11" })), /* @__PURE__ */ React.createElement("radialGradient", { id: "blip-gradient" }, /* @__PURE__ */ React.createElement("stop", { offset: "0%", stopColor: "#F6465D", stopOpacity: "1" }), /* @__PURE__ */ React.createElement("stop", { offset: "100%", stopColor: "#F6465D", stopOpacity: "0" }))), /* @__PURE__ */ React.createElement("rect", { x: "0", y: "0", width: w, height: h, fill: "url(#bg-glow)" }), /* @__PURE__ */ React.createElement("g", { stroke: "#1B2026", strokeWidth: "0.5", fill: "none" }, [-60, -30, 0, 30, 60].map((l) => {
      const [, y] = project(l, 0, w, h);
      return /* @__PURE__ */ React.createElement("line", { key: `la${l}`, x1: "0", x2: w, y1: y, y2: y });
    }), [-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150].map((l) => {
      const [x] = project(0, l, w, h);
      return /* @__PURE__ */ React.createElement("line", { key: `lo${l}`, x1: x, x2: x, y1: "0", y2: h });
    })), /* @__PURE__ */ React.createElement("g", { fill: "#1E2329", stroke: "#2B3139", strokeWidth: "0.6" }, continents.map((d, i) => /* @__PURE__ */ React.createElement("path", { key: i, d }))), /* @__PURE__ */ React.createElement("g", null, (() => {
      const [ox, oy] = project(window.ORIGIN.lat, window.ORIGIN.lon, w, h);
      return /* @__PURE__ */ React.createElement("g", { transform: `translate(${ox},${oy})` }, /* @__PURE__ */ React.createElement("circle", { r: "14", fill: "none", stroke: "#FCD535", strokeWidth: "0.8", opacity: "0.4" }), /* @__PURE__ */ React.createElement("circle", { r: "6", fill: "#FCD535", opacity: "0.95" }), /* @__PURE__ */ React.createElement("text", { y: "-12", textAnchor: "middle", fill: "#FCD535", fontSize: "9", fontWeight: "700" }, "SG-1 EDGE"));
    })()), /* @__PURE__ */ React.createElement("g", null, blips.map((b, i) => {
      const [sx, sy] = project(b.lat, b.lon, w, h);
      const [tx, ty] = project(window.ORIGIN.lat, window.ORIGIN.lon, w, h);
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2 - 60;
      const animKey = (tick + i) % 4 === 0;
      return /* @__PURE__ */ React.createElement("g", { key: i }, /* @__PURE__ */ React.createElement(
        "path",
        {
          d: `M${sx},${sy} Q${mx},${my} ${tx},${ty}`,
          className: "attack-arc",
          strokeDasharray: "3 4",
          strokeDashoffset: tick * 6 % 100
        }
      ), /* @__PURE__ */ React.createElement("circle", { cx: sx, cy: sy, r: "14", fill: "url(#blip-gradient)", opacity: animKey ? 0.7 : 0.3 }), /* @__PURE__ */ React.createElement("circle", { cx: sx, cy: sy, r: "3", fill: "#F6465D" }), b.show && /* @__PURE__ */ React.createElement("text", { x: sx + 6, y: sy - 4, fill: "#FF8896", fontSize: "9", fontFamily: "JetBrains Mono" }, b.label));
    })));
  }
  function RiskHeatmap({ rows, cols = 30, h = 220 }) {
    const w = 760;
    const padL = 140, padT = 16, padB = 22;
    const cellW = (w - padL - 8) / cols;
    const cellH = (h - padT - padB) / rows.length;
    const data = useMemoW(() => rows.map((r) => {
      const arr = [];
      let seed = r.path.length;
      for (let c = 0; c < cols; c++) {
        seed = (seed * 9301 + 49297) % 233280;
        let v = seed / 233280 * (r.intensity || 1);
        if (Math.random() < 0.04) v += 0.6;
        arr.push(Math.min(1, v));
      }
      return arr;
    }), [rows, cols]);
    const colorFor = (v) => {
      if (v < 0.18) return "#1E2329";
      if (v < 0.35) return "#3B2A1A";
      if (v < 0.55) return "#6B4710";
      if (v < 0.75) return "#A87715";
      if (v < 0.9) return "#E0A415";
      return "#FCD535";
    };
    return /* @__PURE__ */ React.createElement("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", height: h, preserveAspectRatio: "none" }, rows.map((r, ri) => /* @__PURE__ */ React.createElement("g", { key: ri }, /* @__PURE__ */ React.createElement("text", { x: padL - 8, y: padT + ri * cellH + cellH * 0.7, textAnchor: "end", fontSize: "10", fill: "#B7BDC6", fontFamily: "JetBrains Mono" }, r.path), data[ri].map((v, ci) => /* @__PURE__ */ React.createElement("rect", { key: ci, x: padL + ci * cellW, y: padT + ri * cellH, width: cellW - 1, height: cellH - 1, fill: colorFor(v), className: "heat-cell" })))), [0, 0.25, 0.5, 0.75, 1].map((p, i) => {
      const ago = Math.round(60 * (1 - p));
      const x = padL + p * (cols * cellW);
      return /* @__PURE__ */ React.createElement("text", { key: i, x, y: h - 6, textAnchor: "middle", fontSize: "9", fill: "#5E6673", fontFamily: "JetBrains Mono" }, "-", ago, "m");
    }));
  }
  function RiskMeter({ value }) {
    const v = Math.max(0, Math.min(100, value));
    const color = v >= 75 ? "var(--down)" : v >= 50 ? "var(--warn)" : v >= 25 ? "var(--info)" : "var(--up)";
    return /* @__PURE__ */ React.createElement("span", { className: "risk-meter" }, /* @__PURE__ */ React.createElement("span", { className: "risk-bar" }, /* @__PURE__ */ React.createElement("span", { style: { width: `${v}%`, background: color } })), /* @__PURE__ */ React.createElement("span", { className: "num", style: { fontSize: 11, color: "var(--ink-mute)" } }, v));
  }
  function ActionPill({ value }) {
    return /* @__PURE__ */ React.createElement("span", { className: `pill ${value}` }, value);
  }
  function TierPill({ value }) {
    return /* @__PURE__ */ React.createElement("span", { className: `pill tier-${value}` }, value);
  }
  function Drawer({ open, onClose, title, children, footer }) {
    if (!open) return null;
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "drawer-backdrop", onClick: onClose }), /* @__PURE__ */ React.createElement("aside", { className: "drawer" }, /* @__PURE__ */ React.createElement("div", { className: "drawer-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: "var(--ink-dim)" } }, "Request detail"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 14, fontWeight: 600 } }, title)), /* @__PURE__ */ React.createElement("button", { className: "icon-btn", onClick: onClose }, /* @__PURE__ */ React.createElement(I.X, null))), /* @__PURE__ */ React.createElement("div", { className: "drawer-body" }, children), footer && /* @__PURE__ */ React.createElement("div", { className: "drawer-foot" }, footer)));
  }
  function StackedBar({ segments, h = 24 }) {
    const total = segments.reduce((s, x) => s + x.value, 0) || 1;
    return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", height: h, borderRadius: 4, overflow: "hidden", background: "var(--surface-3)" } }, segments.map((s, i) => /* @__PURE__ */ React.createElement("div", { key: i, style: { width: `${s.value / total * 100}%`, background: s.color }, title: `${s.name}: ${s.value}` })));
  }
  function BarList({ items, fmt = (v) => v.toLocaleString() }) {
    const max = Math.max(...items.map((i) => i.value), 1);
    return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 6 } }, items.map((it, i) => /* @__PURE__ */ React.createElement("div", { key: i, style: { display: "flex", alignItems: "center", gap: 8, fontSize: 12 } }, /* @__PURE__ */ React.createElement("span", { style: { width: 110, color: "var(--ink-mute)", fontSize: 11 } }, it.label), /* @__PURE__ */ React.createElement("div", { style: { flex: 1, height: 14, background: "var(--surface-2)", borderRadius: 3, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { width: `${it.value / max * 100}%`, height: "100%", background: it.color || "var(--brand-yellow)" } })), /* @__PURE__ */ React.createElement("span", { className: "num", style: { width: 70, textAlign: "right", color: "var(--ink)" } }, fmt(it.value)))));
  }
  function SectionHeader({ title, sub, actions }) {
    return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600 } }, title), sub && /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)" } }, sub)), actions);
  }
  function ToastContainer() {
    const [toasts, setToasts] = useStateW([]);
    useEffectW(() => {
      const onAdd = (e) => {
        const id = Math.random().toString(36).slice(2);
        const t = { id, ts: Date.now(), ...e.detail };
        setToasts((prev) => [...prev.slice(-4), t]);
        const ttl = t.kind === "err" ? 8e3 : t.kind === "ok" ? 2500 : 5e3;
        setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), ttl);
      };
      window.addEventListener("aegis:toast", onAdd);
      return () => window.removeEventListener("aegis:toast", onAdd);
    }, []);
    return /* @__PURE__ */ React.createElement("div", { style: {
      position: "fixed",
      bottom: 32,
      right: 16,
      zIndex: 9999,
      display: "flex",
      flexDirection: "column",
      gap: 6,
      pointerEvents: "none"
    } }, toasts.map((t) => /* @__PURE__ */ React.createElement("div", { key: t.id, style: {
      minWidth: 240,
      maxWidth: 360,
      padding: "8px 12px",
      background: "var(--surface-2)",
      border: "1px solid " + (t.kind === "ok" ? "var(--up)" : t.kind === "warn" ? "var(--warn)" : t.kind === "err" ? "var(--down)" : "var(--hairline-strong)"),
      borderLeft: "3px solid " + (t.kind === "ok" ? "var(--up)" : t.kind === "warn" ? "var(--warn)" : t.kind === "err" ? "var(--down)" : "var(--brand-yellow)"),
      borderRadius: "var(--radius)",
      color: "var(--ink)",
      fontSize: 12,
      boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
      display: "flex",
      alignItems: "center",
      gap: 8,
      pointerEvents: "auto"
    } }, /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, t.message), t.detail && /* @__PURE__ */ React.createElement("span", { className: "dim mono", style: { fontSize: 10 } }, t.detail))));
  }
  function aegisToast(message, kind = "info", detail = null) {
    window.dispatchEvent(new CustomEvent("aegis:toast", {
      detail: { message, kind, detail }
    }));
  }
  Object.assign(window, {
    I,
    Sparkline,
    StatTile,
    TrafficChart,
    Donut,
    WorldMap,
    RiskHeatmap,
    RiskMeter,
    ActionPill,
    TierPill,
    Drawer,
    StackedBar,
    BarList,
    SectionHeader,
    ToastContainer,
    aegisToast
  });
})();
;
(function() {
  const { useState, useEffect, useRef, useMemo, useCallback } = React;
  const ROUTES = [
    "/api/login",
    "/api/profile",
    "/api/orders",
    "/api/checkout",
    "/api/admin",
    "/static/css/style.css",
    "/static/js/app.js",
    "/public/index.html",
    "/wp-admin/install.php",
    "/.env",
    "/.git/config",
    "/aws/credentials",
    "/api/users",
    "/api/products",
    "/sitemap.xml",
    "/robots.txt",
    "/favicon.ico",
    "/index.php",
    "/containers/json",
    "/api/analytics/events",
    "/api/v2/auth",
    "/actuator/env",
    "/phpmyadmin",
    "/healthz"
  ];
  const REGIONS = ["singapore", "us-primary", "eu-frankfurt", "tokyo", "sydney", "mumbai"];
  const METHODS = ["GET", "POST", "GET", "GET", "GET", "PUT", "DELETE", "OPTIONS"];
  const ATTACK_CATS = [
    { id: "sqli", label: "SQLi", color: "#F6465D" },
    { id: "ssrf", label: "SSRF", color: "#A78BFA" },
    { id: "recon", label: "Recon", color: "#3B82F6" },
    { id: "path_traversal", label: "Path Traversal", color: "#F0B90B" },
    { id: "honeypot", label: "Honeypot", color: "#EC4899" },
    { id: "xss", label: "XSS", color: "#2DD4BF" },
    { id: "cmdi", label: "CMDi", color: "#FF8896" },
    { id: "lfi", label: "LFI", color: "#10B981" },
    { id: "ssti", label: "SSTi", color: "#9CA3AF" }
  ];
  const ATTACKER_GEO = [
    { ip: "110.35.80.116", cc: "KR", city: "Seoul", lat: 37.56, lon: 126.97 },
    { ip: "195.178.110.162", cc: "NL", city: "Amsterdam", lat: 52.37, lon: 4.89 },
    { ip: "34.47.62.202", cc: "US", city: "Ashburn", lat: 39.04, lon: -77.49 },
    { ip: "71.6.239.61", cc: "US", city: "Walnut", lat: 34.02, lon: -117.86 },
    { ip: "118.26.104.78", cc: "CN", city: "Beijing", lat: 39.91, lon: 116.41 },
    { ip: "204.76.203.206", cc: "US", city: "New York", lat: 40.71, lon: -74.01 },
    { ip: "192.177.79.149", cc: "GB", city: "London", lat: 51.51, lon: -0.13 },
    { ip: "178.62.193.41", cc: "DE", city: "Frankfurt", lat: 50.11, lon: 8.68 },
    { ip: "46.166.139.111", cc: "LT", city: "Vilnius", lat: 54.69, lon: 25.28 },
    { ip: "202.55.137.24", cc: "IN", city: "Mumbai", lat: 19.08, lon: 72.88 },
    { ip: "103.224.182.7", cc: "AU", city: "Sydney", lat: -33.87, lon: 151.21 },
    { ip: "177.85.34.221", cc: "BR", city: "S\xE3o Paulo", lat: -23.55, lon: -46.63 },
    { ip: "95.214.55.10", cc: "RU", city: "Moscow", lat: 55.75, lon: 37.62 },
    { ip: "41.220.72.99", cc: "NG", city: "Lagos", lat: 6.52, lon: 3.38 },
    { ip: "185.220.101.42", cc: "RO", city: "Bucharest", lat: 44.43, lon: 26.1 }
  ];
  const ORIGIN = { lat: 1.35, lon: 103.82 };
  const RULES = [
    { id: "owasp-sqli-001", name: "SQLi: UNION SELECT", kind: "custom", pri: 100, field: "any", op: "regex", pattern: "(?i)\\bunion\\b\\s+\\bselect\\b", action: "block", risk: 80, enabled: true, cat: "sqli", last: "12s ago", hits1h: 1247 },
    { id: "owasp-sqli-001", name: "SQLi: UNION SELECT", kind: "builtin", pri: 100, field: "any", op: "regex", pattern: "(?i)\\bunion\\b\\s+\\bselect\\b", action: "block", risk: 80, enabled: true, cat: "sqli", last: "12s ago", hits1h: 980 },
    { id: "owasp-sqli-002", name: "SQLi: Boolean Injection", kind: "custom", pri: 101, field: "any", op: "regex", pattern: "(?i)\\b(or|and)\\b\\s*\\d+\\s*=\\s*\\d+", action: "block", risk: 70, enabled: true, cat: "sqli", last: "1m ago", hits1h: 412 },
    { id: "owasp-sqli-002", name: "SQLi: Boolean Injection", kind: "builtin", pri: 101, field: "any", op: "regex", pattern: "(?i)\\b(or|and)\\b\\s*\\d+\\s*=\\s*\\d+", action: "block", risk: 70, enabled: true, cat: "sqli", last: "1m ago", hits1h: 308 },
    { id: "owasp-sqli-003", name: "SQLi: SQL Comments", kind: "builtin", pri: 102, field: "any", op: "regex", pattern: "(?:--|#|/\\*).*$", action: "challenge", risk: 40, enabled: true, cat: "sqli", last: "4m ago", hits1h: 145 },
    { id: "owasp-sqli-004", name: "SQLi: DML Statements", kind: "custom", pri: 103, field: "any", op: "regex", pattern: "(?i)\\b(drop|truncate|alter)\\s+(table|database)\\b", action: "block", risk: 90, enabled: true, cat: "sqli", last: "8s ago", hits1h: 802 },
    { id: "owasp-sqli-004", name: "SQLi: DML Statements", kind: "builtin", pri: 103, field: "any", op: "regex", pattern: "(?i)\\b(drop|truncate|alter)\\s+(table|database)\\b", action: "block", risk: 90, enabled: true, cat: "sqli", last: "8s ago", hits1h: 612 },
    { id: "owasp-sqli-005", name: "SQLi: Stored Procedures", kind: "custom", pri: 104, field: "any", op: "regex", pattern: "(?i)\\b(exec|execute)\\s+xp_cmdshell\\b", action: "block", risk: 95, enabled: true, cat: "sqli", last: "19m ago", hits1h: 21 },
    { id: "owasp-sqli-006", name: "SQLi: Time-Based Blind", kind: "custom", pri: 105, field: "any", op: "regex", pattern: "(?i)\\bsleep\\s*\\(\\s*\\d+\\s*\\)", action: "block", risk: 85, enabled: true, cat: "sqli", last: "32s ago", hits1h: 234 },
    { id: "owasp-sqli-007", name: "SQLi: Information Schema", kind: "custom", pri: 106, field: "any", op: "regex", pattern: "(?i)\\binformation_schema\\b", action: "challenge", risk: 50, enabled: true, cat: "sqli", last: "3m ago", hits1h: 89 },
    { id: "owasp-ssrf-001", name: "SSRF: Internal Addresses", kind: "custom", pri: 400, field: "any", op: "regex", pattern: "(?i)(localhost|127\\.0\\.0\\.1|10\\.|192\\.168\\.|169\\.254\\.|::1)", action: "block", risk: 85, enabled: true, cat: "ssrf", last: "6s ago", hits1h: 1893 },
    { id: "owasp-xss-001", name: "XSS: Script Tag", kind: "builtin", pri: 200, field: "any", op: "regex", pattern: "<script[^>]*>", action: "block", risk: 75, enabled: true, cat: "xss", last: "52s ago", hits1h: 521 },
    { id: "owasp-xss-002", name: "XSS: Event Handler", kind: "builtin", pri: 201, field: "any", op: "regex", pattern: "on\\w+\\s*=", action: "block", risk: 65, enabled: true, cat: "xss", last: "2m ago", hits1h: 187 },
    { id: "owasp-pt-001", name: "Path Traversal", kind: "builtin", pri: 300, field: "path", op: "regex", pattern: "\\.\\./", action: "block", risk: 80, enabled: true, cat: "path_traversal", last: "14s ago", hits1h: 712 },
    { id: "owasp-recon-001", name: "Recon: Admin Paths", kind: "builtin", pri: 500, field: "path", op: "regex", pattern: "(/wp-admin|/phpmyadmin|/admin\\.php)", action: "challenge", risk: 45, enabled: true, cat: "recon", last: "8s ago", hits1h: 2104 },
    { id: "owasp-cmdi-001", name: "CMDi: Shell Metachars", kind: "builtin", pri: 600, field: "any", op: "regex", pattern: ";\\s*(cat|ls|wget|curl|nc)\\b", action: "block", risk: 90, enabled: true, cat: "cmdi", last: "25s ago", hits1h: 388 },
    { id: "owasp-lfi-001", name: "LFI: /etc/passwd", kind: "builtin", pri: 700, field: "any", op: "regex", pattern: "/etc/passwd", action: "block", risk: 90, enabled: true, cat: "lfi", last: "47s ago", hits1h: 156 },
    { id: "honeypot-001", name: "Honeypot: /.env", kind: "custom", pri: 50, field: "path", op: "eq", pattern: "/.env", action: "block", risk: 100, enabled: true, cat: "honeypot", last: "3s ago", hits1h: 4521 },
    { id: "honeypot-002", name: "Honeypot: /.git/config", kind: "custom", pri: 51, field: "path", op: "eq", pattern: "/.git/config", action: "block", risk: 100, enabled: true, cat: "honeypot", last: "11s ago", hits1h: 1102 }
  ];
  const TIERS = [
    { name: "basic", desc: "Public marketing routes", routes: 12, rateLimit: "lenient", detectors: 4, challenge: "js-only", tls: "modern", hits1h: 184523 },
    { name: "enhanced", desc: "Authenticated app surface", routes: 38, rateLimit: "standard", detectors: 6, challenge: "js+captcha", tls: "modern", hits1h: 92847 },
    { name: "strict", desc: "Admin & financial endpoints", routes: 7, rateLimit: "strict", detectors: 7, challenge: "strict", tls: "fips", hits1h: 4218 },
    { name: "public-static", desc: "Static assets, CDN-fronted", routes: 3, rateLimit: "lenient", detectors: 2, challenge: "none", tls: "modern", hits1h: 412384 }
  ];
  const BLACKLIST = [
    { id: "b1", type: "cidr", value: "185.220.101.0/24", scope: "global", action: "block", reason: "Tor exit node range \u2014 recurring abuse", expires: null, created: "2026-04-12", hits24: 8421, lastHit: "2s ago" },
    { id: "b2", type: "ip", value: "110.35.80.116", scope: "global", action: "block", reason: "SQLi flood from this IP (rate>1k/min)", expires: "2026-05-15T00:00:00Z", created: "2026-04-28", hits24: 2104, lastHit: "11s ago" },
    { id: "b3", type: "asn", value: "AS14061", scope: "global", action: "challenge", reason: "DigitalOcean \u2014 high abuse signal", expires: null, created: "2026-03-05", hits24: 4128, lastHit: "34s ago" },
    { id: "b4", type: "cidr", value: "46.166.139.0/24", scope: "route:/api/admin", action: "block", reason: "Brute-force admin login", expires: "2026-05-01T00:00:00Z", created: "2026-04-26", hits24: 91, lastHit: "4m ago" },
    { id: "b5", type: "fingerprint", value: "fp:985730a7cc0fc937", scope: "global", action: "block", reason: "Headless Chrome / botnet TLS fp", expires: null, created: "2026-04-20", hits24: 12482, lastHit: "now" },
    { id: "b6", type: "ip", value: "195.178.110.162", scope: "global", action: "block", reason: "Recon scanner \u2014 1500+ honeypot hits", expires: null, created: "2026-04-22", hits24: 1521, lastHit: "7s ago" },
    { id: "b7", type: "asn", value: "AS16276", scope: "tier:basic", action: "challenge", reason: "OVH \u2014 frequent scrapers", expires: null, created: "2026-02-18", hits24: 821, lastHit: "1m ago" },
    { id: "b8", type: "cidr", value: "95.214.55.0/24", scope: "global", action: "block", reason: "Known C2 infrastructure", expires: "2026-06-15T00:00:00Z", created: "2026-04-15", hits24: 442, lastHit: "15s ago" },
    { id: "b9", type: "country", value: "KP", country: "Korea, DPR", flag: "\u{1F1F0}\u{1F1F5}", scope: "global", action: "block", reason: "Sanctioned jurisdiction \u2014 compliance", expires: null, created: "2026-01-04", hits24: 218, lastHit: "6m ago" },
    { id: "b10", type: "country", value: "IR", country: "Iran", flag: "\u{1F1EE}\u{1F1F7}", scope: "global", action: "block", reason: "Sanctioned jurisdiction \u2014 compliance", expires: null, created: "2026-01-04", hits24: 412, lastHit: "38s ago" },
    { id: "b11", type: "country", value: "RU", country: "Russia", flag: "\u{1F1F7}\u{1F1FA}", scope: "tier:strict", action: "challenge", reason: "Geo-restriction on admin tier", expires: null, created: "2026-03-12", hits24: 1842, lastHit: "4s ago" },
    { id: "b12", type: "country", value: "CN", country: "China", flag: "\u{1F1E8}\u{1F1F3}", scope: "route:/api/admin", action: "challenge", reason: "Heightened-risk geo on admin paths", expires: null, created: "2026-02-08", hits24: 3214, lastHit: "12s ago" }
  ];
  const WHITELIST = [
    { id: "w1", type: "ip", value: "203.0.113.42", scope: "global", bypass: ["rate-limit"], reason: "Office NAT \u2014 SOC team egress", expires: null, created: "2026-01-04", bypasses24: 1284, lastBypass: "1m ago" },
    { id: "w2", type: "cidr", value: "52.94.32.0/20", scope: "global", bypass: ["rate-limit", "detector:sqli"], reason: "AWS health-check CIDR for ELB", expires: null, created: "2026-01-04", bypasses24: 47218, lastBypass: "2s ago" },
    { id: "w3", type: "asn", value: "AS15169", scope: "global", bypass: ["rate-limit"], reason: "Verified Googlebot crawler ASN", expires: null, created: "2025-11-12", bypasses24: 18421, lastBypass: "4s ago" },
    { id: "w4", type: "ip", value: "198.51.100.7", scope: "route:/api/payments", bypass: ["challenge"], reason: "Payment partner webhook \u2014 must not be challenged", expires: "2026-12-31T00:00:00Z", created: "2026-02-08", bypasses24: 824, lastBypass: "12m ago" },
    { id: "w5", type: "fingerprint", value: "fp:internal-soc-tls-2026", scope: "global", bypass: ["all"], reason: "Pen-test team TLS fingerprint \u2014 quarterly engagement, signed off by Hannah Cho 2026-04-25", expires: "2026-05-25T00:00:00Z", created: "2026-04-25", bypasses24: 21, lastBypass: "8m ago" },
    { id: "w6", type: "cidr", value: "10.32.0.0/16", scope: "global", bypass: ["rate-limit", "detector:sqli", "detector:xss"], reason: "Internal RFC1918 \u2014 service-to-service", expires: null, created: "2025-09-01", bypasses24: 281542, lastBypass: "now" },
    { id: "w7", type: "country", value: "SG", country: "Singapore", flag: "\u{1F1F8}\u{1F1EC}", scope: "global", bypass: ["rate-limit"], reason: "Home-country traffic \u2014 relaxed rate-limit", expires: null, created: "2025-10-04", bypasses24: 184238, lastBypass: "now" },
    { id: "w8", type: "country", value: "JP", country: "Japan", flag: "\u{1F1EF}\u{1F1F5}", scope: "tier:basic", bypass: ["challenge"], reason: "Trusted partner geo \u2014 skip JS challenge on basic", expires: null, created: "2026-02-18", bypasses24: 28412, lastBypass: "3s ago" },
    { id: "w9", type: "country", value: "GB", country: "UK", flag: "\u{1F1EC}\u{1F1E7}", scope: "route:/api/payments", bypass: ["rate-limit"], reason: "Payment-partner home country \u2014 webhook bursts", expires: "2026-12-31T00:00:00Z", created: "2026-03-22", bypasses24: 4218, lastBypass: "12s ago" }
  ];
  const UPSTREAMS = [
    { name: "us-primary", members: 8, healthy: 8, lb: "least_conn", cb: "closed", p99: 42, rps: 1240 },
    { name: "us-secondary", members: 6, healthy: 5, lb: "least_conn", cb: "half-open", p99: 81, rps: 320 },
    { name: "eu-frankfurt", members: 6, healthy: 6, lb: "p2c", cb: "closed", p99: 38, rps: 982 },
    { name: "apac-singapore", members: 4, healthy: 4, lb: "least_conn", cb: "closed", p99: 51, rps: 642 },
    { name: "apac-tokyo", members: 4, healthy: 3, lb: "least_conn", cb: "open", p99: 0, rps: 0 }
  ];
  const CLUSTER = [
    { id: "aegis-01", addr: "10.32.4.11:8443", ver: "v0.5.16", role: "leader", lastHB: "0s", leases: ["witness", "state-snap"] },
    { id: "aegis-02", addr: "10.32.4.12:8443", ver: "v0.5.16", role: "follower", lastHB: "1s", leases: [] },
    { id: "aegis-03", addr: "10.32.4.13:8443", ver: "v0.5.16", role: "follower", lastHB: "0s", leases: ["gitops-sync"] },
    { id: "aegis-04", addr: "10.32.4.14:8443", ver: "v0.5.15", role: "follower", lastHB: "2s", leases: [], skew: true },
    { id: "aegis-05", addr: "10.32.4.15:8443", ver: "v0.5.16", role: "follower", lastHB: "1s", leases: [] }
  ];
  const CERTS = [
    { host: "api.aegis.example.com", issuer: "Let's Encrypt", days: 78, source: "acme" },
    { host: "admin.aegis.example.com", issuer: "Let's Encrypt", days: 24, source: "acme" },
    { host: "webhook.aegis.example.com", issuer: "DigiCert", days: 412, source: "static" },
    { host: "mtls.aegis.example.com", issuer: "Internal CA", days: 5, source: "mtls" },
    { host: "edge.aegis.example.com", issuer: "Let's Encrypt", days: 91, source: "acme" }
  ];
  const ALERTS = [
    { sev: "warn", name: "SLOBudgetBurning", since: "24m", runbook: "/runbooks/slo-burn.md", desc: "availability burn rate 2x normal" },
    { sev: "info", name: "CertExpiryApproaching", since: "6h", runbook: "/runbooks/cert-renew.md", desc: "mtls.aegis.example.com expires in 5 days" },
    { sev: "info", name: "ClusterVersionSkew", since: "2h", runbook: "/runbooks/cluster-rollout.md", desc: "aegis-04 lags by one minor version" }
  ];
  const ADMIN_LOG = [
    { ts: "17:11:43", class: "admin", actor: "admin", action: "rule.update", target: "owasp-sqli-007", reason: "risk 50 -> 60", hash: "a4f2e9c1b3d7" },
    { ts: "17:09:14", class: "system", actor: "gitops", action: "config.sync", target: "main@a8b1f2c", reason: "auto-pull", hash: "a4f2e9c1b3d6" },
    { ts: "17:04:02", class: "admin", actor: "admin", action: "blacklist.add", target: "110.35.80.116", reason: "SQLi flood", hash: "a4f2e9c1b3d5" },
    { ts: "16:58:21", class: "admin", actor: "admin", action: "tier.update", target: "strict", reason: "detector +recon", hash: "a4f2e9c1b3d4" },
    { ts: "16:51:09", class: "system", actor: "system", action: "cert.renew", target: "api.aegis.example.com", reason: "auto-renew", hash: "a4f2e9c1b3d3" },
    { ts: "16:42:55", class: "admin", actor: "admin", action: "whitelist.add", target: "fp:internal-soc-tls-2026", reason: "pen-test 2026 Q2", hash: "a4f2e9c1b3d2" },
    { ts: "16:30:11", class: "admin", actor: "admin", action: "rule.create", target: "honeypot-002", reason: "new honeypot path", hash: "a4f2e9c1b3d1" },
    { ts: "16:18:43", class: "system", actor: "system", action: "audit.witness", target: "block 412998", reason: "witness-sig ok", hash: "a4f2e9c1b3d0" }
  ];
  let _liveSeq = 166e4;
  function makeLiveEvent(t) {
    const cat = ATTACK_CATS[Math.floor(Math.random() * ATTACK_CATS.length)];
    const isAttack = Math.random() < 0.18;
    const ipPool = ATTACKER_GEO[Math.floor(Math.random() * ATTACKER_GEO.length)];
    const region = REGIONS[Math.floor(Math.random() * REGIONS.length)];
    const method = METHODS[Math.floor(Math.random() * METHODS.length)];
    const path = ROUTES[Math.floor(Math.random() * ROUTES.length)];
    let action, risk, tier, rules;
    if (isAttack) {
      risk = 60 + Math.floor(Math.random() * 40);
      action = risk >= 75 ? "block" : "challenge";
      tier = risk >= 90 ? "crit" : "high";
      rules = [`owasp-${cat.id}-${String(Math.floor(Math.random() * 9) + 1).padStart(3, "0")}`];
    } else {
      risk = Math.floor(Math.random() * 35);
      action = "allow";
      tier = risk > 20 ? "med" : "low";
      rules = [];
    }
    const ts = new Date(t || Date.now());
    const hh = String(ts.getHours()).padStart(2, "0");
    const mm = String(ts.getMinutes()).padStart(2, "0");
    const ss = String(ts.getSeconds()).padStart(2, "0");
    return {
      id: ++_liveSeq,
      ts: `${hh}:${mm}:${ss}`,
      epoch: Date.now(),
      ip: ipPool.ip,
      geo: ipPool,
      method,
      path,
      region,
      tier,
      risk,
      action,
      rules,
      cat: isAttack ? cat.id : null
    };
  }
  function useLiveFeed(maxLen = 60, paused = false, ratePerSec = 6) {
    const [events, setEvents] = useState(() => {
      const arr = [];
      const now = Date.now();
      for (let i = 0; i < 24; i++) arr.push(makeLiveEvent(now - i * 1e3));
      return arr.reverse();
    });
    useEffect(() => {
      if (paused) return;
      const interval = setInterval(() => {
        const burst = Math.max(1, Math.round(ratePerSec / 2 + Math.random() * ratePerSec));
        setEvents((prev) => {
          const next = [...prev];
          for (let i = 0; i < burst; i++) next.push(makeLiveEvent());
          return next.slice(-maxLen);
        });
      }, 800);
      return () => clearInterval(interval);
    }, [paused, ratePerSec, maxLen]);
    return events;
  }
  function useTrafficSeries(points = 60, paused = false) {
    const [series, setSeries] = useState(() => {
      const arr = [];
      for (let i = 0; i < points; i++) {
        const total = 80 + Math.floor(Math.random() * 60) + Math.sin(i / 5) * 30;
        const blocked = Math.max(0, Math.floor(total * (0.04 + Math.random() * 0.18)));
        arr.push({ t: i, total: Math.max(20, Math.round(total)), blocked });
      }
      return arr;
    });
    useEffect(() => {
      if (paused) return;
      const id = setInterval(() => {
        setSeries((prev) => {
          const last = prev[prev.length - 1] || { t: 0 };
          const t = last.t + 1;
          const burst = Math.random() < 0.08;
          const total = Math.round(70 + Math.random() * 80 + (burst ? 100 : 0));
          const blocked = Math.max(0, Math.round(total * (0.05 + Math.random() * 0.15) + (burst ? 30 : 0)));
          return [...prev.slice(1), { t, total, blocked }];
        });
      }, 1e3);
      return () => clearInterval(id);
    }, [paused]);
    return series;
  }
  function useTicking(intervalMs = 1e3) {
    const [tick, setTick] = useState(0);
    useEffect(() => {
      const id = setInterval(() => setTick((t) => t + 1), intervalMs);
      return () => clearInterval(id);
    }, [intervalMs]);
    return tick;
  }
  function useApi(url, { intervalMs = 5e3, fallback = null } = {}) {
    const [state, setState] = useState({ data: fallback, loading: true, error: null });
    const reload = useCallback(() => {
      fetch(url, { credentials: "same-origin", cache: "no-store" }).then((r) => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))).then((data) => setState({ data, loading: false, error: null })).catch((error) => setState((s) => ({ data: s.data ?? fallback, loading: false, error })));
    }, [url, fallback]);
    useEffect(() => {
      reload();
      if (intervalMs > 0) {
        const id = setInterval(reload, intervalMs);
        return () => clearInterval(id);
      }
    }, [reload, intervalMs]);
    return { ...state, reload };
  }
  let _realLiveSeq = 0;
  function tierForRisk(r) {
    if (r >= 90) return "crit";
    if (r >= 60) return "high";
    if (r >= 25) return "med";
    return "low";
  }
  function fmtTs(epoch) {
    const d = new Date(epoch);
    const h = String(d.getHours()).padStart(2, "0");
    const m = String(d.getMinutes()).padStart(2, "0");
    const s = String(d.getSeconds()).padStart(2, "0");
    return `${h}:${m}:${s}`;
  }
  function useRealLiveFeed(maxLen = 60, paused = false) {
    const [events, setEvents] = useState([]);
    const [connected, setConnected] = useState(false);
    useEffect(() => {
      if (paused) return;
      let es;
      try {
        es = new EventSource("/dashboard/sse", { withCredentials: true });
        es.onopen = () => setConnected(true);
        es.onerror = () => setConnected(false);
        es.onmessage = (e) => {
          try {
            const ev = JSON.parse(e.data);
            const epoch = ev.ts_ms || Date.now();
            const risk = ev.risk_score || 0;
            const action = ev.action || "allow";
            const ip = ev.client_ip || ev.ip || "0.0.0.0";
            const mapped = {
              id: ++_realLiveSeq,
              ts: fmtTs(epoch),
              epoch,
              ip,
              geo: null,
              method: ev.method || "GET",
              path: ev.path || "/",
              region: ev.region || "",
              tier: ev.tier || tierForRisk(risk),
              risk,
              action,
              rules: ev.rule_id ? [ev.rule_id] : ev.rules || [],
              cat: ev.category || ev.cat || null,
              status: ev.status || (action === "block" ? 403 : 200),
              latency: ev.latency_ms || 0
            };
            setEvents((prev) => [...prev, mapped].slice(-maxLen));
          } catch (_) {
          }
        };
      } catch (_) {
      }
      return () => {
        if (es) es.close();
      };
    }, [paused, maxLen]);
    return { events, connected };
  }
  function useRulesApi() {
    return useApi("/api/rules", { intervalMs: 0, fallback: { rules: RULES } });
  }
  function useBlacklistApi() {
    return useApi("/api/blacklist", { intervalMs: 1e4, fallback: { entries: BLACKLIST } });
  }
  function useWhitelistApi() {
    return useApi("/api/whitelist", { intervalMs: 1e4, fallback: { entries: WHITELIST } });
  }
  function useStatusApi() {
    return useApi("/api/about", { intervalMs: 5e3, fallback: null });
  }
  function useStatsApi() {
    return useApi("/api/stats", { intervalMs: 2e3, fallback: null });
  }
  function useTimeseriesApi(window2 = 900, step = 5) {
    return useApi(`/api/stats/timeseries?window=${window2}&step=${step}`, { intervalMs: 5e3, fallback: null });
  }
  function useAttacksDistributionApi(window2 = 900) {
    return useApi(`/api/attacks/distribution?window=${window2}`, { intervalMs: 5e3, fallback: null });
  }
  function useAttacksTopApi(window2 = 900, limit = 10) {
    return useApi(`/api/attacks/top?window=${window2}&limit=${limit}`, { intervalMs: 5e3, fallback: null });
  }
  function useAuditLogApi({ ip, ruleId, requestId, from, to, limit = 200 } = {}) {
    const params = new URLSearchParams();
    if (limit) params.set("limit", String(limit));
    if (ip) params.set("ip", ip);
    if (ruleId) params.set("rule_id", ruleId);
    if (requestId) params.set("request_id", requestId);
    if (from) params.set("from", String(from));
    if (to) params.set("to", String(to));
    return useApi(`/api/audit/since?${params.toString()}`, { intervalMs: 3e3, fallback: null });
  }
  function useRoutesApi() {
    return useApi("/api/routes", { intervalMs: 3e4, fallback: { routes: [] } });
  }
  function useTiersApi() {
    return useApi("/api/tiers", { intervalMs: 3e4, fallback: { tiers: TIERS } });
  }
  function useClusterApi() {
    return useApi("/api/cluster", { intervalMs: 5e3, fallback: { peers: CLUSTER } });
  }
  function useSloApi() {
    return useApi("/api/slo", { intervalMs: 1e4, fallback: null });
  }
  function useCertsApi() {
    return useApi("/api/certs", { intervalMs: 3e4, fallback: { certs: CERTS } });
  }
  function useAlertsApi() {
    return useApi("/api/alerts", { intervalMs: 5e3, fallback: { alerts: ALERTS } });
  }
  function useGitopsApi() {
    return useApi("/api/gitops/status", { intervalMs: 3e4, fallback: null });
  }
  function useUpstreamsApi() {
    return useApi("/api/upstreams", { intervalMs: 5e3, fallback: { pools: UPSTREAMS } });
  }
  function useRuntimeApi() {
    return useApi("/api/runtime", { intervalMs: 6e4, fallback: null });
  }
  async function rulesPost(body) {
    const csrf = document.cookie.split("; ").find((c) => c.startsWith("aegis_csrf="))?.slice(11) || "";
    const r = await fetch("/api/rules", {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      credentials: "same-origin",
      body: JSON.stringify(body)
    });
    return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  }
  async function rulesPut(id, body) {
    const csrf = document.cookie.split("; ").find((c) => c.startsWith("aegis_csrf="))?.slice(11) || "";
    const r = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      credentials: "same-origin",
      body: JSON.stringify(body)
    });
    return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  }
  async function rulesDelete(id) {
    const csrf = document.cookie.split("; ").find((c) => c.startsWith("aegis_csrf="))?.slice(11) || "";
    const r = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { "x-csrf-token": csrf },
      credentials: "same-origin"
    });
    return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  }
  async function rulesToggle(id) {
    const csrf = document.cookie.split("; ").find((c) => c.startsWith("aegis_csrf="))?.slice(11) || "";
    const r = await fetch(`/api/rules/${encodeURIComponent(id)}/toggle`, {
      method: "PUT",
      headers: { "x-csrf-token": csrf },
      credentials: "same-origin"
    });
    return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  }
  async function settingsModePut(mode) {
    const csrf = document.cookie.split("; ").find((c) => c.startsWith("aegis_csrf="))?.slice(11) || "";
    const r = await fetch("/api/mode", {
      method: "PUT",
      headers: { "content-type": "application/json", "x-csrf-token": csrf },
      credentials: "same-origin",
      body: JSON.stringify({ mode })
    });
    return r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  }
  function useModeApi() {
    return useApi("/api/mode", { intervalMs: 5e3, fallback: { mode: "enforce" } });
  }
  async function waitForVersion(expectedVersion, timeoutMs = 1e4) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const r = await fetch("/api/config/version", { credentials: "same-origin", cache: "no-store" });
        if (r.ok) {
          const j = await r.json();
          if (j.version >= expectedVersion) {
            return { applied: true, latencyMs: Date.now() - start, version: j.version, node: j.applied_on_node };
          }
        }
      } catch (_) {
      }
      await new Promise((res) => setTimeout(res, 250));
    }
    return { applied: false, latencyMs: timeoutMs };
  }
  Object.assign(window, {
    ATTACK_CATS,
    ATTACKER_GEO,
    ORIGIN,
    ROUTES,
    REGIONS,
    RULES,
    TIERS,
    BLACKLIST,
    WHITELIST,
    UPSTREAMS,
    CLUSTER,
    CERTS,
    ALERTS,
    ADMIN_LOG,
    useLiveFeed,
    useTrafficSeries,
    useTicking,
    makeLiveEvent,
    // DD-T2 + DD-T6 + DD-T7 — real-API hooks
    useApi,
    useRealLiveFeed,
    useRulesApi,
    useBlacklistApi,
    useWhitelistApi,
    useStatusApi,
    useStatsApi,
    useTimeseriesApi,
    useAttacksDistributionApi,
    useAttacksTopApi,
    useAuditLogApi,
    useClusterApi,
    useSloApi,
    useCertsApi,
    useAlertsApi,
    useGitopsApi,
    useUpstreamsApi,
    useRuntimeApi,
    useRoutesApi,
    useTiersApi,
    rulesPost,
    rulesPut,
    rulesDelete,
    rulesToggle,
    waitForVersion,
    // CI-T6 — settings mutations
    useModeApi,
    settingsModePut
  });
})();
;
(function() {
  const { useState: useStateP, useEffect: useEffectP, useMemo: useMemoP, useRef: useRefP } = React;
  const CAT_COLOR = {
    sqli: "#F6465D",
    xss: "#A555E0",
    ssrf: "#FF8C42",
    path_traversal: "#FCD535",
    recon: "#4DA8FF",
    cmdi: "#FF4D4D",
    lfi: "#E0A415",
    honeypot: "#FCD535",
    rce: "#F6465D",
    body_abuse: "#A87715",
    header_injection: "#6B4710",
    brute_force: "#3B2A1A"
  };
  function colorFor(name) {
    return CAT_COLOR[name] || "#6B7280";
  }
  function PageOverview() {
    const stats = window.useStatsApi();
    const tsApi = window.useTimeseriesApi(60, 1);
    const distApi = window.useAttacksDistributionApi(900);
    const topApi = window.useAttacksTopApi(900, 5);
    const tick = window.useTicking(2e3);
    const [drawerEvent, setDrawerEvent] = useStateP(null);
    const series = useMemoP(() => {
      const pts = tsApi.data?.points || [];
      if (pts.length === 0) return window.useTrafficSeries ? [] : [];
      return pts.map((p) => ({ total: p.total, blocked: p.blocked }));
    }, [tsApi.data]);
    const sparkTotal = series.slice(-30).map((s) => s.total);
    const sparkBlocked = series.slice(-30).map((s) => s.blocked);
    const requestRate = stats.data?.request_rate;
    const blocksTotal = stats.data?.blocks_total ?? 0;
    const blockRate = stats.data?.block_rate_pct;
    const activeThreats = stats.data?.active_threats ?? 0;
    const upstream = stats.data?.upstream;
    const dist = useMemoP(() => {
      const cats = distApi.data?.categories || [];
      return cats.map((c) => ({
        name: c.name,
        color: colorFor(c.name),
        value: c.count
      }));
    }, [distApi.data]);
    const topAttackers = (topApi.data?.attackers || []).map((a) => ({
      id: a.identifier,
      fingerprint: a.identifier.startsWith("fp:") ? a.identifier : null,
      hits: a.hits,
      cats: a.categories || [],
      risk: a.risk,
      country: a.country || null,
      asn: a.asn || null,
      // The WorldMap renderer wants `{cc, city, lat, lon}`. We
      // only have `country` from the backend right now; lat/lon
      // would need a city DB. Pass partial geo so the map can
      // place a country-level blip; full lat/lon arrives when
      // the operator ships a GeoLite2-City.mmdb (follow-up).
      geo: a.country ? { cc: a.country, city: "", lat: 0, lon: 0 } : null
    }));
    const blips = topAttackers.filter((a) => a.country).slice(0, 12).map((a, i) => ({
      cc: a.country,
      city: "",
      lat: 0,
      lon: 0,
      ip: a.id,
      label: a.country,
      show: i < 5
    }));
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Overview"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Realtime WAF traffic monitoring \xB7 5-cluster deployment \xB7 last update ", tick, "s")), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Refresh"), /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.Download, null), " Export"), /* @__PURE__ */ React.createElement("button", { className: "btn primary" }, /* @__PURE__ */ React.createElement(window.I.External, null), " Open Grafana"))), /* @__PURE__ */ React.createElement("div", { className: "ai-card ai-soon", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 10 } }, /* @__PURE__ */ React.createElement("span", { className: "ai-tag" }, /* @__PURE__ */ React.createElement(window.I.Sparkles, null), " AI INSIGHTS"), /* @__PURE__ */ React.createElement("span", { className: "pill warn" }, "Coming soon"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12, color: "var(--ink-mute)" } }, "Automated threat triage & suggested rules \u2014 early access in v1.5"), /* @__PURE__ */ React.createElement("button", { className: "btn sm ghost", style: { marginLeft: "auto" }, disabled: true }, "Notify me \u2192"))), /* @__PURE__ */ React.createElement("div", { className: "kpi-row" }, /* @__PURE__ */ React.createElement(
      window.StatTile,
      {
        title: "Requests / s",
        value: requestRate !== void 0 ? requestRate.toFixed(1) : "\u2014",
        sub: /* @__PURE__ */ React.createElement(React.Fragment, null, "1-second sliding average"),
        icon: /* @__PURE__ */ React.createElement(window.I.Activity, null),
        sparkData: sparkTotal,
        sparkColor: "#3B82F6"
      }
    ), /* @__PURE__ */ React.createElement(
      window.StatTile,
      {
        title: "Block rate",
        value: blockRate !== void 0 ? `${blockRate.toFixed(1)}%` : "\u2014",
        sub: /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("span", { className: "num" }, blocksTotal.toLocaleString()), " blocked total"),
        icon: /* @__PURE__ */ React.createElement(window.I.Ban, null),
        tone: "down",
        sparkData: sparkBlocked,
        sparkColor: "#F6465D"
      }
    ), /* @__PURE__ */ React.createElement(
      window.StatTile,
      {
        title: "Active threats",
        value: String(activeThreats),
        sub: /* @__PURE__ */ React.createElement(React.Fragment, null, "IPs over risk threshold \xB7 last 15m"),
        icon: /* @__PURE__ */ React.createElement(window.I.Siren, null),
        tone: "warn"
      }
    ), /* @__PURE__ */ React.createElement(
      window.StatTile,
      {
        title: "Upstream",
        value: upstream ? upstream.unhealthy === 0 ? "Healthy" : upstream.unhealthy < upstream.healthy ? "Degraded" : "Down" : "\u2014",
        sub: upstream ? `${upstream.healthy} of ${upstream.healthy + upstream.unhealthy} members up` : "awaiting first stats sample",
        icon: /* @__PURE__ */ React.createElement(window.I.Server, null),
        tone: upstream ? upstream.unhealthy === 0 ? "up" : "warn" : void 0
      }
    )), /* @__PURE__ */ React.createElement("div", { className: "card", style: { padding: 0, overflow: "hidden", marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: "1px solid var(--hairline)" } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600 } }, "Live attack origins"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)" } }, "Real-time geolocation of blocked requests \xB7 last 60s")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 8 } }, /* @__PURE__ */ React.createElement("span", { className: "pill block" }, topAttackers.length, " active sources"), /* @__PURE__ */ React.createElement("span", { className: `pill ${blips.length > 0 ? "ok" : "warn"}` }, blips.length > 0 ? `${blips.length} geo-tagged` : "geo DB not loaded"))), /* @__PURE__ */ React.createElement(window.WorldMap, { blips, h: 300 })), /* @__PURE__ */ React.createElement("div", { className: "section-row" }, /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Traffic vs Blocked"), /* @__PURE__ */ React.createElement("div", { className: "card-sub" }, "Realtime \xB7 60s window \xB7 1s buckets")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 6 } }, ["1m", "5m", "15m", "1h"].map((w, i) => /* @__PURE__ */ React.createElement("button", { key: w, className: `chip ${i === 0 ? "active" : ""}` }, w)))), /* @__PURE__ */ React.createElement(window.TrafficChart, { series, h: 220 })), /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Attack distribution"), /* @__PURE__ */ React.createElement("div", { className: "card-sub" }, "By detector class \xB7 15m"))), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 12 } }, /* @__PURE__ */ React.createElement(window.Donut, { slices: dist, size: 170 }), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 4, fontSize: 11, flex: 1 } }, dist.slice().sort((a, b) => b.value - a.value).slice(0, 7).map((s) => /* @__PURE__ */ React.createElement("div", { key: s.name, style: { display: "flex", alignItems: "center", gap: 6 } }, /* @__PURE__ */ React.createElement("span", { style: { width: 8, height: 8, borderRadius: 2, background: s.color } }), /* @__PURE__ */ React.createElement("span", { style: { flex: 1, color: "var(--ink-mute)" } }, s.name), /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: "var(--ink)" } }, s.value))))))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Risk heatmap \u2014 top routes \xD7 time"), /* @__PURE__ */ React.createElement("div", { className: "card-sub" }, "Cell intensity = risk-score sum per 2-min bucket")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 6, alignItems: "center", fontSize: 10, color: "var(--ink-dim)" } }, /* @__PURE__ */ React.createElement("span", null, "low"), ["#1E2329", "#3B2A1A", "#6B4710", "#A87715", "#E0A415", "#FCD535"].map((c) => /* @__PURE__ */ React.createElement("span", { key: c, style: { width: 14, height: 10, background: c, display: "inline-block", borderRadius: 1 } })), /* @__PURE__ */ React.createElement("span", null, "high"))), /* @__PURE__ */ React.createElement(window.RiskHeatmap, { rows: [
      { path: "/api/login", intensity: 0.95 },
      { path: "/api/admin/*", intensity: 0.85 },
      { path: "/wp-admin/*", intensity: 0.75 },
      { path: "/api/payments", intensity: 0.55 },
      { path: "/api/webhooks/*", intensity: 0.92 },
      { path: "/.env, /.git/*", intensity: 0.99 },
      { path: "/actuator/*", intensity: 0.42 },
      { path: "/api/users", intensity: 0.35 }
    ], h: 200 })), /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Top attacker IPs \xB7 15m"), /* @__PURE__ */ React.createElement("button", { className: "btn sm" }, "View all \u2192")), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 36 } }, "#"), /* @__PURE__ */ React.createElement("th", null, "Identifier"), /* @__PURE__ */ React.createElement("th", null, "Origin"), /* @__PURE__ */ React.createElement("th", null, "Hits"), /* @__PURE__ */ React.createElement("th", null, "Categories"), /* @__PURE__ */ React.createElement("th", null, "Risk"), /* @__PURE__ */ React.createElement("th", { style: { width: 180 } }, "Action"))), /* @__PURE__ */ React.createElement("tbody", null, topAttackers.length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 7, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "No attackers observed in the last 15 minutes.")), topAttackers.map((a, i) => /* @__PURE__ */ React.createElement("tr", { key: `${a.id}-${i}`, onClick: () => setDrawerEvent(a) }, /* @__PURE__ */ React.createElement("td", { className: "num dim" }, i + 1), /* @__PURE__ */ React.createElement("td", { className: "mono", style: { fontSize: 12 } }, a.id), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--ink-mute)" } }, a.geo ? `${a.geo.cc} \xB7 ${a.geo.city}` : "\u2014")), /* @__PURE__ */ React.createElement("td", { className: "num" }, a.hits.toLocaleString()), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 4, flexWrap: "wrap" } }, a.cats.map((c) => /* @__PURE__ */ React.createElement("span", { key: c, className: "pill neutral", style: { fontSize: 9 } }, c)))), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement(window.RiskMeter, { value: a.risk })), /* @__PURE__ */ React.createElement("td", { onClick: (e) => e.stopPropagation() }, /* @__PURE__ */ React.createElement("button", { className: "btn sm danger", style: { marginRight: 6 } }, "Block"), /* @__PURE__ */ React.createElement("button", { className: "btn sm", onClick: () => setDrawerEvent(a) }, "Inspect"))))))), /* @__PURE__ */ React.createElement(window.Drawer, { open: !!drawerEvent, onClose: () => setDrawerEvent(null), title: drawerEvent?.id }, drawerEvent && /* @__PURE__ */ React.createElement(RequestDetail, { data: { ip: drawerEvent.id, geo: drawerEvent.geo, hits: drawerEvent.hits, risk: drawerEvent.risk, cats: drawerEvent.cats } })));
  }
  function RequestDetail({ data }) {
    return /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 14 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 6 } }, "Summary"), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: 12 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "dim" }, "Action"), /* @__PURE__ */ React.createElement("span", { className: "pill block" }, "block")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "dim" }, "Reason"), /* @__PURE__ */ React.createElement("span", { className: "mono" }, "owasp-ssrf-001")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "dim" }, "Risk"), /* @__PURE__ */ React.createElement(window.RiskMeter, { value: data.risk || 92 })), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "dim" }, "Tier"), /* @__PURE__ */ React.createElement("span", { className: "pill tier-crit" }, "crit")))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 6 } }, "Network"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, lineHeight: 1.7, fontFamily: "var(--font-mono)" } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "client_ip"), " ", data.ip), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "asn"), " AS14061 (DigitalOcean)"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "geo"), " ", data.geo?.cc, " \xB7 ", data.geo?.city, " (", data.geo?.lat?.toFixed(2), ", ", data.geo?.lon?.toFixed(2), ")"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "ja4"), " t13d_1516h2_8daaf6152771_e5627efa2ab1"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "xff"), " 10.32.4.11 \u2192 10.99.0.1"))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 6 } }, "Request"), /* @__PURE__ */ React.createElement("pre", { style: { background: "var(--canvas)", border: "1px solid var(--hairline)", borderRadius: 6, padding: 10, fontSize: 11, fontFamily: "var(--font-mono)", overflow: "auto", margin: 0, color: "var(--ink-mute)" } }, `POST /api/webhooks/fetch HTTP/1.1
Host: api.aegis.example.com
User-Agent: curl/7.81.0
Content-Type: application/json
X-Forwarded-For: ${data.ip}

{"url": "http://169.254.169.254/latest/meta-data/iam/"}`)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 6 } }, "Detection"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "mono" }, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "rule"), " owasp-ssrf-001 \u2014 SSRF: Internal Addresses"), /* @__PURE__ */ React.createElement("div", { className: "mono" }, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "match"), " body\u2192url contains ", /* @__PURE__ */ React.createElement("span", { style: { color: "var(--down)" } }, "169.254.169.254")))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 6 } }, "Audit"), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--ink-mute)" } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "request_id"), " req_8a1f2c4d9e0b"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "chain_hash"), " a4f2e9c1b3d7\u2026"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "prev"), " a4f2e9c1b3d6 ", /* @__PURE__ */ React.createElement("span", { className: "pill ok", style: { marginLeft: 6 } }, "verified")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "sinks"), " splunk \u2713 \xB7 datadog \u2713 \xB7 s3-archive \u2713"))));
  }
  function PageLiveFeed() {
    const [paused, setPaused] = useStateP(false);
    const { events, connected } = window.useRealLiveFeed(80, paused);
    const [filterAction, setFilterAction] = useStateP("all");
    const [filterTier, setFilterTier] = useStateP("all");
    const [search, setSearch] = useStateP("");
    const [selected, setSelected] = useStateP(null);
    const filtered = events.filter((e) => {
      if (filterAction !== "all" && e.action !== filterAction) return false;
      if (filterTier !== "all" && e.tier !== filterTier) return false;
      if (search && !(e.ip.includes(search) || e.path.toLowerCase().includes(search.toLowerCase()))) return false;
      return true;
    });
    const recent = filtered.slice().reverse();
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Live Feed"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, filtered.length.toLocaleString(), " of ", events.length.toLocaleString(), " events \xB7 streaming via SSE", /* @__PURE__ */ React.createElement("span", { className: `pill ${connected ? "ok" : "warn"}`, style: { marginLeft: 6 } }, connected ? "connected" : "disconnected"))), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.Download, null), " CSV"), /* @__PURE__ */ React.createElement("button", { className: `btn ${paused ? "primary" : ""}`, onClick: () => setPaused((p) => !p) }, paused ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(window.I.Play, null), " Resume") : /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(window.I.Pause, null), " Pause")))), /* @__PURE__ */ React.createElement("div", { className: "card flat", style: { padding: 12, marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" } }, /* @__PURE__ */ React.createElement("select", { className: "input select", style: { width: 130 }, value: filterAction, onChange: (e) => setFilterAction(e.target.value) }, /* @__PURE__ */ React.createElement("option", { value: "all" }, "All actions"), /* @__PURE__ */ React.createElement("option", { value: "allow" }, "Allow"), /* @__PURE__ */ React.createElement("option", { value: "block" }, "Block"), /* @__PURE__ */ React.createElement("option", { value: "challenge" }, "Challenge")), /* @__PURE__ */ React.createElement("select", { className: "input select", style: { width: 130 }, value: filterTier, onChange: (e) => setFilterTier(e.target.value) }, /* @__PURE__ */ React.createElement("option", { value: "all" }, "All risk tiers"), /* @__PURE__ */ React.createElement("option", { value: "low" }, "Low"), /* @__PURE__ */ React.createElement("option", { value: "med" }, "Medium"), /* @__PURE__ */ React.createElement("option", { value: "high" }, "High"), /* @__PURE__ */ React.createElement("option", { value: "crit" }, "Critical")), /* @__PURE__ */ React.createElement("div", { style: { position: "relative", flex: 1, maxWidth: 320 } }, /* @__PURE__ */ React.createElement("span", { style: { position: "absolute", left: 8, top: 7, color: "var(--ink-faint)" } }, /* @__PURE__ */ React.createElement(window.I.Search, null)), /* @__PURE__ */ React.createElement("input", { className: "input", style: { paddingLeft: 28 }, placeholder: "Filter by IP, path\u2026", value: search, onChange: (e) => setSearch(e.target.value) })), /* @__PURE__ */ React.createElement("span", { style: { marginLeft: "auto", fontSize: 11, color: "var(--ink-dim)" } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${connected ? "ok" : "warn"}`, style: { marginRight: 6 } }, connected ? "\u25CF live" : "\u25CB idle"), "buffer ", events.length, "/80"))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { padding: 0, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { maxHeight: "calc(100vh - 280px)", overflow: "auto" } }, /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 80 } }, "Time"), /* @__PURE__ */ React.createElement("th", { style: { width: 130 } }, "IP"), /* @__PURE__ */ React.createElement("th", { style: { width: 70 } }, "Method"), /* @__PURE__ */ React.createElement("th", null, "Path"), /* @__PURE__ */ React.createElement("th", { style: { width: 110 } }, "Region"), /* @__PURE__ */ React.createElement("th", { style: { width: 70 } }, "Tier"), /* @__PURE__ */ React.createElement("th", { style: { width: 80 } }, "Risk"), /* @__PURE__ */ React.createElement("th", { style: { width: 80 } }, "Action"), /* @__PURE__ */ React.createElement("th", { style: { width: 160 } }, "Rules"), /* @__PURE__ */ React.createElement("th", { style: { width: 60 } }))), /* @__PURE__ */ React.createElement("tbody", null, recent.map((e) => /* @__PURE__ */ React.createElement("tr", { key: e.id, className: e.id === recent[0]?.id ? "flash" : "", onClick: () => setSelected(e) }, /* @__PURE__ */ React.createElement("td", { className: "num dim" }, e.ts), /* @__PURE__ */ React.createElement("td", { className: "mono" }, e.ip), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "mono", style: { color: e.method === "POST" ? "var(--info)" : e.method === "DELETE" ? "var(--down)" : "var(--ink-mute)" } }, e.method)), /* @__PURE__ */ React.createElement("td", { className: "mono", style: { color: "var(--ink)" } }, e.path), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "dim", style: { fontSize: 11 } }, e.region)), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement(window.TierPill, { value: e.tier })), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement(window.RiskMeter, { value: e.risk })), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement(window.ActionPill, { value: e.action })), /* @__PURE__ */ React.createElement("td", { className: "mono", style: { fontSize: 10, color: "var(--ink-dim)" } }, e.rules.join(", ") || "\u2014"), /* @__PURE__ */ React.createElement("td", { onClick: (ev) => ev.stopPropagation() }, /* @__PURE__ */ React.createElement("button", { className: "icon-btn", title: "Inspect" }, /* @__PURE__ */ React.createElement(window.I.External, null))))))))), /* @__PURE__ */ React.createElement(
      window.Drawer,
      {
        open: !!selected,
        onClose: () => setSelected(null),
        title: selected?.path,
        footer: /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("button", { className: "btn" }, "Copy as cURL"), /* @__PURE__ */ React.createElement("button", { className: "btn danger" }, "Block IP"), /* @__PURE__ */ React.createElement("button", { className: "btn primary" }, "Whitelist"))
      },
      selected && /* @__PURE__ */ React.createElement(RequestDetail, { data: { ip: selected.ip, geo: selected.geo, risk: selected.risk, cats: [selected.cat] } })
    ));
  }
  function PageAttackEvents() {
    const [win, setWin] = useStateP("1h");
    const detectorBars = window.ATTACK_CATS.map((c) => ({
      label: c.label,
      value: 50 + Math.floor(Math.random() * 1800),
      color: c.color
    })).sort((a, b) => b.value - a.value);
    const topRules = window.RULES.slice(0, 10).sort((a, b) => b.hits1h - a.hits1h);
    const tiHits = [
      { src: "spamhaus_drop", ind: "185.220.101.0/24", cat: "tor-exit", hits: 8421, first: "8h", last: "2s" },
      { src: "firehol_level1", ind: "95.214.55.10", cat: "malware-c2", hits: 412, first: "3h", last: "1m" },
      { src: "tor", ind: "46.166.139.111", cat: "tor-exit", hits: 91, first: "1h", last: "4m" },
      { src: "binarydefense", ind: "AS14061", cat: "abuse-asn", hits: 4128, first: "12h", last: "34s" },
      { src: "emergingthreats", ind: "177.85.34.221", cat: "compromised", hits: 38, first: "20m", last: "12m" }
    ];
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Attack Events"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Curated detector firings \xB7 OWASP + custom rules \xB7 last ", win)), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("select", { className: "input select", value: win, onChange: (e) => setWin(e.target.value), style: { width: 90 } }, ["5m", "15m", "1h", "6h", "24h"].map((v) => /* @__PURE__ */ React.createElement("option", { key: v }, v))), /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.Download, null), " Export CSV"))), /* @__PURE__ */ React.createElement("div", { className: "section-row" }, /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Detector breakdown", sub: `${detectorBars.reduce((s, x) => s + x.value, 0).toLocaleString()} detections in window` }), /* @__PURE__ */ React.createElement(window.BarList, { items: detectorBars })), /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Bot classification mix", sub: "Live classifier signal" }), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 8 } }, /* @__PURE__ */ React.createElement(window.StackedBar, { segments: [
      { name: "verified", value: 4218, color: "var(--up)" },
      { name: "suspect", value: 1842, color: "var(--warn)" },
      { name: "malicious", value: 3104, color: "var(--down)" },
      { name: "unknown", value: 921, color: "var(--ink-faint)" }
    ], h: 28 }), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 6, fontSize: 11 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--up)" } }, "\u25CF verified"), " ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "4,218")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--warn)" } }, "\u25CF suspect"), " ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "1,842")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--down)" } }, "\u25CF malicious"), " ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "3,104")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--ink-faint)" } }, "\u25CF unknown"), " ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "921"))), /* @__PURE__ */ React.createElement("div", { style: { marginTop: 6, padding: 8, background: "var(--canvas-2)", borderRadius: 6, fontSize: 11, color: "var(--ink-mute)" } }, /* @__PURE__ */ React.createElement("strong", { style: { color: "var(--ink-strong)" } }, "30.4%"), " of bot traffic in this window classified as malicious \u2014 above 14d baseline of 18%.")))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Top firing rules", actions: /* @__PURE__ */ React.createElement("button", { className: "btn sm" }, "Manage rules \u2192") }), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "Rule ID"), /* @__PURE__ */ React.createElement("th", null, "Scope"), /* @__PURE__ */ React.createElement("th", null, "Action"), /* @__PURE__ */ React.createElement("th", null, "Risk"), /* @__PURE__ */ React.createElement("th", null, "Count (1h)"), /* @__PURE__ */ React.createElement("th", null, "Last fired"), /* @__PURE__ */ React.createElement("th", null))), /* @__PURE__ */ React.createElement("tbody", null, topRules.map((r, i) => /* @__PURE__ */ React.createElement("tr", { key: `${r.id}-${r.kind}-${i}` }, /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "mono", style: { color: "var(--brand-yellow)" } }, r.id), " ", /* @__PURE__ */ React.createElement("span", { className: "pill builtin", style: { marginLeft: 6 } }, r.kind)), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "dim" }, "global")), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement(window.ActionPill, { value: r.action })), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement(window.RiskMeter, { value: r.risk })), /* @__PURE__ */ React.createElement("td", { className: "num" }, r.hits1h.toLocaleString()), /* @__PURE__ */ React.createElement("td", { className: "dim" }, r.last), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("button", { className: "btn sm" }, "Disable 1h"))))))), /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Threat-intel hits", sub: "Indicators matched in window" }), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "Source"), /* @__PURE__ */ React.createElement("th", null, "Indicator"), /* @__PURE__ */ React.createElement("th", null, "Category"), /* @__PURE__ */ React.createElement("th", null, "Hits"), /* @__PURE__ */ React.createElement("th", null, "First"), /* @__PURE__ */ React.createElement("th", null, "Last"))), /* @__PURE__ */ React.createElement("tbody", null, tiHits.map((t, i) => /* @__PURE__ */ React.createElement("tr", { key: i }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, /* @__PURE__ */ React.createElement("span", { className: "pill violet" }, t.src)), /* @__PURE__ */ React.createElement("td", { className: "mono" }, t.ind), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, t.cat)), /* @__PURE__ */ React.createElement("td", { className: "num" }, t.hits.toLocaleString()), /* @__PURE__ */ React.createElement("td", { className: "dim" }, t.first, " ago"), /* @__PURE__ */ React.createElement("td", { className: "dim" }, t.last, " ago")))))));
  }
  function PageAnalytics() {
    const [range, setRange] = useStateP("24h");
    const reqOverTime = Array.from({ length: 60 }, (_, i) => 800 + Math.sin(i / 5) * 200 + Math.random() * 150);
    const blockRatio = Array.from({ length: 60 }, (_, i) => 0.05 + Math.abs(Math.sin(i / 8)) * 0.12 + Math.random() * 0.04);
    const latP50 = Array.from({ length: 60 }, () => 8 + Math.random() * 4);
    const latP95 = Array.from({ length: 60 }, () => 24 + Math.random() * 8);
    const latP99 = Array.from({ length: 60 }, () => 48 + Math.random() * 16);
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Analytics"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Historical trends \xB7 Prometheus-backed \xB7 ", range, " window")), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 4 } }, ["1h", "6h", "24h", "7d", "30d"].map((r) => /* @__PURE__ */ React.createElement("button", { key: r, className: `chip ${range === r ? "active" : ""}`, onClick: () => setRange(r) }, r))), /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.Refresh, null)), /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.External, null), " Grafana"))), /* @__PURE__ */ React.createElement("div", { className: "grid-12", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Requests over time", sub: `avg ${Math.round(reqOverTime.reduce((s, x) => s + x, 0) / reqOverTime.length)} req/s` }), /* @__PURE__ */ React.createElement(window.Sparkline, { data: reqOverTime, w: 460, h: 120, color: "#3B82F6", fill: true, strokeWidth: 1.5 })), /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Latency p50/p95/p99", sub: "WAF + upstream end-to-end" }), /* @__PURE__ */ React.createElement("div", { style: { position: "relative", height: 120 } }, /* @__PURE__ */ React.createElement(window.Sparkline, { data: latP99, w: 460, h: 120, color: "#F6465D" }), /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", inset: 0 } }, /* @__PURE__ */ React.createElement(window.Sparkline, { data: latP95, w: 460, h: 120, color: "#F0B90B" })), /* @__PURE__ */ React.createElement("div", { style: { position: "absolute", inset: 0 } }, /* @__PURE__ */ React.createElement(window.Sparkline, { data: latP50, w: 460, h: 120, color: "#0ECB81" }))), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 14, fontSize: 11, marginTop: 6 } }, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--up)" } }, "\u25CF p50 9.2ms"), /* @__PURE__ */ React.createElement("span", { style: { color: "var(--warn)" } }, "\u25CF p95 28.4ms"), /* @__PURE__ */ React.createElement("span", { style: { color: "var(--down)" } }, "\u25CF p99 56.1ms"))), /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Block ratio", sub: "Blocked / total \xB7 histogram" }), /* @__PURE__ */ React.createElement(window.Sparkline, { data: blockRatio.map((v) => v * 100), w: 460, h: 120, color: "#F6465D", fill: true }), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-mute)", marginTop: 4 } }, "avg ", /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: "var(--down)" } }, "9.4%"), " \xB7 peak ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "21.8%"), " at 14:32")), /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Error rate by route", sub: "Top 5 routes by block volume" }), /* @__PURE__ */ React.createElement(window.BarList, { items: [
      { label: "/api/login", value: 4218, color: "var(--down)" },
      { label: "/wp-admin/install.php", value: 3812, color: "var(--down)" },
      { label: "/.env", value: 2104, color: "var(--down)" },
      { label: "/api/webhooks/*", value: 1521, color: "var(--warn)" },
      { label: "/api/admin/*", value: 821, color: "var(--warn)" }
    ] }))), /* @__PURE__ */ React.createElement("div", { className: "grid-12" }, /* @__PURE__ */ React.createElement("div", { className: "col-8 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "SLO budget remaining", sub: "30d rolling burn" }), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 10 } }, [
      { name: "availability", target: "99.95%", val: "99.972%", remain: 78, sparkColor: "var(--up)" },
      { name: "latency p95 \u2264 30ms", target: "99%", val: "99.4%", remain: 62, sparkColor: "var(--up)" },
      { name: "WAF overhead p99 \u2264 100\xB5s", target: "99.5%", val: "99.1%", remain: 18, sparkColor: "var(--down)" },
      { name: "audit delivery", target: "99.9%", val: "99.94%", remain: 84, sparkColor: "var(--up)" },
      { name: "cert freshness \u2265 7d", target: "100%", val: "100%", remain: 100, sparkColor: "var(--up)" }
    ].map((s) => /* @__PURE__ */ React.createElement("div", { key: s.name, style: { display: "grid", gridTemplateColumns: "180px 80px 80px 1fr 80px", gap: 12, alignItems: "center", fontSize: 12 } }, /* @__PURE__ */ React.createElement("span", null, s.name), /* @__PURE__ */ React.createElement("span", { className: "dim" }, s.target), /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: "var(--ink)" } }, s.val), /* @__PURE__ */ React.createElement("div", { style: { height: 6, background: "var(--surface-3)", borderRadius: 3, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { width: `${s.remain}%`, height: "100%", background: s.remain < 30 ? "var(--down)" : s.remain < 60 ? "var(--warn)" : "var(--up)" } })), /* @__PURE__ */ React.createElement("span", { className: "num right", style: { color: s.remain < 30 ? "var(--down)" : "var(--ink-mute)" } }, s.remain, "% left"))))), /* @__PURE__ */ React.createElement("div", { className: "col-4 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "Cert freshness" }), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 8 } }, window.CERTS.slice(0, 5).map((c) => {
      const tone = c.days < 7 ? "down" : c.days < 30 ? "warn" : "up";
      return /* @__PURE__ */ React.createElement("div", { key: c.host, style: { display: "flex", alignItems: "center", gap: 8, fontSize: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { flex: 1, overflow: "hidden", textOverflow: "ellipsis" }, className: "mono" }, c.host), /* @__PURE__ */ React.createElement("span", { className: `pill ${tone}` }, c.days, "d"));
    })))));
  }
  function PageAuditLog() {
    const [ipFilter, setIpFilter] = useStateP("");
    const [ruleIdFilter, setRuleIdFilter] = useStateP("");
    const [requestIdFilter, setRequestIdFilter] = useStateP("");
    const [debouncedQ, setDebouncedQ] = useStateP({ ip: "", ruleId: "", requestId: "" });
    useEffectP(() => {
      const t = setTimeout(() => setDebouncedQ({
        ip: ipFilter.trim(),
        ruleId: ruleIdFilter.trim(),
        requestId: requestIdFilter.trim()
      }), 250);
      return () => clearTimeout(t);
    }, [ipFilter, ruleIdFilter, requestIdFilter]);
    const audit = window.useAuditLogApi({
      ip: debouncedQ.ip || void 0,
      ruleId: debouncedQ.ruleId || void 0,
      requestId: debouncedQ.requestId || void 0,
      limit: 200
    });
    const events = audit.data?.events || [];
    const gap = audit.data?.gap;
    function fmt(ts) {
      try {
        const d = new Date(ts);
        const h = String(d.getHours()).padStart(2, "0");
        const m = String(d.getMinutes()).padStart(2, "0");
        const s = String(d.getSeconds()).padStart(2, "0");
        return `${h}:${m}:${s}`;
      } catch (_) {
        return ts;
      }
    }
    function classPill(c) {
      if (c === "admin") return "warn";
      if (c === "system") return "info";
      if (c === "access") return "neutral";
      if (c === "detection") return "block";
      return "neutral";
    }
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Audit Log"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Hash-chained \xB7 ", events.length.toLocaleString(), " events shown", /* @__PURE__ */ React.createElement("span", { style: { marginLeft: 8 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${audit.error ? "warn" : "ok"}` }, audit.error ? "fetch failed" : "live")), gap && /* @__PURE__ */ React.createElement("span", { style: { marginLeft: 6 } }, /* @__PURE__ */ React.createElement("span", { className: "pill warn" }, "stream gap")))), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => audit.reload && audit.reload() }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Refresh"))), /* @__PURE__ */ React.createElement("div", { className: "card flat", style: { padding: 12, marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" } }, /* @__PURE__ */ React.createElement(
      "input",
      {
        className: "input",
        style: { width: 160 },
        placeholder: "client IP",
        value: ipFilter,
        onChange: (e) => setIpFilter(e.target.value)
      }
    ), /* @__PURE__ */ React.createElement(
      "input",
      {
        className: "input",
        style: { width: 200 },
        placeholder: "rule_id",
        value: ruleIdFilter,
        onChange: (e) => setRuleIdFilter(e.target.value)
      }
    ), /* @__PURE__ */ React.createElement(
      "input",
      {
        className: "input",
        style: { flex: 1, maxWidth: 320 },
        placeholder: "request_id",
        value: requestIdFilter,
        onChange: (e) => setRequestIdFilter(e.target.value)
      }
    ), /* @__PURE__ */ React.createElement("span", { style: { marginLeft: "auto", fontSize: 11, color: "var(--ink-dim)" } }, "cursor ", audit.data?.cursor ?? 0, " \u2192 ", audit.data?.next_cursor ?? 0))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { padding: 0 } }, /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 90 } }, "Time"), /* @__PURE__ */ React.createElement("th", { style: { width: 90 } }, "Class"), /* @__PURE__ */ React.createElement("th", { style: { width: 90 } }, "Action"), /* @__PURE__ */ React.createElement("th", { style: { width: 130 } }, "Client IP"), /* @__PURE__ */ React.createElement("th", { style: { width: 160 } }, "Rule"), /* @__PURE__ */ React.createElement("th", null, "Reason"), /* @__PURE__ */ React.createElement("th", { style: { width: 200 } }, "Request ID"))), /* @__PURE__ */ React.createElement("tbody", null, events.length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 7, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "No audit events match the current filters.")), events.slice().reverse().map((row) => {
      const e = row.event || row;
      return /* @__PURE__ */ React.createElement("tr", { key: row.seq }, /* @__PURE__ */ React.createElement("td", { className: "num dim" }, fmt(e.ts)), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: `pill ${classPill(e.class)}` }, e.class)), /* @__PURE__ */ React.createElement("td", { className: "mono", style: { color: "var(--ink)" } }, e.action), /* @__PURE__ */ React.createElement("td", { className: "mono" }, e.client_ip || "\u2014"), /* @__PURE__ */ React.createElement("td", { className: "mono dim", style: { fontSize: 11 } }, e.rule_id || "\u2014"), /* @__PURE__ */ React.createElement("td", { className: "dim" }, e.reason), /* @__PURE__ */ React.createElement("td", { className: "mono", style: { fontSize: 10, color: "var(--brand-yellow)" } }, e.request_id));
    })))));
  }
  function defaultRuleBody(id) {
    return `rule "${id}" {
  priority   = 100
  field      = "any"
  operator   = "regex"
  pattern    = r"example"
  action     = "block"
  risk_delta = 50
  scope      = ["global"]
  tags       = ["custom"]
}
`;
  }
  function ruleRowToBody(r) {
    if (r.body) return r.body;
    return [
      `rule "${r.id}" {`,
      `  // ${r.name || r.id}`,
      `  priority   = ${r.pri ?? 100}`,
      `  field      = "${r.field || "any"}"`,
      `  operator   = "${r.op || "regex"}"`,
      `  pattern    = r"${r.pattern || ""}"`,
      `  action     = "${r.action || "block"}"`,
      `  risk_delta = ${r.risk ?? 50}`,
      `  scope      = ["global"]`,
      `  tags       = ["${r.cat || "custom"}"]`,
      `}`,
      ""
    ].join("\n");
  }
  async function fetchCurrentVersion() {
    try {
      const r = await fetch("/api/config/version", { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) return 0;
      const j = await r.json();
      return Number(j.version) || 0;
    } catch (_) {
      return 0;
    }
  }
  function PageRuleManager() {
    const rulesApi = window.useRulesApi();
    const apiRules = rulesApi.data && Array.isArray(rulesApi.data.rules) && rulesApi.data.rules.length > 0 ? rulesApi.data.rules : window.RULES;
    const mockById = useMemoP(() => {
      const m = /* @__PURE__ */ new Map();
      window.RULES.forEach((r) => {
        if (!m.has(r.id)) m.set(r.id, r);
      });
      return m;
    }, []);
    const merged = apiRules.map((r) => {
      const mock = mockById.get(r.id) || {};
      return {
        id: r.id,
        name: mock.name || r.id,
        kind: mock.kind || "custom",
        pri: mock.pri ?? 100,
        field: mock.field || "any",
        op: mock.op || "regex",
        pattern: mock.pattern || "",
        action: mock.action || "block",
        risk: mock.risk ?? 50,
        enabled: r.enabled !== void 0 ? r.enabled : mock.enabled ?? true,
        cat: mock.cat || "custom",
        hits1h: mock.hits1h ?? 0,
        body: r.body || mock.body || ruleRowToBody(mock.id ? mock : { id: r.id })
      };
    });
    const [selectedId, setSelectedId] = useStateP(merged[0]?.id || null);
    const [tab, setTab] = useStateP("dsl");
    const [search, setSearch] = useStateP("");
    const [editing, setEditing] = useStateP(false);
    const [editBody, setEditBody] = useStateP("");
    const [busy, setBusy] = useStateP(false);
    const [showNew, setShowNew] = useStateP(false);
    const [newId, setNewId] = useStateP("");
    const [newBody, setNewBody] = useStateP(defaultRuleBody("my-rule-001"));
    const [newEnabled, setNewEnabled] = useStateP(true);
    useEffectP(() => {
      if (merged.length === 0) {
        setSelectedId(null);
        return;
      }
      if (!selectedId || !merged.find((r) => r.id === selectedId)) {
        setSelectedId(merged[0].id);
      }
    }, [merged.length, selectedId]);
    const filtered = merged.filter((r) => !search || r.id.includes(search) || r.name.toLowerCase().includes(search.toLowerCase()));
    const selected = merged.find((r) => r.id === selectedId) || merged[0] || null;
    async function runMutation(label, fn) {
      if (busy) return;
      setBusy(true);
      try {
        const before = await fetchCurrentVersion();
        const result = await fn();
        if (result && result.ok) {
          const v = await window.waitForVersion(before + 1, 1e4);
          if (v.applied) {
            window.aegisToast(`${label} \xB7 applied in ${v.latencyMs} ms`, "ok");
          } else {
            window.aegisToast(`${label} \xB7 pending after 10 s`, "warn");
          }
          rulesApi.reload && rulesApi.reload();
        } else {
          const msg = result && (result.message || result.error || result.reason) || "unknown error";
          window.aegisToast(`${label} failed: ${msg}`, "err");
        }
      } catch (err) {
        window.aegisToast(`${label} error: ${err.message || err}`, "err");
      } finally {
        setBusy(false);
      }
    }
    function startEdit() {
      if (!selected) return;
      setEditBody(selected.body || ruleRowToBody(selected));
      setEditing(true);
      setTab("dsl");
    }
    function cancelEdit() {
      setEditing(false);
      setEditBody("");
    }
    async function saveEdit() {
      if (!selected) return;
      await runMutation(
        `Rule ${selected.id} updated`,
        () => window.rulesPut(selected.id, { body: editBody, enabled: selected.enabled })
      );
      setEditing(false);
    }
    async function toggleSelected() {
      if (!selected) return;
      const label = selected.enabled ? `Rule ${selected.id} disabled` : `Rule ${selected.id} enabled`;
      await runMutation(label, () => window.rulesToggle(selected.id));
    }
    async function deleteSelected() {
      if (!selected) return;
      if (!window.confirm(`Delete rule ${selected.id}? This is audit-mutated and cannot be undone.`)) return;
      await runMutation(`Rule ${selected.id} deleted`, () => window.rulesDelete(selected.id));
    }
    async function createNew() {
      const id = newId.trim();
      if (!id) {
        window.aegisToast("Rule id is required", "err");
        return;
      }
      await runMutation(
        `Rule ${id} created`,
        () => window.rulesPost({ id, body: newBody, enabled: newEnabled })
      );
      setShowNew(false);
      setNewId("");
      setNewBody(defaultRuleBody("my-rule-001"));
      setNewEnabled(true);
      setSelectedId(id);
    }
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Rule Manager"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, merged.length, " total \xB7 validate before apply \xB7 audit-chained")), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => rulesApi.reload && rulesApi.reload(), disabled: busy }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Reload"), /* @__PURE__ */ React.createElement("button", { className: "btn primary", onClick: () => setShowNew(true), disabled: busy }, /* @__PURE__ */ React.createElement(window.I.Plus, null), " New rule"))), /* @__PURE__ */ React.createElement("div", { className: "split-list" }, /* @__PURE__ */ React.createElement("div", { className: "left" }, /* @__PURE__ */ React.createElement("div", { style: { padding: 10, borderBottom: "1px solid var(--hairline)" } }, /* @__PURE__ */ React.createElement("div", { style: { position: "relative" } }, /* @__PURE__ */ React.createElement("span", { style: { position: "absolute", left: 8, top: 7, color: "var(--ink-faint)" } }, /* @__PURE__ */ React.createElement(window.I.Search, null)), /* @__PURE__ */ React.createElement("input", { className: "input", style: { paddingLeft: 28 }, placeholder: "Search rule\u2026", value: search, onChange: (e) => setSearch(e.target.value) }))), /* @__PURE__ */ React.createElement("div", { style: { overflow: "auto", flex: 1 } }, filtered.length === 0 && /* @__PURE__ */ React.createElement("div", { style: { padding: 20, fontSize: 12, color: "var(--ink-dim)", textAlign: "center" } }, "No rules match."), filtered.map((r, i) => /* @__PURE__ */ React.createElement(
      "button",
      {
        key: `${r.id}-${i}`,
        onClick: () => {
          setSelectedId(r.id);
          setEditing(false);
        },
        style: {
          display: "block",
          width: "100%",
          textAlign: "left",
          padding: "8px 12px",
          border: "none",
          borderBottom: "1px solid var(--hairline)",
          background: selected && selected.id === r.id ? "var(--surface-active)" : "transparent",
          borderLeft: selected && selected.id === r.id ? "3px solid var(--brand-yellow)" : "3px solid transparent",
          cursor: "pointer",
          color: "inherit"
        }
      },
      /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 6, marginBottom: 2 } }, /* @__PURE__ */ React.createElement("span", { className: "num dim", style: { width: 36, fontSize: 10 } }, r.pri), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12, fontWeight: 500, color: "var(--ink)" } }, r.name), /* @__PURE__ */ React.createElement("span", { className: `pill ${r.kind}`, style: { marginLeft: "auto" } }, r.kind)),
      /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 6, alignItems: "center", fontSize: 10, color: "var(--ink-dim)" } }, /* @__PURE__ */ React.createElement("span", { className: "mono" }, r.id), /* @__PURE__ */ React.createElement("span", null, "\xB7"), /* @__PURE__ */ React.createElement(window.ActionPill, { value: r.action }), r.enabled ? null : /* @__PURE__ */ React.createElement("span", { className: "pill warn", style: { marginLeft: 4 } }, "off"), /* @__PURE__ */ React.createElement("span", { style: { marginLeft: "auto" }, className: "num" }, "+", r.risk))
    )))), /* @__PURE__ */ React.createElement("div", { className: "right" }, selected ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { style: { padding: 14, borderBottom: "1px solid var(--hairline)", display: "flex", alignItems: "center", gap: 10 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 14, fontWeight: 600 } }, selected.name), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)" }, className: "mono" }, selected.id, " \xB7 priority ", selected.pri, " \xB7 ", (selected.hits1h || 0).toLocaleString(), " hits/1h")), /* @__PURE__ */ React.createElement("div", { style: { marginLeft: "auto", display: "flex", gap: 6 } }, !editing && /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: startEdit, disabled: busy }, /* @__PURE__ */ React.createElement(window.I.Edit, null), " Edit"), /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: toggleSelected, disabled: busy }, selected.enabled ? "Disable" : "Enable"), /* @__PURE__ */ React.createElement("button", { className: "btn danger", onClick: deleteSelected, disabled: busy, title: "Delete rule" }, /* @__PURE__ */ React.createElement(window.I.Trash, null)))), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", borderBottom: "1px solid var(--hairline)" } }, ["general", "dsl", "stats"].map((t) => /* @__PURE__ */ React.createElement("button", { key: t, onClick: () => setTab(t), style: {
      flex: "unset",
      padding: "10px 16px",
      background: "transparent",
      border: "none",
      color: tab === t ? "var(--brand-yellow)" : "var(--ink-mute)",
      borderBottom: tab === t ? "2px solid var(--brand-yellow)" : "2px solid transparent",
      fontSize: 12,
      fontWeight: 600,
      textTransform: "capitalize",
      cursor: "pointer"
    } }, t))), /* @__PURE__ */ React.createElement("div", { style: { padding: 16 } }, tab === "general" && /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, fontSize: 12 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "ID"), /* @__PURE__ */ React.createElement("div", { className: "mono" }, selected.id)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Kind"), /* @__PURE__ */ React.createElement("span", { className: `pill ${selected.kind}` }, selected.kind)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Field"), /* @__PURE__ */ React.createElement("div", null, selected.field)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Operator"), /* @__PURE__ */ React.createElement("div", null, selected.op)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Action"), /* @__PURE__ */ React.createElement(window.ActionPill, { value: selected.action })), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Risk \u0394"), /* @__PURE__ */ React.createElement("span", { className: "num" }, "+", selected.risk)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Priority"), /* @__PURE__ */ React.createElement("span", { className: "num" }, selected.pri)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Enabled"), /* @__PURE__ */ React.createElement("div", { className: `toggle ${selected.enabled ? "on" : ""}` }))), tab === "dsl" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8, marginBottom: 8 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${editing ? "warn" : "ok"}` }, editing ? "editing" : "view"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 11, color: "var(--ink-dim)" } }, editing ? "Save & deploy will PUT /api/rules/{id} and toast on apply" : "Click Edit to modify")), editing ? /* @__PURE__ */ React.createElement(
      "textarea",
      {
        className: "input",
        style: { width: "100%", minHeight: 240, fontFamily: "var(--font-mono)", fontSize: 12, lineHeight: 1.5, padding: 12 },
        value: editBody,
        onChange: (e) => setEditBody(e.target.value)
      }
    ) : /* @__PURE__ */ React.createElement("pre", { style: { background: "var(--canvas)", border: "1px solid var(--hairline)", borderRadius: 6, padding: 14, fontSize: 12, fontFamily: "var(--font-mono)", margin: 0, overflow: "auto", lineHeight: 1.6, whiteSpace: "pre-wrap" } }, selected.body || ruleRowToBody(selected))), tab === "stats" && /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)", marginBottom: 6 } }, "Match count \xB7 last 1h"), /* @__PURE__ */ React.createElement(window.Sparkline, { data: Array.from({ length: 60 }, () => 100 + Math.random() * 200), w: 600, h: 80, color: "#FCD535", fill: true })), /* @__PURE__ */ React.createElement(window.BarList, { items: [
      { label: "/api/login", value: 412 },
      { label: "/api/users", value: 318 },
      { label: "/api/orders", value: 217 },
      { label: "/api/admin/*", value: 145 },
      { label: "/api/products", value: 96 }
    ] }))), /* @__PURE__ */ React.createElement("div", { style: { padding: 12, borderTop: "1px solid var(--hairline)", display: "flex", gap: 8, justifyContent: "flex-end" } }, editing && /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: cancelEdit, disabled: busy }, "Cancel"), editing && /* @__PURE__ */ React.createElement("button", { className: "btn primary", onClick: saveEdit, disabled: busy }, "Save & deploy"))) : /* @__PURE__ */ React.createElement("div", { style: { padding: 24, fontSize: 12, color: "var(--ink-dim)" } }, "No rule selected. Use \u201C+ New rule\u201D to create one."))), showNew && /* @__PURE__ */ React.createElement(
      NewRuleModal,
      {
        newId,
        setNewId,
        newBody,
        setNewBody,
        newEnabled,
        setNewEnabled,
        onCancel: () => setShowNew(false),
        onSave: createNew,
        busy
      }
    ));
  }
  function NewRuleModal({ newId, setNewId, newBody, setNewBody, newEnabled, setNewEnabled, onCancel, onSave, busy }) {
    return /* @__PURE__ */ React.createElement("div", { style: {
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,0.5)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 1e3
    }, onClick: onCancel }, /* @__PURE__ */ React.createElement("div", { className: "card", style: { width: 560, maxWidth: "90vw", padding: 0 }, onClick: (e) => e.stopPropagation() }, /* @__PURE__ */ React.createElement("div", { style: { padding: "14px 16px", borderBottom: "1px solid var(--hairline)", display: "flex", alignItems: "center" } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 14, fontWeight: 600 } }, "New rule"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 11, color: "var(--ink-dim)", marginLeft: 8 } }, "POST /api/rules \xB7 audit-mutated \xB7 CSRF-gated"), /* @__PURE__ */ React.createElement("button", { className: "btn", style: { marginLeft: "auto" }, onClick: onCancel, disabled: busy }, "\xD7")), /* @__PURE__ */ React.createElement("div", { style: { padding: 16, display: "flex", flexDirection: "column", gap: 12 } }, /* @__PURE__ */ React.createElement("label", { style: { display: "flex", flexDirection: "column", gap: 4 } }, /* @__PURE__ */ React.createElement("span", { className: "field-label" }, "Rule ID"), /* @__PURE__ */ React.createElement("input", { className: "input", value: newId, onChange: (e) => setNewId(e.target.value), placeholder: "custom-xss-001", autoFocus: true })), /* @__PURE__ */ React.createElement("label", { style: { display: "flex", flexDirection: "column", gap: 4 } }, /* @__PURE__ */ React.createElement("span", { className: "field-label" }, "DSL body"), /* @__PURE__ */ React.createElement(
      "textarea",
      {
        className: "input",
        style: { minHeight: 220, fontFamily: "var(--font-mono)", fontSize: 12, lineHeight: 1.5, padding: 12 },
        value: newBody,
        onChange: (e) => setNewBody(e.target.value)
      }
    )), /* @__PURE__ */ React.createElement("label", { style: { display: "flex", alignItems: "center", gap: 8, fontSize: 12 } }, /* @__PURE__ */ React.createElement("input", { type: "checkbox", checked: newEnabled, onChange: (e) => setNewEnabled(e.target.checked) }), /* @__PURE__ */ React.createElement("span", null, "Enabled on save"))), /* @__PURE__ */ React.createElement("div", { style: { padding: 12, borderTop: "1px solid var(--hairline)", display: "flex", gap: 8, justifyContent: "flex-end" } }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: onCancel, disabled: busy }, "Cancel"), /* @__PURE__ */ React.createElement("button", { className: "btn primary", onClick: onSave, disabled: busy || !newId.trim() }, "Save"))));
  }
  function PageTierConfig() {
    const tiersApi = window.useTiersApi();
    const routesApi = window.useRoutesApi();
    const tiers = tiersApi.data?.tiers || [];
    const routes = routesApi.data?.routes || [];
    const [selectedName, setSelectedName] = useStateP(null);
    useEffectP(() => {
      if (!selectedName && tiers.length > 0) setSelectedName(tiers[0].name);
    }, [tiers.length, selectedName]);
    const selected = tiers.find((t) => t.name === selectedName) || tiers[0] || null;
    const routesForSelected = selected ? routes.filter((r) => r.tier_override === selected.name) : [];
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Tier Config"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Pipeline assignment per tier \xB7", /* @__PURE__ */ React.createElement("span", { className: "num" }, " ", tiers.length), " active tiers \xB7", /* @__PURE__ */ React.createElement("span", { className: "num" }, " ", routes.length), " routes", /* @__PURE__ */ React.createElement("span", { style: { marginLeft: 8 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${tiersApi.error || routesApi.error ? "warn" : "ok"}` }, tiersApi.error || routesApi.error ? "fetch failed" : "live")))), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => {
      tiersApi.reload && tiersApi.reload();
      routesApi.reload && routesApi.reload();
    } }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Refresh"))), /* @__PURE__ */ React.createElement("div", { className: "split-list" }, /* @__PURE__ */ React.createElement("div", { className: "left" }, /* @__PURE__ */ React.createElement("div", { style: { overflow: "auto", flex: 1 } }, tiers.length === 0 && /* @__PURE__ */ React.createElement("div", { style: { padding: 16, fontSize: 12, color: "var(--ink-dim)", textAlign: "center" } }, "No tiers configured."), tiers.map((t) => {
      const tierRouteCount = routes.filter((r) => r.tier_override === t.name).length;
      const detectorCount = (t.pipeline || []).filter((p) => !["rate", "rules", "risk", "challenge"].includes(p)).length;
      return /* @__PURE__ */ React.createElement(
        "button",
        {
          key: t.name,
          onClick: () => setSelectedName(t.name),
          style: {
            display: "block",
            width: "100%",
            textAlign: "left",
            padding: 14,
            border: "none",
            borderBottom: "1px solid var(--hairline)",
            background: selected && selected.name === t.name ? "var(--surface-active)" : "transparent",
            borderLeft: selected && selected.name === t.name ? "3px solid var(--brand-yellow)" : "3px solid transparent",
            cursor: "pointer",
            color: "inherit"
          }
        },
        /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600, marginBottom: 2 } }, t.name),
        /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)", marginBottom: 6 } }, "risk \u2265 ", t.risk_threshold, " \xB7 block \u2265 ", t.block_threshold, "/s"),
        /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 6, fontSize: 10 } }, /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, tierRouteCount, " routes"), /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, detectorCount, " detectors"))
      );
    }))), /* @__PURE__ */ React.createElement("div", { className: "right", style: { padding: 16 } }, selected ? /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 10, marginBottom: 14 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 16, fontWeight: 700 } }, selected.name), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)" } }, (selected.pipeline || []).length, " pipeline stages \xB7 risk threshold ", /* @__PURE__ */ React.createElement("span", { className: "num" }, selected.risk_threshold)))), /* @__PURE__ */ React.createElement("div", { style: { background: "var(--canvas-2)", border: "1px solid var(--hairline)", borderRadius: 6, padding: 12, marginBottom: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, fontWeight: 600, marginBottom: 10 } }, "Pipeline (", (selected.pipeline || []).length, " stages)"), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexWrap: "wrap", gap: 6 } }, (selected.pipeline || []).map((p) => /* @__PURE__ */ React.createElement("span", { key: p, className: "pill neutral", style: { fontSize: 10 } }, p)))), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, fontWeight: 600, marginBottom: 8 } }, "Routes assigned to ", /* @__PURE__ */ React.createElement("span", { className: "mono" }, selected.name), " (", routesForSelected.length, ")"), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "Route ID"), /* @__PURE__ */ React.createElement("th", null, "Host"), /* @__PURE__ */ React.createElement("th", null, "Path"), /* @__PURE__ */ React.createElement("th", null, "Match"), /* @__PURE__ */ React.createElement("th", null, "Methods"), /* @__PURE__ */ React.createElement("th", null, "Upstream"))), /* @__PURE__ */ React.createElement("tbody", null, routesForSelected.length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 6, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "No routes assigned to this tier.")), routesForSelected.map((r) => /* @__PURE__ */ React.createElement("tr", { key: r.id }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, r.id), /* @__PURE__ */ React.createElement("td", { className: "mono dim" }, r.host || "*"), /* @__PURE__ */ React.createElement("td", { className: "mono" }, r.path), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, r.match_type)), /* @__PURE__ */ React.createElement("td", { className: "mono dim" }, r.methods.length === 0 ? "ANY" : r.methods.join(", ")), /* @__PURE__ */ React.createElement("td", { className: "mono" }, r.upstream))))))) : /* @__PURE__ */ React.createElement("div", { style: { padding: 24, color: "var(--ink-dim)", fontSize: 12 } }, "Select a tier to inspect."))));
  }
  function ListPage({ kind }) {
    const isBL = kind === "blacklist";
    const api = isBL ? window.useBlacklistApi() : window.useWhitelistApi();
    const raw = api.data?.entries ?? api.data ?? [];
    const data = Array.isArray(raw) ? raw : [];
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, isBL ? "Blacklist" : "Whitelist"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, data.length.toLocaleString(), " entries", /* @__PURE__ */ React.createElement("span", { style: { marginLeft: 8 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${api.error ? "warn" : "ok"}` }, api.error ? "fetch failed" : "live")))), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => api.reload && api.reload() }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Refresh"), /* @__PURE__ */ React.createElement("button", { className: "btn primary" }, /* @__PURE__ */ React.createElement(window.I.Plus, null), " Add entry"))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { padding: 0 } }, /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 90 } }, "Type"), /* @__PURE__ */ React.createElement("th", null, "Value"), /* @__PURE__ */ React.createElement("th", null, "Note"), /* @__PURE__ */ React.createElement("th", { style: { width: 130 } }, isBL ? "Action" : "Bypass"), /* @__PURE__ */ React.createElement("th", { style: { width: 130 } }, "Expires"), /* @__PURE__ */ React.createElement("th", { style: { width: 130 } }, "Created"))), /* @__PURE__ */ React.createElement("tbody", null, data.length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 6, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "No entries.")), data.map((e) => /* @__PURE__ */ React.createElement("tr", { key: e.id }, /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, e.kind || e.type)), /* @__PURE__ */ React.createElement("td", { className: "mono", style: { color: "var(--ink-strong)" } }, e.value), /* @__PURE__ */ React.createElement("td", { className: "dim", style: { maxWidth: 280, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" } }, e.note || e.reason || ""), /* @__PURE__ */ React.createElement("td", null, isBL ? /* @__PURE__ */ React.createElement(window.ActionPill, { value: e.action || "block" }) : /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 4, flexWrap: "wrap" } }, (e.bypass || []).includes("all") ? /* @__PURE__ */ React.createElement("span", { className: "pill solid-yellow" }, "all \xB7 high-trust") : (e.bypass || []).map((b) => /* @__PURE__ */ React.createElement("span", { key: b, className: "pill neutral", style: { fontSize: 9 } }, b)))), /* @__PURE__ */ React.createElement("td", { className: "num", style: { color: e.expires_at ? "var(--warn)" : "var(--ink-dim)" } }, e.expires_at ? new Date(e.expires_at).toISOString().slice(0, 10) : "never"), /* @__PURE__ */ React.createElement("td", { className: "dim", style: { fontSize: 11 } }, e.created_at ? new Date(e.created_at).toISOString().slice(0, 10) : "\u2014")))))));
  }
  function PageSettings() {
    const modeApi = window.useModeApi();
    const mode = modeApi.data?.mode || "enforce";
    const isShadow = mode === "log_only";
    const [busy, setBusy] = useStateP(false);
    const [allow, setAllow] = useStateP(51);
    const [challenge, setChallenge] = useStateP(75);
    const [honeypots, setHoneypots] = useStateP(["/.env", "/.git/config", "/wp-admin/install.php", "/phpmyadmin", "/aws/credentials", "/actuator/env"]);
    const [stackTraces, setStackTraces] = useStateP(true);
    const [redactJSON, setRedactJSON] = useStateP(true);
    async function toggleShadow() {
      if (busy) return;
      setBusy(true);
      const next = isShadow ? "enforce" : "log_only";
      try {
        const before = await fetch("/api/config/version", { credentials: "same-origin", cache: "no-store" }).then((r) => r.json()).then((j) => Number(j.version) || 0).catch(() => 0);
        const result = await window.settingsModePut(next);
        if (result && result.ok) {
          const v = await window.waitForVersion(before + 1, 1e4);
          if (v.applied) {
            window.aegisToast(`Mode \u2192 ${next} \xB7 applied in ${v.latencyMs} ms`, "ok");
          } else {
            window.aegisToast(`Mode \u2192 ${next} \xB7 pending after 10 s`, "warn");
          }
          modeApi.reload && modeApi.reload();
        } else {
          const msg = result && (result.message || result.error || result.reason) || "unknown error";
          window.aegisToast(`Mode change failed: ${msg}`, "err");
        }
      } catch (err) {
        window.aegisToast(`Mode change error: ${err.message || err}`, "err");
      } finally {
        setBusy(false);
      }
    }
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Settings"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Changes apply immediately \u2014 no restart required", /* @__PURE__ */ React.createElement("span", { style: { marginLeft: 8 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${isShadow ? "warn" : "ok"}` }, isShadow ? "log_only" : "enforce"))))), isShadow && /* @__PURE__ */ React.createElement("div", { className: "banner warn", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { style: { marginTop: 1 } }, /* @__PURE__ */ React.createElement(window.I.Siren, null)), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ React.createElement("div", { className: "banner-strong" }, "Shadow mode is ON \u2014 no traffic is being blocked."), /* @__PURE__ */ React.createElement("div", null, "Detection events still appear in Live Feed with their original action.")), /* @__PURE__ */ React.createElement("span", { className: "pill warn", style: { alignSelf: "flex-start" } }, "ACTIVE")), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Shadow Mode (Dry-Run)"), /* @__PURE__ */ React.createElement(
      "div",
      {
        className: `toggle ${isShadow ? "on" : ""}`,
        onClick: busy ? void 0 : toggleShadow,
        style: { cursor: busy ? "wait" : "pointer" }
      }
    )), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: "var(--ink-mute)" } }, "Log detections without blocking. Audit chain still records every event; /api/mode endpoint is audit-mutated and CSRF-gated.")), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Risk thresholds")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 14 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 6 } }, /* @__PURE__ */ React.createElement("span", null, "Allow (0 \u2013 ", allow, ")"), /* @__PURE__ */ React.createElement("span", { className: "num" }, allow)), /* @__PURE__ */ React.createElement("input", { type: "range", min: "0", max: "100", value: allow, onChange: (e) => setAllow(+e.target.value), style: { width: "100%", accentColor: "var(--brand-yellow)" } })), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 6 } }, /* @__PURE__ */ React.createElement("span", null, "Challenge (", allow + 1, " \u2013 ", challenge, ")"), /* @__PURE__ */ React.createElement("span", { className: "num" }, challenge)), /* @__PURE__ */ React.createElement("input", { type: "range", min: allow + 1, max: "100", value: challenge, onChange: (e) => setChallenge(+e.target.value), style: { width: "100%", accentColor: "var(--brand-yellow)" } })), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: "var(--ink-mute)" } }, "Block threshold: ", /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: "var(--down)" } }, "\u2265 ", challenge + 1)))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Challenge Engine")), /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Challenge type"), /* @__PURE__ */ React.createElement("select", { className: "input select", defaultValue: "JS Challenge" }, /* @__PURE__ */ React.createElement("option", null, "JS Challenge"), /* @__PURE__ */ React.createElement("option", null, "JS + CAPTCHA"), /* @__PURE__ */ React.createElement("option", null, "Strict (PoW)"))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Honeypot Paths")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 } }, honeypots.map((p) => /* @__PURE__ */ React.createElement("span", { key: p, className: "chip active" }, p, " ", /* @__PURE__ */ React.createElement("span", { className: "chip-x", onClick: () => setHoneypots((hp) => hp.filter((x) => x !== p)) }, /* @__PURE__ */ React.createElement(window.I.X, null))))), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 6 } }, /* @__PURE__ */ React.createElement("input", { className: "input", placeholder: "/trap-path" }), /* @__PURE__ */ React.createElement("button", { className: "icon-btn" }, /* @__PURE__ */ React.createElement(window.I.Plus, null)))), /* @__PURE__ */ React.createElement("div", { className: "card" }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Response Filtering")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 10 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8 } }, /* @__PURE__ */ React.createElement("div", { className: `toggle ${stackTraces ? "on" : ""}`, onClick: () => setStackTraces((s) => !s) }), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12 } }, "Block stack traces in responses")), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8 } }, /* @__PURE__ */ React.createElement("div", { className: `toggle ${redactJSON ? "on" : ""}`, onClick: () => setRedactJSON((s) => !s) }), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12 } }, "Redact JSON fields (password, secret, token, ssn)")))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginTop: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "card-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "card-title" }, "Cache management"), /* @__PURE__ */ React.createElement("div", { className: "card-sub" }, "Flush internal caches without restarting the WAF")), /* @__PURE__ */ React.createElement("button", { className: "btn danger" }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Reset all caches")), /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 10 } }, [
      { k: "rules", t: "Rule cache", d: "Compiled regex / rule AST", size: "128 MB", age: "14m", n: "1,247 entries" },
      { k: "geoip", t: "GeoIP cache", d: "IP \u2192 country/ASN lookups", size: "412 MB", age: "2h 8m", n: "8.4M entries" },
      { k: "ti", t: "Threat-intel cache", d: "Feed-derived indicators", size: "58 MB", age: "6m", n: "142,381 entries" },
      { k: "fp", t: "Fingerprint cache", d: "JA4 / TLS fingerprints", size: "24 MB", age: "3m", n: "52,108 entries" },
      { k: "session", t: "Session cache", d: "Challenge-passed session tokens", size: "16 MB", age: "52s", n: "12,884 entries" },
      { k: "dns", t: "DNS cache", d: "Upstream resolution", size: "4 MB", age: "11m", n: "3,212 entries" }
    ].map((c) => /* @__PURE__ */ React.createElement("div", { key: c.k, style: { display: "flex", alignItems: "center", gap: 10, padding: 10, background: "var(--canvas-2)", border: "1px solid var(--hairline)", borderRadius: 6 } }, /* @__PURE__ */ React.createElement("div", { style: { flex: 1, minWidth: 0 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, fontWeight: 600 } }, c.t), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 11, color: "var(--ink-dim)" } }, c.d), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", marginTop: 2 } }, /* @__PURE__ */ React.createElement("span", { className: "num" }, c.size), " \xB7 ", /* @__PURE__ */ React.createElement("span", { className: "num" }, c.n), " \xB7 refreshed ", /* @__PURE__ */ React.createElement("span", { className: "num" }, c.age), " ago")), /* @__PURE__ */ React.createElement("button", { className: "btn sm" }, "Flush")))), /* @__PURE__ */ React.createElement("div", { className: "banner warn", style: { marginTop: 12, padding: 10 } }, /* @__PURE__ */ React.createElement("div", { style: { marginTop: 1 } }, /* @__PURE__ */ React.createElement(window.I.Siren, null)), /* @__PURE__ */ React.createElement("div", { style: { flex: 1, fontSize: 12 } }, "Flushing the GeoIP or rule cache briefly increases latency while caches warm up. The action is hash-chained into the audit log."))));
  }
  function PageTracking() {
    const cluster = window.useClusterApi();
    const upstreamsApi = window.useUpstreamsApi();
    const slo = window.useSloApi();
    const certs = window.useCertsApi();
    const alerts = window.useAlertsApi();
    const gitops = window.useGitopsApi();
    const upstreamsRaw = upstreamsApi.data?.pools ?? upstreamsApi.data ?? [];
    const upstreams = Array.isArray(upstreamsRaw) ? upstreamsRaw : [];
    const peers = cluster.data?.peers || [];
    const ourNode = cluster.data?.our_node;
    const isLeader = cluster.data?.is_leader;
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Tracking"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Operational state \xB7 SLO \xB7 cluster \xB7 GitOps \xB7 cert health", /* @__PURE__ */ React.createElement("span", { style: { marginLeft: 8 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${isLeader ? "solid-yellow" : "neutral"}` }, ourNode ? `node ${ourNode}${isLeader ? " \xB7 leader" : ""}` : "standalone")))), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn", onClick: () => {
      cluster.reload && cluster.reload();
      upstreamsApi.reload && upstreamsApi.reload();
      slo.reload && slo.reload();
      certs.reload && certs.reload();
      alerts.reload && alerts.reload();
      gitops.reload && gitops.reload();
    } }, /* @__PURE__ */ React.createElement(window.I.Refresh, null), " Refresh"))), /* @__PURE__ */ React.createElement("div", { className: "grid-12", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, /* @__PURE__ */ React.createElement(window.SectionHeader, { title: "SLO budget", sub: "live engine \xB7 burn windows pending wiring" }), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 8 } }, (slo.data?.slis || []).length === 0 && /* @__PURE__ */ React.createElement("div", { style: { padding: 12, fontSize: 12, color: "var(--ink-dim)", textAlign: "center" } }, "No SLO data \u2014 engine warming up."), (slo.data?.slis || []).map((s) => {
      const tone = s.budget_remaining > 0.5 ? "up" : s.budget_remaining > 0.1 ? "warn" : "down";
      return /* @__PURE__ */ React.createElement("div", { key: s.name, style: { display: "grid", gridTemplateColumns: "180px 80px 80px 1fr 80px", gap: 10, alignItems: "center", fontSize: 12 } }, /* @__PURE__ */ React.createElement("span", null, s.name), /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: `var(--${tone === "up" ? "up" : tone === "warn" ? "warn" : "down"})` } }, s.current.toFixed(2), "%"), /* @__PURE__ */ React.createElement("span", { className: "dim" }, s.target.toFixed(2), "%"), /* @__PURE__ */ React.createElement("div", { style: { height: 6, background: "var(--surface-3)", borderRadius: 3, overflow: "hidden" } }, /* @__PURE__ */ React.createElement("div", { style: { width: `${(s.budget_remaining * 100).toFixed(0)}%`, height: "100%", background: tone === "up" ? "var(--up)" : tone === "warn" ? "var(--warn)" : "var(--down)" } })), /* @__PURE__ */ React.createElement("span", { className: `pill ${tone}` }, (s.budget_remaining * 100).toFixed(0), "% left"));
    }))), /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, (() => {
      const firing = alerts.data?.firing || [];
      const resolved = alerts.data?.resolved || [];
      return /* @__PURE__ */ React.createElement(
        window.SectionHeader,
        {
          title: "Active alerts",
          sub: `${firing.length} firing \xB7 ${resolved.length} acked`
        }
      );
    })(), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 6 } }, (alerts.data?.firing || []).length === 0 && /* @__PURE__ */ React.createElement("div", { style: { padding: 12, fontSize: 12, color: "var(--ink-dim)", textAlign: "center" } }, "No alerts firing."), (alerts.data?.firing || []).map((a) => /* @__PURE__ */ React.createElement("div", { key: a.name, style: { display: "flex", alignItems: "center", gap: 8, padding: 8, background: "var(--canvas-2)", borderRadius: 6, fontSize: 12 } }, /* @__PURE__ */ React.createElement("span", { className: `pill ${a.severity === "page" ? "err" : a.severity === "ticket" ? "warn" : "info"}` }, a.severity), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }, /* @__PURE__ */ React.createElement("div", { className: "mono", style: { color: "var(--ink)" } }, a.name), a.runbook_url && /* @__PURE__ */ React.createElement("a", { href: a.runbook_url, target: "_blank", rel: "noopener noreferrer", className: "dim", style: { fontSize: 11 } }, "runbook \u2197")), /* @__PURE__ */ React.createElement("span", { className: "dim", style: { fontSize: 11 } }, a.since ? new Date(a.since).toLocaleTimeString() : "")))))), /* @__PURE__ */ React.createElement("div", { className: "card", style: { marginBottom: 12 } }, (() => {
      const totalMembers = upstreams.reduce((s, x) => s + (x.members || x.total_members || 0), 0);
      const totalHealthy = upstreams.reduce((s, x) => s + (x.healthy || x.healthy_members || 0), 0);
      return /* @__PURE__ */ React.createElement(
        window.SectionHeader,
        {
          title: "Upstream pools",
          sub: `${upstreams.length} pools \xB7 ${totalHealthy}/${totalMembers} healthy`
        }
      );
    })(), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "Pool"), /* @__PURE__ */ React.createElement("th", null, "Members"), /* @__PURE__ */ React.createElement("th", null, "LB"), /* @__PURE__ */ React.createElement("th", null, "Circuit"), /* @__PURE__ */ React.createElement("th", null, "p99"), /* @__PURE__ */ React.createElement("th", null, "req/s"), /* @__PURE__ */ React.createElement("th", null, "Status"))), /* @__PURE__ */ React.createElement("tbody", null, upstreams.length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 7, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "No upstream pools registered.")), upstreams.map((p) => {
      const total = p.members ?? p.total_members ?? 0;
      const healthy = p.healthy ?? p.healthy_members ?? 0;
      const cb = p.cb || p.circuit_breaker || "closed";
      const ok = total > 0 && healthy === total;
      const half = cb === "half-open";
      const open = cb === "open";
      return /* @__PURE__ */ React.createElement("tr", { key: p.name }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, p.name), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", gap: 2 } }, Array.from({ length: total }).map((_, i) => /* @__PURE__ */ React.createElement("span", { key: i, style: { width: 8, height: 14, background: i < healthy ? "var(--up)" : "var(--down)", borderRadius: 1 } })), /* @__PURE__ */ React.createElement("span", { className: "num dim", style: { marginLeft: 6, fontSize: 11 } }, healthy, "/", total))), /* @__PURE__ */ React.createElement("td", { className: "mono dim" }, p.lb || "\u2014"), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: `pill ${open ? "err" : half ? "warn" : "ok"}` }, cb)), /* @__PURE__ */ React.createElement("td", { className: "num" }, p.p99 ? `${p.p99}ms` : "\u2014"), /* @__PURE__ */ React.createElement("td", { className: "num" }, (p.rps ?? 0).toLocaleString()), /* @__PURE__ */ React.createElement("td", null, ok && !open ? /* @__PURE__ */ React.createElement("span", { className: "pill ok" }, "healthy") : open ? /* @__PURE__ */ React.createElement("span", { className: "pill err" }, "down") : /* @__PURE__ */ React.createElement("span", { className: "pill warn" }, "degraded")));
    })))), /* @__PURE__ */ React.createElement("div", { className: "grid-12", style: { marginBottom: 12 } }, /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, /* @__PURE__ */ React.createElement(
      window.SectionHeader,
      {
        title: "Cluster peers",
        sub: `${peers.length} ${peers.length === 1 ? "node" : "nodes"} \xB7 ${cluster.data?.leader_node ? `leader: ${cluster.data.leader_node}` : "no leader observed"}`
      }
    ), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "ID"), /* @__PURE__ */ React.createElement("th", null, "Address"), /* @__PURE__ */ React.createElement("th", null, "Version"), /* @__PURE__ */ React.createElement("th", null, "Role"), /* @__PURE__ */ React.createElement("th", null, "Heartbeat"), /* @__PURE__ */ React.createElement("th", null, "Leases"))), /* @__PURE__ */ React.createElement("tbody", null, peers.length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 6, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "Single-node deployment \u2014 no cluster peers.")), peers.map((c) => /* @__PURE__ */ React.createElement("tr", { key: c.id }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, c.id), /* @__PURE__ */ React.createElement("td", { className: "mono dim" }, c.addr || "\u2014"), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, c.version || "\u2014")), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: `pill ${c.id === cluster.data?.leader_node ? "solid-yellow" : "neutral"}` }, c.id === cluster.data?.leader_node ? "leader" : "follower")), /* @__PURE__ */ React.createElement("td", { className: "num dim" }, c.last_heartbeat ? new Date(c.last_heartbeat).toLocaleTimeString() : "\u2014"), /* @__PURE__ */ React.createElement("td", null, (c.leases || []).length === 0 ? /* @__PURE__ */ React.createElement("span", { className: "dim" }, "\u2014") : c.leases.map((l) => /* @__PURE__ */ React.createElement("span", { key: l, className: "pill info", style: { marginRight: 4 } }, l)))))))), /* @__PURE__ */ React.createElement("div", { className: "col-6 card" }, (() => {
      const certList = certs.data?.certs || [];
      return /* @__PURE__ */ React.createElement(
        window.SectionHeader,
        {
          title: "Cert freshness",
          sub: `${certList.length} cert${certList.length === 1 ? "" : "s"} loaded`
        }
      );
    })(), /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "Host"), /* @__PURE__ */ React.createElement("th", null, "Issuer"), /* @__PURE__ */ React.createElement("th", null, "Source"), /* @__PURE__ */ React.createElement("th", null, "Expires"))), /* @__PURE__ */ React.createElement("tbody", null, (certs.data?.certs || []).length === 0 && /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("td", { colSpan: 4, style: { textAlign: "center", padding: 16, color: "var(--ink-dim)", fontSize: 12 } }, "No certs configured (data plane is plaintext).")), (certs.data?.certs || []).map((c) => {
      const tone = c.days_to_expiry < 7 ? "err" : c.days_to_expiry < 30 ? "warn" : "ok";
      return /* @__PURE__ */ React.createElement("tr", { key: c.host + c.issuer }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, c.host), /* @__PURE__ */ React.createElement("td", { className: "dim" }, c.issuer), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, c.source)), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("span", { className: `pill ${tone}` }, c.days_to_expiry, "d")));
    }))))), /* @__PURE__ */ React.createElement("div", { className: "card" }, (() => {
      const g = gitops.data || {};
      const configured = Boolean(g.repo);
      return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement(
        window.SectionHeader,
        {
          title: "GitOps sync",
          sub: configured ? `auto-pull from ${g.branch || "main"}` : "not configured"
        }
      ), configured ? /* @__PURE__ */ React.createElement("div", { style: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, fontSize: 12 } }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Repo"), /* @__PURE__ */ React.createElement("div", { className: "mono" }, g.repo)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Branch"), /* @__PURE__ */ React.createElement("span", { className: "pill neutral" }, g.branch)), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Last sync"), /* @__PURE__ */ React.createElement("span", { className: "num" }, g.last_sync ? new Date(g.last_sync).toLocaleTimeString() : "\u2014")), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "Drift"), /* @__PURE__ */ React.createElement("span", { className: `pill ${g.drift ? "warn" : "ok"}` }, g.drift ? "drift" : "none")), g.head_commit && /* @__PURE__ */ React.createElement("div", { style: { gridColumn: "1 / -1" } }, /* @__PURE__ */ React.createElement("div", { className: "field-label" }, "HEAD commit"), /* @__PURE__ */ React.createElement("div", { className: "mono", style: { fontSize: 11 } }, /* @__PURE__ */ React.createElement("span", { style: { color: "var(--brand-yellow)" } }, g.head_commit.slice(0, 7)), /* @__PURE__ */ React.createElement("span", { className: `pill ${g.signature_ok ? "ok" : "err"}`, style: { marginLeft: 8 } }, g.signature_ok ? "signature verified" : "signature failed")))) : /* @__PURE__ */ React.createElement("div", { style: { padding: 12, fontSize: 12, color: "var(--ink-dim)" } }, "GitOps disabled. Set ", /* @__PURE__ */ React.createElement("span", { className: "mono" }, "gitops.repo_url"), " in your config to enable config-as-code."));
    })()));
  }
  Object.assign(window, {
    PageOverview,
    PageLiveFeed,
    PageAttackEvents,
    PageAnalytics,
    PageAuditLog,
    PageRuleManager,
    PageTierConfig,
    ListPage,
    PageSettings,
    PageTracking
  });
})();
;
(function() {
  const { useState: useStateH } = React;
  function PageHelp() {
    const [tab, setTab] = useStateH("start");
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "page-head" }, /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("h1", { className: "page-title" }, "Help & Guide"), /* @__PURE__ */ React.createElement("p", { className: "page-subtitle" }, "Onboarding for new operators \xB7 last updated 2026-04-28 \xB7 v1.4.2")), /* @__PURE__ */ React.createElement("div", { className: "page-actions" }, /* @__PURE__ */ React.createElement("button", { className: "btn" }, /* @__PURE__ */ React.createElement(window.I.External, null), " Full docs"), /* @__PURE__ */ React.createElement("button", { className: "btn primary" }, /* @__PURE__ */ React.createElement(window.I.Bell, null), " Contact on-call"))), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", borderBottom: "1px solid var(--hairline)", marginBottom: 14, gap: 0 } }, [
      { id: "start", label: "Quickstart" },
      { id: "glossary", label: "Glossary" },
      { id: "workflows", label: "Common workflows" },
      { id: "shortcuts", label: "Shortcuts" }
    ].map((t) => /* @__PURE__ */ React.createElement("button", { key: t.id, onClick: () => setTab(t.id), style: {
      padding: "10px 18px",
      background: "transparent",
      border: "none",
      color: tab === t.id ? "var(--brand-yellow)" : "var(--ink-mute)",
      borderBottom: tab === t.id ? "2px solid var(--brand-yellow)" : "2px solid transparent",
      fontSize: 13,
      fontWeight: 600,
      cursor: "pointer"
    } }, t.label))), tab === "start" && /* @__PURE__ */ React.createElement("div", { className: "grid-12" }, [
      { n: 1, t: "Watch the live feed", d: "Open Live Feed to see every request the WAF is evaluating. Each row shows the IP, path, risk score, and the action that was taken. Use this when investigating an incident.", cta: "Open Live Feed \u2192", to: "#/live" },
      { n: 2, t: "Block an attacker", d: "Click any row in Live Feed or Top Attackers to open the inspector drawer, then hit Block IP. The IP is added to the global blacklist with an audit-chained reason.", cta: "See Blacklist \u2192", to: "#/blacklist" },
      { n: 3, t: "Test a new rule safely", d: "Toggle Shadow Mode in Settings \u2014 the WAF will log every detection without enforcing. Watch Live Feed for false positives, then disable shadow mode to enforce.", cta: "Open Settings \u2192", to: "#/settings" },
      { n: 4, t: "Validate before deploy", d: "In Rule Manager, edit the DSL and click Validate. The 1h dry-run shows how many requests in production would have matched. Save & deploy commits with a hash-chained audit entry.", cta: "Open Rule Manager \u2192", to: "#/rules" },
      { n: 5, t: "Track operational health", d: "Tracking surfaces SLO burn, upstream pool health, cluster peers, GitOps sync, and cert freshness. Alerts firing here have linked runbooks.", cta: "Open Tracking \u2192", to: "#/tracking" },
      { n: 6, t: "Audit any change", d: "Audit Log is a hash-chained, witnessed record of every config change and detection. Filter by actor, target, or hash; verify the chain on demand.", cta: "Open Audit Log \u2192", to: "#/audit" }
    ].map((s) => /* @__PURE__ */ React.createElement("div", { key: s.n, className: "col-4 card", style: { padding: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 10, marginBottom: 8 } }, /* @__PURE__ */ React.createElement("span", { style: { width: 28, height: 28, borderRadius: 6, background: "var(--brand-yellow)", color: "#0B0E11", display: "inline-flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 13 } }, s.n), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600 } }, s.t)), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 12, color: "var(--ink-mute)", lineHeight: 1.6, marginBottom: 12 } }, s.d), /* @__PURE__ */ React.createElement("a", { href: s.to, className: "btn sm", style: { textDecoration: "none" } }, s.cta)))), tab === "glossary" && /* @__PURE__ */ React.createElement("div", { className: "card", style: { padding: 0 } }, /* @__PURE__ */ React.createElement("table", { className: "tbl tbl-compact" }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", { style: { width: 200 } }, "Term"), /* @__PURE__ */ React.createElement("th", null, "Meaning"))), /* @__PURE__ */ React.createElement("tbody", null, [
      ["Tier", "A pipeline assignment for a route. Each tier defines a TLS profile, rate-limit profile, challenge ladder, and detector set. Higher tiers = stricter posture."],
      ["Risk score", "A 0\u2013100 number assigned per request based on detector firings and signal aggregation. Compared against the Allow / Challenge / Block thresholds set in Settings."],
      ["Action", "Final disposition: allow (pass-through), challenge (JS / CAPTCHA / PoW), block (closed connection or 403)."],
      ["Detector", "A class of analyzer (sqli, xss, ssrf, recon, \u2026). Each rule belongs to one detector."],
      ["Rule", "A single match definition: field \xD7 operator \xD7 pattern \u2192 action + risk delta. Built-in rules ship with releases; custom rules live in your config repo."],
      ["Shadow mode", "A global switch that logs detections without blocking. Use it to validate new rules in production traffic without customer impact."],
      ["Fingerprint", "A stable hash of TLS / HTTP characteristics (JA4, header order, etc.) \u2014 useful for identifying actors that rotate IPs."],
      ["Honeypot", "A path that should never receive legitimate traffic (/.env, /.git/config). Hits are an immediate high-risk signal."],
      ["Audit chain", "Append-only hash-chained log of every config change and detection. Each entry includes the previous hash; an external witness signs batches."],
      ["GitOps drift", "Difference between the running config and the HEAD of the config repo. The control plane auto-pulls and reports drift."],
      ["SLO burn", "How fast you are spending your error budget for a given SLO. Burn > 1\xD7 means you will exhaust the budget before the window resets."],
      ["Upstream pool", "A logical group of origin servers behind a load-balancing strategy. Each pool has a circuit-breaker state."]
    ].map(([t, d]) => /* @__PURE__ */ React.createElement("tr", { key: t }, /* @__PURE__ */ React.createElement("td", { className: "mono", style: { color: "var(--brand-yellow)" } }, t), /* @__PURE__ */ React.createElement("td", { className: "dim" }, d)))))), tab === "workflows" && /* @__PURE__ */ React.createElement("div", { className: "grid-12" }, [
      { t: "Block an attacker mid-incident", steps: ["Open Live Feed and filter by the IP or path of interest.", "Click any matching row to open the request inspector.", "Press Block IP in the drawer footer \u2014 the IP is added to the global blacklist immediately.", "The change is recorded in Audit Log under blacklist.add."] },
      { t: "Test a new rule before enforcing", steps: ["Settings \u2192 toggle Shadow Mode ON.", "Rule Manager \u2192 New rule. Write the DSL and click Validate.", "The 1h dry-run shows the would-have-matched count against live traffic.", "Save & deploy. Watch Live Feed for false positives over 30\u201360 min.", "Toggle Shadow Mode OFF to enforce."] },
      { t: "Investigate a 5xx spike on upstream", steps: ["Tracking \u2192 Upstream pools. Look for circuit-breaker state of half-open or open.", "Drill into the pool to see member health and p99 latency.", "Cross-reference Live Feed for matching upstream errors.", "If circuit is open, fix the upstream then click Reset breaker."] },
      { t: "Renew a certificate", steps: ["Tracking \u2192 Cert freshness. Identify cert with < 7 days remaining (red).", "For ACME-managed certs, click Renew \u2014 it reorders inline.", "For static certs, follow the runbook linked in the alert."] },
      { t: "Geo-block a country", steps: ["Blacklist \u2192 Add entry \u2192 Type: Country.", "Pick the ISO code and choose action (block or challenge).", "Optionally scope to a specific tier or route (e.g. /api/admin only).", "Save. The change is hash-chained into the audit log."] },
      { t: "Trust a partner network", steps: ["Whitelist \u2192 Add entry \u2192 Type: CIDR or ASN.", "Choose which protections to bypass (rate-limit, specific detector, all).", "Set an expiry if temporary (e.g. for a pen-test engagement).", "Add a clear reason \u2014 your auditors will read it."] }
    ].map((w, i) => /* @__PURE__ */ React.createElement("div", { key: i, className: "col-6 card", style: { padding: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600, marginBottom: 10 } }, w.t), /* @__PURE__ */ React.createElement("ol", { style: { margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.8, color: "var(--ink-mute)" } }, w.steps.map((s, j) => /* @__PURE__ */ React.createElement("li", { key: j }, s)))))), tab === "shortcuts" && /* @__PURE__ */ React.createElement("div", { className: "grid-12" }, /* @__PURE__ */ React.createElement("div", { className: "col-6 card", style: { padding: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600, marginBottom: 12 } }, "Global"), [
      ["\u2318K / Ctrl+K", "Open command palette"],
      ["ESC", "Close palette / drawer"],
      ["G then O", "Go to Overview"],
      ["G then L", "Go to Live Feed"],
      ["G then R", "Go to Rule Manager"],
      ["G then S", "Go to Settings"],
      ["G then T", "Go to Tracking"]
    ].map(([k, l]) => /* @__PURE__ */ React.createElement("div", { key: k, style: { display: "flex", alignItems: "center", gap: 12, fontSize: 12, padding: "7px 0", borderBottom: "1px solid var(--hairline)" } }, /* @__PURE__ */ React.createElement("span", { className: "kbd", style: { minWidth: 110, display: "inline-block", textAlign: "center" } }, k), /* @__PURE__ */ React.createElement("span", { style: { color: "var(--ink-mute)" } }, l)))), /* @__PURE__ */ React.createElement("div", { className: "col-6 card", style: { padding: 16 } }, /* @__PURE__ */ React.createElement("div", { style: { fontSize: 13, fontWeight: 600, marginBottom: 12 } }, "Live Feed"), [
      ["Space", "Pause / resume stream"],
      ["/", "Focus filter input"],
      ["\u2191 / \u2193", "Move between rows"],
      ["Enter", "Open request inspector"],
      ["B", "Block IP from selected row"],
      ["W", "Whitelist IP from selected row"],
      ["C", "Copy as cURL"]
    ].map(([k, l]) => /* @__PURE__ */ React.createElement("div", { key: k, style: { display: "flex", alignItems: "center", gap: 12, fontSize: 12, padding: "7px 0", borderBottom: "1px solid var(--hairline)" } }, /* @__PURE__ */ React.createElement("span", { className: "kbd", style: { minWidth: 110, display: "inline-block", textAlign: "center" } }, k), /* @__PURE__ */ React.createElement("span", { style: { color: "var(--ink-mute)" } }, l))))));
  }
  Object.assign(window, { PageHelp });
})();
;
(function() {
  const { useState, useEffect } = React;
  const NAV = [
    { group: "Operator", items: [
      { id: "overview", label: "Overview", icon: /* @__PURE__ */ React.createElement(window.I.Shield, null), badge: null },
      { id: "live", label: "Live Feed", icon: /* @__PURE__ */ React.createElement(window.I.Activity, null), badge: "LIVE", tone: "live" },
      { id: "attacks", label: "Attack Events", icon: /* @__PURE__ */ React.createElement(window.I.Siren, null), badge: null },
      { id: "analytics", label: "Analytics", icon: /* @__PURE__ */ React.createElement(window.I.BarChart, null), badge: null },
      { id: "audit", label: "Audit Log", icon: /* @__PURE__ */ React.createElement(window.I.Book, null), badge: null }
    ] },
    { group: "Configuration", items: [
      { id: "rules", label: "Rule Manager", icon: /* @__PURE__ */ React.createElement(window.I.Layers, null), badge: null },
      { id: "tiers", label: "Tier Config", icon: /* @__PURE__ */ React.createElement(window.I.Cluster, null), badge: null },
      { id: "blacklist", label: "Blacklist", icon: /* @__PURE__ */ React.createElement(window.I.Ban, null), badge: null, tone: "down" },
      { id: "whitelist", label: "Whitelist", icon: /* @__PURE__ */ React.createElement(window.I.Check, null), badge: null, tone: "up" },
      { id: "settings", label: "Settings", icon: /* @__PURE__ */ React.createElement(window.I.Settings, null), badge: null }
    ] },
    { group: "Tracking", items: [
      { id: "tracking", label: "Tracking", icon: /* @__PURE__ */ React.createElement(window.I.Gauge, null), badge: "SLO", tone: "warn" }
    ] },
    { group: "Resources", items: [
      { id: "help", label: "Help & Guide", icon: /* @__PURE__ */ React.createElement(window.I.Book, null), badge: null }
    ] }
  ];
  function TopBar({ env }) {
    return /* @__PURE__ */ React.createElement("div", { className: "topbar" }, /* @__PURE__ */ React.createElement("div", { className: "brand" }, /* @__PURE__ */ React.createElement("div", { className: "brand-mark" }, "A"), /* @__PURE__ */ React.createElement("div", null, /* @__PURE__ */ React.createElement("div", { className: "brand-name" }, "Aegis WAF", /* @__PURE__ */ React.createElement("span", { className: "brand-version", style: { marginLeft: 6 } }, "v1.4.2")), /* @__PURE__ */ React.createElement("div", { style: { fontSize: 10, color: "var(--ink-faint)", letterSpacing: 0.4 } }, "ENTERPRISE CONTROL PLANE"))), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 6 } }, /* @__PURE__ */ React.createElement("span", { className: `env-pill ${env}` }, "\u25CF ", env.toUpperCase()), /* @__PURE__ */ React.createElement("span", { className: "env-pill", style: { background: "var(--surface-2)", color: "var(--ink-mute)" } }, "SG-1 EDGE \xB7 5 nodes")), /* @__PURE__ */ React.createElement("div", { style: { flex: 1 } }), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8 } }, /* @__PURE__ */ React.createElement("span", { style: { display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "var(--ink-mute)" } }, /* @__PURE__ */ React.createElement("span", { className: "led ok" }), " Healthy"), /* @__PURE__ */ React.createElement("button", { className: "icon-btn", title: "Notifications", style: { position: "relative" } }, /* @__PURE__ */ React.createElement(window.I.Bell, null), /* @__PURE__ */ React.createElement("span", { style: { position: "absolute", top: 4, right: 4, width: 6, height: 6, borderRadius: "50%", background: "var(--down)" } })), /* @__PURE__ */ React.createElement("div", { className: "user-chip" }, /* @__PURE__ */ React.createElement("div", { className: "avatar" }, "AD"), /* @__PURE__ */ React.createElement("div", { style: { display: "flex", flexDirection: "column" } }, /* @__PURE__ */ React.createElement("span", { style: { fontSize: 12, color: "var(--ink)", fontWeight: 600, lineHeight: 1.2 } }, "admin"), /* @__PURE__ */ React.createElement("span", { style: { fontSize: 10, color: "var(--ink-dim)" } }, "SUPER \xB7 TOTP")))));
  }
  function Sidebar({ active, onNav }) {
    return /* @__PURE__ */ React.createElement("aside", { className: "sidebar" }, /* @__PURE__ */ React.createElement("div", { style: { flex: 1, overflowY: "auto", padding: "12px 8px" } }, NAV.map((g) => /* @__PURE__ */ React.createElement("div", { key: g.group, className: "nav-group" }, /* @__PURE__ */ React.createElement("div", { className: "nav-heading" }, g.group), g.items.map((it) => /* @__PURE__ */ React.createElement(
      "button",
      {
        key: it.id,
        onClick: () => onNav(it.id),
        className: `nav-item ${active === it.id ? "active" : ""}`
      },
      /* @__PURE__ */ React.createElement("span", { className: "nav-icon" }, it.icon),
      /* @__PURE__ */ React.createElement("span", { className: "nav-label" }, it.label),
      it.badge && /* @__PURE__ */ React.createElement("span", { className: `nav-badge ${it.tone || ""} ${it.tone === "live" ? "live-dot" : ""}` }, it.badge)
    ))))), /* @__PURE__ */ React.createElement("div", { style: { padding: 12, borderTop: "1px solid var(--hairline)", fontSize: 10, color: "var(--ink-faint)" } }, /* @__PURE__ */ React.createElement("div", { style: { marginBottom: 4 } }, "BUILD ", /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: "var(--ink-mute)" } }, "1.4.2-3a8f")), /* @__PURE__ */ React.createElement("div", null, "UPTIME ", /* @__PURE__ */ React.createElement("span", { className: "num", style: { color: "var(--ink-mute)" } }, "14d 22h"))));
  }
  function StatusBar({ tick }) {
    return /* @__PURE__ */ React.createElement("div", { className: "statusbar" }, /* @__PURE__ */ React.createElement("span", null, /* @__PURE__ */ React.createElement("span", { className: "led ok" }), " SSE connected"), /* @__PURE__ */ React.createElement("span", { className: "dim" }, "|"), /* @__PURE__ */ React.createElement("span", null, "Cluster ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "5/5")), /* @__PURE__ */ React.createElement("span", { className: "dim" }, "|"), /* @__PURE__ */ React.createElement("span", null, "Last config sync ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "14s")), /* @__PURE__ */ React.createElement("span", { className: "dim" }, "|"), /* @__PURE__ */ React.createElement("span", null, "Audit chain ", /* @__PURE__ */ React.createElement("span", { className: "pill ok" }, "verified")), /* @__PURE__ */ React.createElement("span", { className: "dim" }, "|"), /* @__PURE__ */ React.createElement("span", null, "GitOps ", /* @__PURE__ */ React.createElement("span", { className: "pill ok" }, "in-sync")), /* @__PURE__ */ React.createElement("span", { style: { marginLeft: "auto" } }, "Build ", /* @__PURE__ */ React.createElement("span", { className: "num" }, "1.4.2-3a8f"), " \xB7 ", tick, "s"));
  }
  function App() {
    const [route, setRoute] = useState(() => location.hash.slice(2) || "overview");
    const tick = window.useTicking(2e3);
    useEffect(() => {
      document.documentElement.dataset.density = "compact";
      document.documentElement.dataset.accent = "yellow";
    }, []);
    useEffect(() => {
      const onHash = () => setRoute(location.hash.slice(2) || "overview");
      window.addEventListener("hashchange", onHash);
      return () => window.removeEventListener("hashchange", onHash);
    }, []);
    const nav = (id) => {
      location.hash = `/${id}`;
    };
    let page = null;
    switch (route) {
      case "overview":
        page = /* @__PURE__ */ React.createElement(window.PageOverview, null);
        break;
      case "live":
        page = /* @__PURE__ */ React.createElement(window.PageLiveFeed, null);
        break;
      case "attacks":
        page = /* @__PURE__ */ React.createElement(window.PageAttackEvents, null);
        break;
      case "analytics":
        page = /* @__PURE__ */ React.createElement(window.PageAnalytics, null);
        break;
      case "audit":
        page = /* @__PURE__ */ React.createElement(window.PageAuditLog, null);
        break;
      case "rules":
        page = /* @__PURE__ */ React.createElement(window.PageRuleManager, null);
        break;
      case "tiers":
        page = /* @__PURE__ */ React.createElement(window.PageTierConfig, null);
        break;
      case "blacklist":
        page = /* @__PURE__ */ React.createElement(window.ListPage, { kind: "blacklist" });
        break;
      case "whitelist":
        page = /* @__PURE__ */ React.createElement(window.ListPage, { kind: "whitelist" });
        break;
      case "settings":
        page = /* @__PURE__ */ React.createElement(window.PageSettings, null);
        break;
      case "tracking":
        page = /* @__PURE__ */ React.createElement(window.PageTracking, null);
        break;
      case "help":
        page = /* @__PURE__ */ React.createElement(window.PageHelp, null);
        break;
      default:
        page = /* @__PURE__ */ React.createElement(window.PageOverview, null);
    }
    return /* @__PURE__ */ React.createElement("div", { className: "app density-compact" }, /* @__PURE__ */ React.createElement(TopBar, { env: "prod" }), /* @__PURE__ */ React.createElement(Sidebar, { active: route, onNav: nav }), /* @__PURE__ */ React.createElement("main", { className: "content" }, page), /* @__PURE__ */ React.createElement(StatusBar, { tick }), /* @__PURE__ */ React.createElement(window.ToastContainer, null));
  }
  ReactDOM.createRoot(document.getElementById("root")).render(/* @__PURE__ */ React.createElement(App, null));
})();
