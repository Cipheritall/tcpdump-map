#!/usr/bin/env python3
"""Build an interactive HTML port map from the tcpdump network-services CSVs.

Every ``<name>_<ip>_network_services.csv`` file in the input folder is read
(the format produced by ``net.py``). TCP/UDP rows are turned into directed
flows ``source -> destination:port`` and rendered as a graph with draggable
nodes plus a filterable flow table.

Usage:
    python build_ports_map.py [--input ../tcpdump] [--output ../tcpdump/ports-map.html]
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "tcpdump"
DEFAULT_OUTPUT = DEFAULT_INPUT / "ports-map.html"

FILE_RE = re.compile(
    r"^(?P<name>.+)_(?P<ip>\d{1,3}(?:\.\d{1,3}){3})_network_services\.csv$"
)
TRANSPORTS = {"TCP", "UDP"}
EPHEMERAL_START = 1024


@dataclass
class Capture:
    name: str
    ip: str
    file: str
    rows: list[dict[str, str]]


@dataclass
class Flow:
    src: str
    dst: str
    proto: str
    port: int
    service: str | None = None
    packets: int = 0
    bytes: int = 0
    observers: set[str] = field(default_factory=set)


def clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return None if value in ("", "-") else value


def to_int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def load_captures(folder: Path) -> list[Capture]:
    captures = []
    for path in sorted(folder.glob("*_network_services.csv"), key=lambda p: p.name.lower()):
        match = FILE_RE.match(path.name)
        if not match:
            print(f"Skipping {path.name}: cannot extract <name>_<ip> from file name", file=sys.stderr)
            continue
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.DictReader(handle))
        captures.append(Capture(match["name"], match["ip"], path.name, rows))
    return captures


def capture_flows(capture: Capture) -> dict[tuple, Flow]:
    """Reduce one capture to service-port flows, dropping reply traffic."""
    outbound_tuples = {
        (r["protocol"].upper(), r["local_port"], r["remote_ip"], r["remote_port"])
        for r in capture.rows
        if r.get("direction", "").upper() == "OUT"
    }
    flows: dict[tuple, Flow] = {}

    for row in capture.rows:
        proto = (row.get("protocol") or "").upper()
        local_port, remote_port = row.get("local_port", ""), row.get("remote_port", "")
        if proto not in TRANSPORTS or not (local_port.isdigit() and remote_port.isdigit()):
            continue
        local_service = clean(row.get("local_service"))
        remote_service = clean(row.get("remote_service"))
        remote_ip = row["remote_ip"].strip()
        lport, rport = int(local_port), int(remote_port)
        direction = (row.get("direction") or "").upper()

        if direction == "OUT":
            # Answer sent by a local service (e.g. SNMP reply) -> covered by the IN row.
            if remote_service is None and (local_service is not None or (lport < EPHEMERAL_START <= rport)):
                continue
            src, dst, port, service = capture.ip, remote_ip, rport, remote_service
        elif direction == "IN":
            if local_service is not None:
                src, dst, port, service = remote_ip, capture.ip, lport, local_service
            elif remote_service is not None or rport < EPHEMERAL_START <= lport:
                continue  # answer to one of our requests
            elif (proto, local_port, remote_ip, remote_port) in outbound_tuples:
                continue  # answer to an unclassified outbound flow
            else:
                src, dst, port, service = remote_ip, capture.ip, lport, None
        else:
            continue

        key = (src, dst, proto, port)
        flow = flows.setdefault(key, Flow(src, dst, proto, port, service))
        flow.service = flow.service or service
        flow.packets += to_int(row.get("packets"))
        flow.bytes += to_int(row.get("bytes"))
        flow.observers.add(capture.name)
    return flows


def merge_flows(captures: list[Capture]) -> list[Flow]:
    merged: dict[tuple, Flow] = {}
    for capture in captures:
        for key, flow in capture_flows(capture).items():
            if key not in merged:
                merged[key] = flow
                continue
            # Same flow seen from both monitored ends: keep the largest count, not the sum.
            existing = merged[key]
            existing.service = existing.service or flow.service
            existing.packets = max(existing.packets, flow.packets)
            existing.bytes = max(existing.bytes, flow.bytes)
            existing.observers |= flow.observers
    return sorted(merged.values(), key=lambda f: (f.src, f.dst, f.proto, f.port))


def ip_scope(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if address.is_multicast:
        return "multicast"
    if address.is_private:
        return "private"
    return "public"


def build_data(captures: list[Capture], flows: list[Flow]) -> dict:
    servers = {c.ip: c for c in captures}
    nodes = [
        {"id": c.ip, "label": c.name, "ip": c.ip, "kind": "server", "file": c.file}
        for c in sorted(captures, key=lambda c: tuple(int(p) for p in c.ip.split(".")))
    ]
    services_by_peer: dict[str, set[str]] = {}
    for flow in flows:
        for ip in (flow.src, flow.dst):
            if ip not in servers:
                services_by_peer.setdefault(ip, set())
        if flow.dst not in servers:
            services_by_peer[flow.dst].add(flow.service or f"{flow.proto.lower()}/{flow.port}")

    def ip_key(ip: str):
        try:
            return (0, int(ipaddress.ip_address(ip)))
        except ValueError:
            return (1, ip)

    for ip in sorted(services_by_peer, key=ip_key):
        nodes.append({
            "id": ip,
            "label": ip,
            "ip": ip,
            "kind": ip_scope(ip),
            "services": sorted(services_by_peer[ip]),
        })

    protocols: dict[str, int] = {}
    for flow in flows:
        protocols[flow.proto] = protocols.get(flow.proto, 0) + 1
    raw_protocols: dict[str, int] = {}
    for capture in captures:
        for row in capture.rows:
            proto = (row.get("protocol") or "?").upper()
            raw_protocols[proto] = raw_protocols.get(proto, 0) + 1

    return {
        "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "files": [c.file for c in captures],
        "nodes": nodes,
        "flows": [
            {
                "src": f.src,
                "dst": f.dst,
                "proto": f.proto,
                "port": f.port,
                "service": f.service,
                "packets": f.packets,
                "bytes": f.bytes,
                "observers": sorted(f.observers),
            }
            for f in flows
        ],
        "stats": {
            "servers": len(captures),
            "flows": len(flows),
            "peers": len(nodes) - len(captures),
            "rows": sum(len(c.rows) for c in captures),
            "protocols": protocols,
            "rawProtocols": raw_protocols,
            "serverToServer": sum(1 for f in flows if f.src in servers and f.dst in servers),
        },
    }


def render_html(data: dict) -> str:
    # Escape "<" so the JSON can never close the <script> element.
    payload = json.dumps(data, separators=(",", ":")).replace("<", "\\u003c")
    return HTML_TEMPLATE.replace("__DATA__", payload)


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Diverto · Observed network ports</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #09111f; --panel: #111d30; --line: #273a55; --text: #edf4ff; --muted: #9aacc4;
      --server: #61d5e8; --private: #82aaff; --public: #c792ea; --multicast: #85e0a3; --inbound: #ffb86b;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-width: 320px; color: var(--text); background: radial-gradient(ellipse at 16% -5%, #163252 0, transparent 38rem), var(--bg); }
    .page { width: min(1480px, 100% - 40px); margin: 0 auto; padding: 34px 0 60px; }
    .eyebrow { color: var(--server); font-size: 11px; font-weight: 750; letter-spacing: .16em; text-transform: uppercase; }
    h1 { margin: 8px 0 10px; font-size: clamp(26px, 4vw, 40px); letter-spacing: -.04em; }
    .intro { max-width: 860px; margin: 0; color: var(--muted); line-height: 1.6; }
    .summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 24px 0 18px; }
    .stat, .panel { border: 1px solid var(--line); border-radius: 14px; background: rgba(17, 29, 48, .92); }
    .stat { padding: 16px 18px; }
    .stat strong { display: block; font-size: 25px; }
    .stat span { display: block; margin-top: 4px; color: var(--muted); font-size: 12px; }
    .notice { margin-bottom: 18px; padding: 14px 16px; border: 1px solid #664c2d; border-radius: 12px; background: #302516; color: #f3dfc0; font-size: 13px; line-height: 1.55; }
    .notice b { color: #ffd398; }
    .panel { overflow: hidden; }
    .panel-heading { display: flex; justify-content: space-between; gap: 18px; padding: 18px 20px 14px; border-bottom: 1px solid var(--line); }
    h2 { margin: 0; font-size: 17px; }
    .panel-heading p { margin: 5px 0 0; color: var(--muted); font-size: 12px; line-height: 1.5; }
    .legend { display: flex; flex-wrap: wrap; gap: 12px; align-content: flex-start; color: var(--muted); font-size: 11px; }
    .legend span { display: inline-flex; align-items: center; gap: 6px; }
    .dot { width: 9px; height: 9px; border-radius: 50%; }
    .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding: 12px 20px; border-bottom: 1px solid var(--line); }
    label { color: var(--muted); font-size: 12px; }
    select, input, button { min-height: 36px; border: 1px solid #344a68; border-radius: 8px; padding: 0 11px; color: var(--text); background: #0d1829; font: inherit; font-size: 12px; }
    select { min-width: 200px; }
    input[type=search] { flex: 1 1 220px; }
    button { cursor: pointer; }
    button:hover { border-color: var(--server); }
    select:focus, input:focus, button:focus-visible { outline: 2px solid #61d5e866; border-color: var(--server); }
    #graph-scroll { overflow-x: auto; }
    #graph { display: block; width: 100%; height: max(480px, calc(100vh - 140px)); touch-action: none; user-select: none; -webkit-user-select: none; cursor: grab; background-image: radial-gradient(#1c2c44 1px, transparent 1px); background-size: 22px 22px; }
    #graph.panning { cursor: grabbing; }
    .link path { fill: none; stroke: #6685ac; stroke-width: 1.5; opacity: .6; }
    .link.inbound path { stroke: var(--inbound); stroke-dasharray: 6 4; }
    .link rect { fill: #0c1727; stroke: #344a68; }
    .link text { fill: #d9e7f8; font-size: 10px; font-weight: 650; text-anchor: middle; dominant-baseline: central; pointer-events: none; }
    .link:hover path, .link.hl path { stroke: var(--server); stroke-width: 2.6; opacity: 1; }
    .node { cursor: move; }
    .node rect { fill: #16263c; stroke-width: 1.6; }
    .node .title { fill: var(--text); font-size: 12px; font-weight: 700; text-anchor: middle; pointer-events: none; }
    .node .sub { fill: var(--muted); font-size: 9.5px; text-anchor: middle; pointer-events: none; }
    .node.selected rect { stroke-width: 3; fill: #1d3452; }
    .node .badge rect, .node.selected .badge rect { stroke: #0b1320; stroke-width: 1.5; }
    .node .badge text { fill: #0b1320; font-size: 10px; font-weight: 800; text-anchor: middle; pointer-events: none; }
    .node .badge.local rect { fill: #0b1320; stroke: #85e0a3; stroke-width: 1.5; }
    .node .badge.local text { fill: #85e0a3; }
    .dim { opacity: .12; }
    .hint { padding: 8px 20px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--line); }
    .table-meta { padding: 12px 20px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); }
    .table-scroll { max-height: 520px; overflow: auto; border-top: 1px solid var(--line); }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 12px; }
    th, td { padding: 10px 14px; border-bottom: 1px solid #22334a; white-space: nowrap; }
    thead { position: sticky; top: 0; z-index: 1; }
    th { color: #9aacc4; background: #101b2d; font-size: 10px; letter-spacing: .09em; text-transform: uppercase; }
    .filter-row th { padding: 0 8px 10px; border-bottom: 1px solid #344a68; }
    .filter-row input { width: 100%; min-width: 90px; min-height: 30px; padding: 0 8px; text-transform: none; letter-spacing: 0; font-size: 11px; }
    .filter-row input.active { border-color: var(--server); background: #10283a; }
    .table-meta { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .table-meta button { min-height: 30px; }
    .table-meta button[hidden] { display: none; }
    tbody tr:hover { background: #17263b; }
    .name { font-weight: 700; }
    .subtle { display: block; margin-top: 2px; color: var(--muted); font-size: 10px; }
    .badge { display: inline-block; border: 1px solid #35516e; border-radius: 20px; padding: 3px 8px; color: #bfeefa; background: #122a3b; font-size: 10px; font-weight: 700; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .none { padding: 26px; color: var(--muted); text-align: center; }
    .footnote { margin: 14px 2px 0; color: #8295af; font-size: 11px; line-height: 1.6; }
    @media (max-width: 780px) {
      .page { width: calc(100% - 24px); }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .panel-heading { flex-direction: column; }
      #graph { height: 520px; }
    }
  </style>
</head>
<body>
  <main class="page">
    <header>
      <div class="eyebrow">Diverto migration · network observation</div>
      <h1>Observed server port flows</h1>
      <p class="intro">Generated from the <code>tcpdump</code> network-services CSVs. Each arrow goes from the client to the destination service port that must be reachable. Drag nodes to rearrange the full map; that layout is remembered in this browser (filtered views are re-arranged automatically).</p>
    </header>

    <section class="summary" id="summary" aria-label="Capture summary"></section>
    <aside class="notice" id="notice"></aside>

    <section class="panel" aria-labelledby="graph-title">
      <div class="panel-heading">
        <div>
          <h2 id="graph-title">Server and endpoint map</h2>
          <p>Arrow labels list destination ports. Dashed orange arrows are inbound connections to a monitored server.</p>
        </div>
        <div class="legend" aria-label="Legend">
          <span><i class="dot" style="background:var(--server)"></i>Monitored server</span>
          <span><i class="dot" style="background:var(--private)"></i>Private peer</span>
          <span><i class="dot" style="background:var(--public)"></i>Public peer</span>
          <span><i class="dot" style="background:var(--multicast)"></i>Multicast</span>
          <span><i class="dot" style="background:var(--inbound)"></i>Inbound</span>
          <span><i class="dot" style="background:#0b1320;border:1.5px solid #85e0a3"></i>Top-left: local relations</span>
          <span><i class="dot" style="background:var(--text)"></i>Top-right: all relations</span>
        </div>
      </div>
      <div class="controls">
        <label for="server-filter">Server</label>
        <select id="server-filter"><option value="">All monitored servers</option></select>
        <input id="search" type="search" placeholder="Search host, IP, service or port…" aria-label="Search flows">
        <label><input id="hide-public" type="checkbox"> Hide public peers</label>
        <button id="fit" type="button">Fit to view</button>
        <button id="reset" type="button">Reset layout</button>
      </div>
      <div id="graph-scroll">
      <svg id="graph" role="img" aria-label="Network diagram of observed port flows">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#6685ac"/></marker>
          <marker id="arrow-in" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#ffb86b"/></marker>
        </defs>
        <g id="viewport"><g id="links"></g><g id="nodes"></g></g>
      </svg>
      </div>
      <div class="hint">Drag a node to move it · drag the background to pan · Ctrl + scroll to zoom · click a node to highlight its flows · “Fit to view” re-arranges the visible nodes to fill the screen.</div>
      <div class="table-meta">
        <span id="table-meta" aria-live="polite"></span>
        <button id="clear-columns" type="button" hidden>Clear column filters</button>
      </div>
      <div class="table-scroll">
        <table>
          <thead>
            <tr><th>Source</th><th>Destination</th><th>Protocol / port</th><th>Service</th><th class="num">Packets</th><th>Seen in capture</th></tr>
            <tr class="filter-row">
              <th><input type="search" data-col="source" placeholder="Filter…" aria-label="Filter by source"></th>
              <th><input type="search" data-col="destination" placeholder="Filter…" aria-label="Filter by destination"></th>
              <th><input type="search" data-col="port" placeholder="e.g. 53 or =53" aria-label="Filter by protocol or port"></th>
              <th><input type="search" data-col="service" placeholder="Filter…" aria-label="Filter by service"></th>
              <th><input type="search" data-col="packets" placeholder="e.g. >100" aria-label="Filter by packets"></th>
              <th><input type="search" data-col="observers" placeholder="Filter…" aria-label="Filter by capture"></th>
            </tr>
          </thead>
          <tbody id="flow-rows"></tbody>
        </table>
      </div>
    </section>
    <p class="footnote" id="footnote"></p>
  </main>

  <script>
    const DATA = __DATA__;
    const NODE_W = 160, NODE_H = 40, STORAGE_KEY = "diverto-ports-map-positions";
    const COLORS = { server: "#61d5e8", private: "#82aaff", public: "#c792ea", multicast: "#85e0a3", unknown: "#9aacc4" };
    const SVG_NS = "http://www.w3.org/2000/svg";

    const nodesById = new Map(DATA.nodes.map((n) => [n.id, n]));
    const isServer = (id) => nodesById.get(id)?.kind === "server";
    const nameOf = (id) => nodesById.get(id)?.label ?? id;
    const svg = document.getElementById("graph");
    const viewport = document.getElementById("viewport");
    const linksLayer = document.getElementById("links");
    const nodesLayer = document.getElementById("nodes");
    const filter = document.getElementById("server-filter");
    const search = document.getElementById("search");
    const hidePublic = document.getElementById("hide-public");

    const view = { x: 0, y: 0, k: 1 };
    const positions = new Map();
    let selectedId = null;
    let current = { links: [], nodeEls: new Map() };

    function el(tag, attrs = {}, parent) {
      const node = document.createElementNS(SVG_NS, tag);
      for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
      if (parent) parent.append(node);
      return node;
    }

    // ---------- summary ----------
    (function renderSummary() {
      const s = DATA.stats;
      const protocolList = Object.entries(s.protocols).map(([p, n]) => `${n} ${p}`).join(" · ") || "none";
      const stats = [
        [s.servers, "monitored servers (CSV files)"],
        [s.flows, `unique port flows (${protocolList})`],
        [s.peers, "other endpoints observed"],
        [s.serverToServer, "flows between monitored servers"],
      ];
      document.getElementById("summary").innerHTML = "";
      for (const [value, label] of stats) {
        const div = document.createElement("div");
        div.className = "stat";
        const strong = document.createElement("strong");
        strong.textContent = value;
        const span = document.createElement("span");
        span.textContent = label;
        div.append(strong, span);
        document.getElementById("summary").append(div);
      }
      const raw = Object.entries(s.rawProtocols).map(([p, n]) => `${p}: ${n}`).join(", ");
      const notice = document.getElementById("notice");
      notice.innerHTML = "<b>Capture evidence, not a firewall policy.</b> ";
      notice.append(`Raw rows by protocol — ${raw}. Reply traffic is removed (stateful firewalls allow it automatically) and ICMP is not shown. ` +
        (s.serverToServer === 0 ? "No direct traffic between the monitored servers was captured. " : "") +
        "Validate each flow with the application owners before opening ports.");
      document.getElementById("footnote").textContent =
        `Generated ${DATA.generatedAt} from ${DATA.files.length} file(s): ${DATA.files.join(", ")}.`;
      for (const node of DATA.nodes.filter((n) => n.kind === "server")) {
        const option = document.createElement("option");
        option.value = node.id;
        option.textContent = `${node.label} (${node.ip})`;
        filter.append(option);
      }
    })();

    // ---------- layout ----------
    function defaultLayout() {
      positions.clear();
      const servers = DATA.nodes.filter((n) => n.kind === "server");
      const peers = DATA.nodes.filter((n) => n.kind !== "server");
      const gap = 60;
      const height = Math.max(servers.length, peers.length, 1) * gap;
      servers.forEach((n, i) => positions.set(n.id, { x: 120, y: (i + 0.5) * height / servers.length }));
      peers.forEach((n, i) => positions.set(n.id, { x: 760, y: (i + 0.5) * height / peers.length }));
    }

    function savedLayout() {
      try {
        const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
        return saved && typeof saved === "object" && Object.keys(saved).length ? saved : null;
      } catch { return null; }
    }

    function loadLayout() {
      defaultLayout();
      for (const [id, pos] of Object.entries(savedLayout() || {})) {
        if (positions.has(id) && Number.isFinite(pos.x) && Number.isFinite(pos.y)) positions.set(id, pos);
      }
    }

    function saveLayout() {
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(Object.fromEntries(positions))); } catch { /* storage unavailable */ }
    }

    // ---------- filtering ----------
    const columnInputs = [...document.querySelectorAll(".filter-row input")];
    const columnValues = {
      source: (f) => [f.src, nameOf(f.src)],
      destination: (f) => [f.dst, nameOf(f.dst)],
      port: (f) => [String(f.port), f.proto, `${f.proto} / ${f.port}`, `${f.proto}/${f.port}`],
      service: (f) => [f.service ?? "unclassified"],
      packets: (f) => [String(f.packets)],
      observers: (f) => f.observers,
    };

    // "abc" = contains, "=abc" = exact, "!abc" = does not contain, ">n" / "<n" / ">=n" / "<=n" = numeric.
    function matchColumn(values, raw) {
      const term = raw.trim().toLowerCase();
      if (!term) return true;
      const numeric = term.match(/^(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)$/);
      if (numeric) {
        const limit = Number(numeric[2]);
        return values.some((v) => {
          const n = Number(v);
          if (!Number.isFinite(n)) return false;
          return { ">": n > limit, "<": n < limit, ">=": n >= limit, "<=": n <= limit }[numeric[1]];
        });
      }
      const lower = values.map((v) => String(v).toLowerCase());
      if (term.startsWith("=")) return lower.includes(term.slice(1).trim());
      if (term.startsWith("!")) {
        const needle = term.slice(1).trim();
        return !needle || !lower.some((v) => v.includes(needle));
      }
      return lower.some((v) => v.includes(term));
    }

    function hasColumnFilters() {
      return columnInputs.some((input) => input.value.trim());
    }

    function filteredFlows() {
      const server = filter.value;
      const query = search.value.trim().toLowerCase();
      const active = columnInputs.filter((input) => input.value.trim());
      return DATA.flows.filter((f) => {
        if (server && f.src !== server && f.dst !== server) return false;
        if (hidePublic.checked && [f.src, f.dst].some((id) => nodesById.get(id)?.kind === "public")) return false;
        if (!active.every((input) => matchColumn(columnValues[input.dataset.col](f), input.value))) return false;
        if (!query) return true;
        const text = `${f.src} ${nameOf(f.src)} ${f.dst} ${nameOf(f.dst)} ${f.proto} ${f.port} ${f.service ?? "unclassified"}`.toLowerCase();
        return text.includes(query);
      });
    }

    // ---------- graph ----------
    function renderGraph(flows) {
      linksLayer.replaceChildren();
      nodesLayer.replaceChildren();
      const visible = new Set();
      if (!filter.value && !search.value.trim() && !hasColumnFilters()) DATA.nodes.filter((n) => n.kind === "server").forEach((n) => visible.add(n.id));
      const grouped = new Map();
      for (const f of flows) {
        visible.add(f.src); visible.add(f.dst);
        const key = `${f.src}|${f.dst}`;
        if (!grouped.has(key)) grouped.set(key, { src: f.src, dst: f.dst, flows: [] });
        grouped.get(key).flows.push(f);
      }

      const links = [];
      for (const link of grouped.values()) {
        link.inbound = isServer(link.dst) && !isServer(link.src);
        link.curved = grouped.has(`${link.dst}|${link.src}`);
        const ports = [...new Set(link.flows.map((f) => `${f.proto} ${f.port}`))];
        const text = ports.length > 3 ? `${ports.slice(0, 3).join(", ")} +${ports.length - 3}` : ports.join(", ");
        const g = el("g", { class: `link${link.inbound ? " inbound" : ""}` }, linksLayer);
        el("title", {}, g).textContent = `${nameOf(link.src)} → ${nameOf(link.dst)}\n` +
          link.flows.map((f) => `${f.proto}/${f.port} ${f.service ?? "unclassified"} (${f.packets} pkts)`).join("\n");
        link.path = el("path", { "marker-end": `url(#${link.inbound ? "arrow-in" : "arrow"})` }, g);
        link.rect = el("rect", { rx: 7, height: 16, width: text.length * 6 + 12 }, g);
        link.label = el("text", {}, g);
        link.label.textContent = text;
        link.el = g;
        links.push(link);
      }

      const isExternal = (id) => nodesById.get(id)?.kind === "public";
      const relations = new Map();
      const relationsOf = (id) => {
        if (!relations.has(id)) relations.set(id, { peers: new Set(), out: new Set(), in: new Set(), local: new Set() });
        return relations.get(id);
      };
      for (const link of links) {
        relationsOf(link.src).peers.add(link.dst); relationsOf(link.src).out.add(link.dst);
        relationsOf(link.dst).peers.add(link.src); relationsOf(link.dst).in.add(link.src);
        if (!isExternal(link.dst)) relationsOf(link.src).local.add(link.dst);
        if (!isExternal(link.src)) relationsOf(link.dst).local.add(link.src);
      }

      const nodeEls = new Map();
      for (const id of [...visible].sort((a, b) => (isServer(b) - isServer(a)))) {
        const node = nodesById.get(id) ?? { id, label: id, ip: id, kind: "unknown" };
        if (!positions.has(id)) positions.set(id, { x: 760, y: 0 });
        const g = el("g", { class: "node", "data-id": id, tabindex: 0 }, nodesLayer);
        el("title", {}, g).textContent = node.kind === "server"
          ? `${node.label} (${node.ip})\nSource: ${node.file}`
          : `${node.ip} [${node.kind}]\nReceives: ${(node.services || []).join(", ") || "-"}`;
        el("rect", { x: -NODE_W / 2, y: -NODE_H / 2, width: NODE_W, height: NODE_H, rx: 9, stroke: COLORS[node.kind] ?? COLORS.unknown }, g);
        el("text", { class: "title", y: node.kind === "server" ? -3 : -3 }, g).textContent = node.label;
        el("text", { class: "sub", y: 11 }, g).textContent = node.kind === "server"
          ? node.ip
          : (node.services || []).join(", ").slice(0, 28) || node.kind;
        const rel = relations.get(id) ?? { peers: new Set(), out: new Set(), in: new Set(), local: new Set() };
        const localCount = String(rel.local.size);
        const localBadge = el("g", { class: "badge local", transform: `translate(${-NODE_W / 2 + 4},${-NODE_H / 2 + 2})` }, g);
        el("title", {}, localBadge).textContent = `${rel.local.size} local relation(s) (servers and private IPs, external IPs excluded)`;
        el("rect", { x: -(localCount.length * 6 + 10) / 2, y: -8, width: localCount.length * 6 + 10, height: 16, rx: 8 }, localBadge);
        el("text", { y: 3.5 }, localBadge).textContent = localCount;
        const count = String(rel.peers.size);
        const badge = el("g", { class: "badge", transform: `translate(${NODE_W / 2 - 4},${-NODE_H / 2 + 2})` }, g);
        el("title", {}, badge).textContent = `${rel.peers.size} relation(s): ${rel.out.size} outgoing, ${rel.in.size} incoming`;
        el("rect", { x: -(count.length * 6 + 10) / 2, y: -8, width: count.length * 6 + 10, height: 16, rx: 8, style: `fill:${COLORS[node.kind] ?? COLORS.unknown}` }, badge);
        el("text", { y: 3.5 }, badge).textContent = count;
        nodeEls.set(id, g);
      }
      current = { links, nodeEls };
      updateGeometry();
      applySelection();
    }

    function clipToBox(center, toward) {
      const dx = toward.x - center.x, dy = toward.y - center.y;
      if (!dx && !dy) return { ...center };
      const t = Math.min(dx ? (NODE_W / 2 + 4) / Math.abs(dx) : Infinity, dy ? (NODE_H / 2 + 4) / Math.abs(dy) : Infinity);
      return { x: center.x + dx * Math.min(t, 1), y: center.y + dy * Math.min(t, 1) };
    }

    function updateGeometry(onlyId) {
      for (const [id, g] of current.nodeEls) {
        if (onlyId && id !== onlyId) continue;
        const p = positions.get(id);
        g.setAttribute("transform", `translate(${p.x},${p.y})`);
      }
      for (const link of current.links) {
        if (onlyId && link.src !== onlyId && link.dst !== onlyId) continue;
        const a = positions.get(link.src), b = positions.get(link.dst);
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
        const bend = link.curved ? 34 : 0;
        const c = { x: mx - (b.y - a.y) / len * bend, y: my + (b.x - a.x) / len * bend };
        const start = clipToBox(a, c), end = clipToBox(b, c);
        link.path.setAttribute("d", `M${start.x},${start.y} Q${c.x},${c.y} ${end.x},${end.y}`);
        // Label near the source end: labels then spread out per server instead of piling up mid-graph.
        const t = 0.3, u = 1 - t;
        const lx = u * u * start.x + 2 * u * t * c.x + t * t * end.x;
        const ly = u * u * start.y + 2 * u * t * c.y + t * t * end.y;
        const w = Number(link.rect.getAttribute("width"));
        link.rect.setAttribute("x", lx - w / 2);
        link.rect.setAttribute("y", ly - 8);
        link.label.setAttribute("x", lx);
        link.label.setAttribute("y", ly);
      }
    }

    function applySelection() {
      const neighbours = new Set(selectedId ? [selectedId] : []);
      for (const link of current.links) {
        const touches = selectedId && (link.src === selectedId || link.dst === selectedId);
        if (touches) { neighbours.add(link.src); neighbours.add(link.dst); }
        link.el.classList.toggle("dim", Boolean(selectedId) && !touches);
        link.el.classList.toggle("hl", Boolean(touches));
      }
      for (const [id, g] of current.nodeEls) {
        g.classList.toggle("dim", Boolean(selectedId) && !neighbours.has(id));
        g.classList.toggle("selected", id === selectedId);
      }
    }

    function applyView() {
      viewport.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.k})`);
    }

    function fitView() {
      svg.style.height = "";
      svg.style.width = "";
      const ids = [...current.nodeEls.keys()];
      if (!ids.length) return;
      const xs = ids.map((id) => positions.get(id).x), ys = ids.map((id) => positions.get(id).y);
      const minX = Math.min(...xs) - NODE_W / 2 - 30, maxX = Math.max(...xs) + NODE_W / 2 + 30;
      const minY = Math.min(...ys) - NODE_H / 2 - 30, maxY = Math.max(...ys) + NODE_H / 2 + 30;
      const { width, height } = svg.getBoundingClientRect();
      view.k = Math.min(1.2, width / (maxX - minX), height / (maxY - minY));
      view.x = (width - (maxX - minX) * view.k) / 2 - minX * view.k;
      view.y = (height - (maxY - minY) * view.k) / 2 - minY * view.k;
      applyView();
    }

    // Lays out the visible nodes left to right in layers that follow the arrows: whoever
    // initiates a connection sits left of the node it calls, so incoming peers end up on
    // the left of the receiver and outgoing destinations on the right of the sender.
    // Large layers wrap into several sub-columns. When everything fits, the graph keeps the
    // screen height; otherwise it grows taller at a readable zoom and the page scrolls.
    const ROW_H = NODE_H + 20, COL_W = NODE_W + 44, MARGIN = 24, MIN_GAP = 120, MAX_GAP = 320, READABLE_ZOOM = 0.8;

    function computeLayers(ids, rank) {
      const succ = new Map(ids.map((id) => [id, new Set()]));
      const pred = new Map(ids.map((id) => [id, new Set()]));
      for (const l of current.links) {
        if (l.src === l.dst || !succ.has(l.src) || !succ.has(l.dst)) continue;
        succ.get(l.src).add(l.dst);
        pred.get(l.dst).add(l.src);
      }
      // Mutual or circular calls cannot all point right: drop DFS back edges to get a DAG.
      const state = new Map(), topo = [];
      const dagSucc = new Map(ids.map((id) => [id, []]));
      const dagPredCount = new Map(ids.map((id) => [id, 0]));
      const visit = (id) => {
        state.set(id, 1);
        for (const next of succ.get(id)) {
          if (state.get(next) === 1) continue;
          dagSucc.get(id).push(next);
          dagPredCount.set(next, dagPredCount.get(next) + 1);
          if (!state.has(next)) visit(next);
        }
        state.set(id, 2);
        topo.push(id);
      };
      [...ids]
        .sort((a, b) => pred.get(a).size - pred.get(b).size || rank(a) - rank(b))
        .forEach((id) => { if (!state.has(id)) visit(id); });
      topo.reverse();

      const layer = new Map(ids.map((id) => [id, 0]));
      for (const id of topo) {
        for (const next of dagSucc.get(id)) layer.set(next, Math.max(layer.get(next), layer.get(id) + 1));
      }
      // Pure callers go right next to the leftmost node they call instead of the far left.
      for (const id of ids) {
        if (dagPredCount.get(id) === 0 && dagSucc.get(id).length) {
          layer.set(id, Math.min(...dagSucc.get(id).map((n) => layer.get(n))) - 1);
        }
      }
      const used = [...new Set(layer.values())].sort((a, b) => a - b);
      const layers = used.map(() => []);
      for (const id of ids) layers[used.indexOf(layer.get(id))].push(id);
      for (const list of layers) list.sort((a, b) => (isServer(b) - isServer(a)) || rank(a) - rank(b));
      return layers;
    }

    function arrangeVisible() {
      svg.style.height = "";
      svg.style.width = "";
      const ids = [...current.nodeEls.keys()];
      if (!ids.length) { view.x = 0; view.y = 0; view.k = 1; applyView(); return; }
      const order = new Map(DATA.nodes.map((n, i) => [n.id, i]));
      const rank = (id) => order.get(id) ?? Infinity;
      const layers = computeLayers(ids, rank);
      const L = layers.length;
      let { width, height } = svg.getBoundingClientRect();
      const layerW = (cols) => cols.reduce((sum, c) => sum + (c - 1) * COL_W + NODE_W, 0);

      let k, worldH, cols, fitted = false;
      for (k = 1; k >= READABLE_ZOOM - 1e-9; k -= 0.05) {
        worldH = height / k;
        const rows = Math.max(1, Math.floor((worldH - 2 * MARGIN) / ROW_H));
        cols = layers.map((list) => Math.ceil(list.length / rows));
        if (layerW(cols) + (L - 1) * MIN_GAP + 2 * MARGIN <= width / k) { fitted = true; break; }
      }
      if (!fitted) {
        // Too many nodes for one screen: stay at a readable zoom. Fill the screen width first;
        // if the graph would still be very tall, widen it (up to ~2 screens, scrolling sideways)
        // rather than shrinking the boxes, then let it grow downwards.
        k = READABLE_ZOOM;
        const screenW = width;
        const targetRows = Math.max(1, Math.floor((1.5 * height / k - 2 * MARGIN) / ROW_H));
        const neededW = () => (layerW(cols) + (L - 1) * MIN_GAP + 2 * MARGIN) * k;
        const maxRows = () => Math.max(...layers.map((list, i) => Math.ceil(list.length / cols[i])));
        const addColumn = (limitW) => {
          let worst = -1, worstRows = 1;
          layers.forEach((list, i) => {
            const r = Math.ceil(list.length / cols[i]);
            if (r > worstRows) { worst = i; worstRows = r; }
          });
          if (worst < 0) return false;
          cols[worst]++;
          if (neededW() > limitW) { cols[worst]--; return false; }
          return true;
        };
        cols = layers.map(() => 1);
        while (addColumn(screenW));
        while (maxRows() > targetRows && addColumn(Math.max(2 * screenW, neededW())));
        width = Math.max(screenW, Math.ceil(neededW()));
        if (width > screenW) svg.style.width = `${width}px`;
        const rows = maxRows();
        worldH = rows * ROW_H + 2 * MARGIN;
        svg.style.height = `${Math.max(height, worldH * k)}px`;
        worldH = Math.max(worldH, height / k);
      }
      const worldW = width / k;
      const gap = L > 1 ? Math.max(MIN_GAP, Math.min(MAX_GAP, (worldW - 2 * MARGIN - layerW(cols)) / (L - 1))) : 0;
      const usedW = layerW(cols) + (L - 1) * gap;
      const offsetX = Math.max(MARGIN, (worldW - usedW) / 2);

      // Row-major placement inside a layer, so a layer's order maps to increasing y.
      const placeAll = () => {
        let x = offsetX + NODE_W / 2;
        layers.forEach((list, i) => {
          const rows = Math.ceil(list.length / cols[i]);
          const top = (worldH - rows * ROW_H) / 2;
          list.forEach((id, j) => {
            const row = Math.floor(j / cols[i]), col = j % cols[i];
            const inRow = Math.min(cols[i], list.length - row * cols[i]);
            const shift = (cols[i] - inRow) * COL_W / 2;
            positions.set(id, { x: x + shift + col * COL_W, y: top + (row + 0.5) * ROW_H });
          });
          x += (cols[i] - 1) * COL_W + NODE_W + gap;
        });
      };

      // Barycentre sweeps: order each layer by the average height of its neighbours.
      const neighbours = new Map(ids.map((id) => [id, []]));
      for (const l of current.links) {
        if (l.src === l.dst || !neighbours.has(l.src) || !neighbours.has(l.dst)) continue;
        neighbours.get(l.src).push(l.dst);
        neighbours.get(l.dst).push(l.src);
      }
      placeAll();
      for (let pass = 0; pass < 4; pass++) {
        for (const list of layers) {
          const index = new Map(list.map((id, i) => [id, i]));
          const score = new Map(list.map((id) => {
            const ns = neighbours.get(id);
            return [id, ns.length ? ns.reduce((sum, n) => sum + positions.get(n).y, 0) / ns.length : positions.get(id).y];
          }));
          list.sort((a, b) => score.get(a) - score.get(b) || index.get(a) - index.get(b));
        }
        placeAll();
      }

      view.x = 0; view.y = 0; view.k = k;
      updateGeometry();
      applyView();
    }

    function hasAnyFilter() {
      return Boolean(filter.value || search.value.trim() || hasColumnFilters() || hidePublic.checked);
    }

    // Unfiltered view: reuse the layout the user dragged into place, if any.
    // Filtered views always get a fresh readable arrangement of what is left.
    function placeView() {
      const saved = !hasAnyFilter() && savedLayout();
      if (saved) {
        for (const [id, pos] of Object.entries(saved)) {
          if (positions.has(id) && Number.isFinite(pos.x) && Number.isFinite(pos.y)) positions.set(id, pos);
        }
        updateGeometry();
        fitView();
      } else {
        arrangeVisible();
      }
    }

    // ---------- interaction: drag nodes, pan, zoom ----------
    function toWorld(event) {
      const r = svg.getBoundingClientRect();
      return { x: (event.clientX - r.left - view.x) / view.k, y: (event.clientY - r.top - view.y) / view.k };
    }

    let drag = null;
    svg.addEventListener("dragstart", (event) => event.preventDefault());
    svg.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      // Stops native text-selection/drag gestures that would cancel the pointer stream.
      event.preventDefault();
      const nodeEl = event.target.closest(".node");
      const p = toWorld(event);
      if (nodeEl) {
        const id = nodeEl.dataset.id;
        const pos = positions.get(id);
        drag = { type: "node", id, offX: p.x - pos.x, offY: p.y - pos.y, sx: event.clientX, sy: event.clientY, moved: false };
        nodesLayer.append(nodeEl); // bring to front
      } else {
        drag = { type: "pan", sx: event.clientX, sy: event.clientY, vx: view.x, vy: view.y, moved: false };
        svg.classList.add("panning");
      }
      svg.setPointerCapture(event.pointerId);
    });

    svg.addEventListener("pointermove", (event) => {
      if (!drag) return;
      if (Math.hypot(event.clientX - drag.sx, event.clientY - drag.sy) > 3) drag.moved = true;
      if (drag.type === "node") {
        const p = toWorld(event);
        positions.set(drag.id, { x: p.x - drag.offX, y: p.y - drag.offY });
        updateGeometry(drag.id);
      } else {
        view.x = drag.vx + event.clientX - drag.sx;
        view.y = drag.vy + event.clientY - drag.sy;
        applyView();
      }
    });

    function endDrag() {
      if (!drag) return;
      if (drag.type === "node") {
        if (drag.moved) { if (!hasAnyFilter()) saveLayout(); }
        else { selectedId = selectedId === drag.id ? null : drag.id; applySelection(); }
      } else if (!drag.moved && selectedId) {
        selectedId = null; applySelection();
      }
      svg.classList.remove("panning");
      drag = null;
    }
    svg.addEventListener("pointerup", endDrag);
    svg.addEventListener("pointercancel", endDrag);

    svg.addEventListener("wheel", (event) => {
      // Plain wheel scrolls the page (the graph can be taller than the screen); Ctrl/⌘ + wheel zooms.
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      const r = svg.getBoundingClientRect();
      const mx = event.clientX - r.left, my = event.clientY - r.top;
      const k = Math.min(4, Math.max(0.2, view.k * Math.exp(-event.deltaY * 0.0015)));
      view.x = mx - (mx - view.x) * (k / view.k);
      view.y = my - (my - view.y) * (k / view.k);
      view.k = k;
      applyView();
    }, { passive: false });

    nodesLayer.addEventListener("keydown", (event) => {
      const nodeEl = event.target.closest(".node");
      if (!nodeEl || (event.key !== "Enter" && event.key !== " ")) return;
      event.preventDefault();
      selectedId = selectedId === nodeEl.dataset.id ? null : nodeEl.dataset.id;
      applySelection();
    });

    // ---------- table ----------
    function cell(row, main, sub, className) {
      const td = document.createElement("td");
      if (className) td.className = className;
      const span = document.createElement("span");
      span.className = sub !== undefined ? "name" : "";
      span.textContent = main;
      td.append(span);
      if (sub !== undefined) {
        const small = document.createElement("span");
        small.className = "subtle";
        small.textContent = sub;
        td.append(small);
      }
      row.append(td);
      return td;
    }

    function renderTable(flows) {
      const body = document.getElementById("flow-rows");
      body.replaceChildren();
      document.getElementById("table-meta").textContent = `${flows.length} flow${flows.length === 1 ? "" : "s"} shown.`;
      if (!flows.length) {
        const row = body.insertRow();
        const td = row.insertCell();
        td.colSpan = 6; td.className = "none"; td.textContent = "No matching port flows.";
        return;
      }
      for (const f of flows) {
        const row = body.insertRow();
        cell(row, nameOf(f.src), isServer(f.src) ? f.src : nodesById.get(f.src)?.kind ?? "");
        cell(row, nameOf(f.dst), isServer(f.dst) ? f.dst : nodesById.get(f.dst)?.kind ?? "");
        const port = cell(row, "");
        port.replaceChildren();
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = `${f.proto} / ${f.port}`;
        port.append(badge);
        cell(row, f.service ?? "Unclassified");
        cell(row, f.packets.toLocaleString(), undefined, "num");
        cell(row, f.observers.join(", "));
      }
    }

    function render(relayout = false) {
      const flows = filteredFlows();
      if (selectedId && !flows.some((f) => f.src === selectedId || f.dst === selectedId)) selectedId = null;
      renderGraph(flows);
      renderTable(flows);
      if (relayout) placeView();
    }

    let relayoutTimer = null;
    function renderDebounced() {
      render(false);
      clearTimeout(relayoutTimer);
      relayoutTimer = setTimeout(placeView, 300);
    }

    filter.addEventListener("change", () => render(true));
    search.addEventListener("input", renderDebounced);
    const clearColumns = document.getElementById("clear-columns");
    function onColumnFilter() {
      for (const input of columnInputs) input.classList.toggle("active", Boolean(input.value.trim()));
      clearColumns.hidden = !hasColumnFilters();
      renderDebounced();
    }
    for (const input of columnInputs) input.addEventListener("input", onColumnFilter);
    clearColumns.addEventListener("click", () => {
      for (const input of columnInputs) input.value = "";
      onColumnFilter();
    });
    hidePublic.addEventListener("change", () => render(true));
    document.getElementById("fit").addEventListener("click", arrangeVisible);
    document.getElementById("reset").addEventListener("click", () => {
      try { localStorage.removeItem(STORAGE_KEY); } catch { /* storage unavailable */ }
      selectedId = null;
      applySelection();
      arrangeVisible();
    });

    loadLayout();
    render(true);
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="folder with *_network_services.csv files")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="HTML file to write")
    args = parser.parse_args()

    if not args.input.is_dir():
        parser.error(f"input folder not found: {args.input}")
    captures = load_captures(args.input)
    if not captures:
        parser.error(f"no *_network_services.csv files found in {args.input}")

    flows = merge_flows(captures)
    data = build_data(captures, flows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_html(data), encoding="utf-8")

    stats = data["stats"]
    print(f"Read {len(captures)} CSV files ({stats['rows']} rows)")
    print(f"{stats['flows']} flows, {stats['peers']} other endpoints, {stats['serverToServer']} server-to-server flows")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
