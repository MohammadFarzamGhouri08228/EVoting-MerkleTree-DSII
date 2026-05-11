#pragma once
// =============================================================================
// voting_system.hpp  —  Central controller / application logic
//
// VotingSystem wires together VoterRegistry, MerkleTree, and Ballot.
// It is the only class that main.cpp needs to touch.
//
// Merkle Tree operations used:
//   cast_vote()         → tree_.insert()      (adds one leaf node)
//   build_tree()        → tree_.build()       (full O(n) construction)
//   tamper_vote()       → tree_.update()      (O(log n) parent-pointer walk)
//   invalidate_ballot() → tree_.delete_leaf() (O(log n) parent-pointer walk)
//   verify_vote()       → tree_.generate_proof() + print_proof_path()
// =============================================================================
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <random>
#include <chrono>
#include <fstream>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <cctype>
#include "header/ballot.hpp"
#include "header/voter_registry.hpp"
#include "header/merkle_tree.hpp"
#include "header/live_visualization_server.hpp"

class VotingSystem {

    VoterRegistry       registry_;
    MerkleTree          tree_;
    std::vector<Ballot> ballots_;

    // Published election root snapshot: updated on build_tree(), each live
    // cast_vote() insert, invalidate_ballot(), and delete_ballot().
    // Intentionally NOT updated by tamper_vote() — voters who saved the old
    // root see a proof MISMATCH until officials publish a new snapshot (e.g.
    // by running build_tree() again, which re-commits to current ballots).
    std::string         last_built_root_;
    bool                tree_built_ = false;
    mutable std::mutex  state_mutex_;
    LiveVisualizationServer vis_server_;
    bool                dataset_loaded_ = false;
    std::string         dataset_source_ = "";
    bool                changed_after_dataset_load_ = false;

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    static std::mt19937& rng() {
        static std::mt19937 gen(
            static_cast<unsigned>(
                std::chrono::steady_clock::now().time_since_epoch().count()
            )
        );
        return gen;
    }

    static std::string make_salt() {
        std::uniform_int_distribution<uint32_t> dist;
        std::ostringstream oss;
        oss << std::hex << std::setfill('0')
            << std::setw(8) << dist(rng())
            << std::setw(8) << dist(rng());
        return oss.str();
    }

    static std::string make_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                       now.time_since_epoch()).count();
        return std::to_string(sec);
    }

    static std::string make_receipt_id(const std::string& voter_id) {
        std::string seed = voter_id + make_salt() + make_timestamp();
        return "RCP-" + sha256(seed).substr(0, 12);
    }

    static std::string short_h(const std::string& h) {
        return (h.size() > 16) ? h.substr(0, 16) + "..." : h;
    }

    static std::string json_escape(const std::string& s) {
        std::ostringstream out;
        for (char ch : s) {
            switch (ch) {
                case '\\': out << "\\\\"; break;
                case '"':  out << "\\\""; break;
                case '\b': out << "\\b"; break;
                case '\f': out << "\\f"; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(ch) < 0x20) {
                        out << "\\u"
                            << std::hex << std::setw(4) << std::setfill('0')
                            << static_cast<int>(static_cast<unsigned char>(ch))
                            << std::dec << std::setfill(' ');
                    } else {
                        out << ch;
                    }
            }
        }
        return out.str();
    }

    static std::string url_decode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size()) {
                int value = 0;
                std::istringstream iss(s.substr(i + 1, 2));
                if (iss >> std::hex >> value) {
                    out += static_cast<char>(value);
                    i += 2;
                    continue;
                }
            }
            if (s[i] == '+') {
                out += ' ';
                continue;
            }
            out += s[i];
        }
        return out;
    }

    static std::string query_param(const std::string& path, const std::string& key) {
        const std::string marker = key + "=";
        const size_t query_pos = path.find('?');
        if (query_pos == std::string::npos) return "";
        size_t pos = path.find(marker, query_pos + 1);
        if (pos == std::string::npos) return "";
        pos += marker.size();
        size_t end = path.find('&', pos);
        return url_decode(path.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
    }

    template <typename Fn>
    static std::string capture_stdout(Fn&& fn) {
        std::ostringstream buffer;
        std::streambuf* old = std::cout.rdbuf(buffer.rdbuf());
        try {
            fn();
            std::cout.rdbuf(old);
        } catch (...) {
            std::cout.rdbuf(old);
            throw;
        }
        return buffer.str();
    }

    static bool open_in_browser(const std::string& filepath) {
#ifdef _WIN32
        std::string command = "start \"\" \"" + filepath + "\"";
#elif __APPLE__
        std::string command = "open \"" + filepath + "\"";
#else
        std::string command = "xdg-open \"" + filepath + "\"";
#endif
        return std::system(command.c_str()) == 0;
    }

    static std::string visualization_html_template(
        const std::string& tree_json,
        const std::string& summary_json) {
        std::ostringstream html;
        html << R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Merkle Tree Visualization</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
  <style>
    :root {
      --bg: #f4efe3;
      --panel: rgba(255, 251, 245, 0.86);
      --panel-strong: rgba(255, 255, 255, 0.74);
      --ink: #17343b;
      --muted: #61767a;
      --edge: #b1c0bb;
      --root: #d39a1f;
      --internal: #6e96a3;
      --leaf: #2a8a61;
      --deleted: #c65b4e;
      --tampered: #d9852d;
      --shadow: 0 24px 60px rgba(23, 52, 59, 0.10);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Trebuchet MS", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #fff2c6 0%, transparent 26%),
        radial-gradient(circle at top right, #d8ecef 0%, transparent 24%),
        linear-gradient(180deg, #f5efe3 0%, #edf5f2 100%);
      min-height: 100vh;
    }
    .shell {
      display: grid;
      grid-template-columns: minmax(360px, 440px) 1fr;
      gap: 22px;
      padding: 22px;
      max-width: 1680px;
      margin: 0 auto;
      min-height: 100vh;
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(23, 52, 59, 0.08);
      border-radius: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }
    .sidebar {
      padding: 22px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      overflow-y: auto;
    }
    h1, h2, p { margin: 0; }
    h1 {
      font-size: 2rem;
      line-height: 1.05;
      letter-spacing: -0.03em;
    }
    h2 {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      color: var(--muted);
    }
    .hero-card {
      padding: 22px;
      border-radius: 24px;
      background:
        linear-gradient(135deg, rgba(255,255,255,0.66), rgba(255,247,229,0.82)),
        linear-gradient(160deg, rgba(211,154,31,0.08), rgba(42,138,97,0.06));
      border: 1px solid rgba(23, 52, 59, 0.08);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.5);
    }
    .hero-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }
    .hero-copy {
      color: var(--muted);
      line-height: 1.55;
      font-size: 0.96rem;
    }
    .hero-badge {
      display: inline-flex;
      align-items: center;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(23, 52, 59, 0.08);
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .section-card {
      border-radius: 22px;
      padding: 18px;
      background: var(--panel-strong);
      border: 1px solid rgba(23, 52, 59, 0.08);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.6);
    }
    .section-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 14px;
    }
    .section-note {
      color: var(--muted);
      font-size: 0.84rem;
      line-height: 1.45;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .stat-card {
      padding: 14px;
      border-radius: 18px;
      background: rgba(255,255,255,0.72);
      border: 1px solid rgba(23, 52, 59, 0.08);
    }
    .stat-label {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }
    .stat-value {
      font-size: 1.55rem;
      font-weight: 800;
      letter-spacing: -0.04em;
    }
    .stat-sub {
      margin-top: 6px;
      color: var(--muted);
      font-size: 0.82rem;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .helper-copy {
      color: var(--muted);
      font-size: 0.9rem;
      line-height: 1.5;
      padding: 14px 16px;
      background: rgba(23, 52, 59, 0.045);
      border-radius: 18px;
    }
    .candidate-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .action-form {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .action-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .action-row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .field label {
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
    }
    .field input, .field select, .field textarea {
      width: 100%;
      border: 1px solid rgba(19, 42, 47, 0.14);
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(255,255,255,0.9);
      color: var(--ink);
      font: inherit;
    }
    .field textarea {
      min-height: 120px;
      resize: vertical;
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.83rem;
    }
    .action-btn.alt { background: #2d8f5a; }
    .action-btn.warn { background: #c84b3f; }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }
    .data-table th, .data-table td {
      text-align: left;
      padding: 8px 6px;
      border-bottom: 1px solid rgba(19, 42, 47, 0.08);
      vertical-align: top;
    }
    .data-table th {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 0.76rem;
      font-weight: 600;
      background: rgba(19, 42, 47, 0.08);
    }
    .candidate-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.76);
      border: 1px solid rgba(23, 52, 59, 0.08);
      padding: 14px 16px;
    }
    .candidate-row strong {
      display: block;
      font-size: 1rem;
    }
    .candidate-row span {
      color: var(--muted);
      font-size: 0.86rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 46px;
      min-height: 46px;
      padding: 6px 12px;
      border-radius: 999px;
      background: linear-gradient(135deg, #183840, #204851);
      color: white;
      font-weight: 700;
      font-size: 1rem;
      box-shadow: 0 10px 24px rgba(23, 52, 59, 0.14);
    }
    .swatch {
      width: 14px;
      height: 14px;
      border-radius: 999px;
      border: 2px solid transparent;
      flex: none;
    }
    .workspace {
      position: relative;
      overflow: hidden;
      min-height: 78vh;
      background:
        radial-gradient(circle at 8% 10%, rgba(211,154,31,0.08), transparent 18%),
        radial-gradient(circle at 100% 0%, rgba(42,138,97,0.10), transparent 22%),
        linear-gradient(180deg, rgba(255,255,255,0.72), rgba(247,251,249,0.82));
    }
    .workspace::before {
      content: "Tree Canvas";
      position: absolute;
      left: 22px;
      top: 20px;
      z-index: 2;
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      font-weight: 700;
    }
    #chart {
      width: 100%;
      height: 100%;
      min-height: 78vh;
    }
    .node-card {
      fill: rgba(255,255,255,0.94);
      stroke-width: 2.5px;
      rx: 14px;
      ry: 14px;
    }
    .node text {
      font-size: 12px;
      fill: var(--ink);
      pointer-events: none;
    }
    .link {
      fill: none;
      stroke: var(--edge);
      stroke-width: 1.6px;
    }
    .link.deleted-link {
      stroke: var(--deleted);
      stroke-dasharray: 5 5;
    }
    .tooltip {
      position: absolute;
      pointer-events: none;
      opacity: 0;
      transform: translateY(6px);
      transition: opacity 140ms ease, transform 140ms ease;
      max-width: 320px;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(19, 42, 47, 0.94);
      color: #f9faf7;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.18);
      font-size: 0.9rem;
      line-height: 1.45;
    }
    .tooltip strong { color: #ffe28a; }
    .toolbar {
      position: absolute;
      right: 18px;
      top: 18px;
      display: flex;
      gap: 10px;
      z-index: 3;
    }
    button {
      border: 0;
      border-radius: 999px;
      background: linear-gradient(135deg, #183840, #204851);
      color: white;
      padding: 11px 16px;
      font-size: 0.9rem;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 10px 24px rgba(23, 52, 59, 0.14);
    }
    button:hover { transform: translateY(-1px); filter: brightness(1.04); }
    .action-form {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .action-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .action-row {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .field {
      display: flex;
      flex-direction: column;
      gap: 7px;
    }
    .field label {
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.10em;
      color: var(--muted);
      font-weight: 700;
    }
    .field input, .field select, .field textarea {
      width: 100%;
      border: 1px solid rgba(23, 52, 59, 0.12);
      border-radius: 16px;
      padding: 11px 13px;
      background: rgba(255,255,255,0.92);
      color: var(--ink);
      font: inherit;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.8);
    }
    .field textarea {
      min-height: 140px;
      resize: vertical;
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.82rem;
      line-height: 1.45;
    }
    .action-btn {
      width: 100%;
    }
    .action-btn.alt {
      background: linear-gradient(135deg, #2a8a61, #3ca476);
    }
    .action-btn.warn {
      background: linear-gradient(135deg, #c65b4e, #db786b);
    }
    .table-shell {
      overflow: hidden;
      border-radius: 18px;
      border: 1px solid rgba(23, 52, 59, 0.08);
      background: rgba(255,255,255,0.72);
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.86rem;
    }
    .data-table th, .data-table td {
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(23, 52, 59, 0.07);
      vertical-align: top;
    }
    .data-table th {
      color: var(--muted);
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.10em;
      background: rgba(23, 52, 59, 0.04);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 0.74rem;
      font-weight: 700;
      background: rgba(23, 52, 59, 0.08);
      white-space: nowrap;
    }
    @media (max-width: 960px) {
      .shell { grid-template-columns: 1fr; }
      .workspace, #chart { min-height: 68vh; }
      .action-grid, .action-row, .stats-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="panel sidebar">
      <div>
        <h2>Interactive View</h2>
        <h1>Merkle Tree Structure</h1>
        <p style="margin-top:8px;color:var(--muted);">Zoom with the mouse wheel, drag to pan, and hover a leaf to inspect ballot metadata.</p>
      </div>
      <div class="helper-copy">
        The <strong>root</strong> is the final fingerprint of the whole election tree. Every ballot rolls upward into it, so if any leaf changes, the root hash changes too.
      </div>
      <div>
        <h2>Data Source</h2>
        <div class="helper-copy">
          <strong id="sourceLabel">-</strong><br>
          <span id="sourceDetail">-</span>
        </div>
      </div>
      <div>
        <div class="stat"><span>Root hash</span><strong id="rootHash">-</strong></div>
        <div class="stat"><span>Total levels</span><strong id="levelCount">-</strong></div>
        <div class="stat"><span>Leaf nodes</span><strong id="leafCount">-</strong></div>
        <div class="stat"><span>Registered voters</span><strong id="registeredVoters">-</strong></div>
        <div class="stat"><span>Valid ballots</span><strong id="validBallots">-</strong></div>
        <div class="stat"><span>Invalidated ballots</span><strong id="invalidBallots">-</strong></div>
      </div>
      <div>
        <h2>Candidates</h2>
        <div id="candidateList" class="candidate-list"></div>
      </div>
      <div>
        <h2>Legend</h2>
        <div class="legend-item"><span class="swatch" style="background:#fff7d6;border-color:var(--root);"></span><span>Root node</span></div>
        <div class="legend-item"><span class="swatch" style="background:#edf5f7;border-color:var(--internal);"></span><span>Internal node</span></div>
        <div class="legend-item"><span class="swatch" style="background:#e8f7ee;border-color:var(--leaf);"></span><span>Valid ballot leaf</span></div>
        <div class="legend-item"><span class="swatch" style="background:#f6e3e1;border-color:var(--deleted);"></span><span>Invalidated or deleted leaf</span></div>
        <div class="legend-item"><span class="swatch" style="background:#fff0df;border-color:var(--tampered);"></span><span>Tampered ballot marker</span></div>
      </div>
    </aside>
    <main class="panel workspace">
      <div class="toolbar">
        <button id="hubBtn" type="button">Back to Hub</button>
        <button id="fitBtn">Fit to Screen</button>
      </div>
      <svg id="chart"></svg>
      <div id="tooltip" class="tooltip"></div>
    </main>
  </div>
  <script>
    const treeData = )HTML";
        html << tree_json;
        html << R"HTML(;
    const summary = )HTML";
        html << summary_json;
        html << R"HTML(;

    const svg = d3.select("#chart");
    const workspace = document.querySelector(".workspace");
    const tooltip = d3.select("#tooltip");
    const width = () => workspace.clientWidth;
    const height = () => Math.max(workspace.clientHeight, 620);
    const root = d3.hierarchy(treeData);
    const levels = root.height + 1;
    const leaves = root.leaves().length;

    document.getElementById("rootHash").textContent = treeData.shortHash;
    document.getElementById("levelCount").textContent = String(levels);
    document.getElementById("leafCount").textContent = String(leaves);
    document.getElementById("registeredVoters").textContent = String(summary.registeredVoters);
    document.getElementById("validBallots").textContent = String(summary.validBallots);
    document.getElementById("invalidBallots").textContent = String(summary.invalidBallots);

    const candidateList = document.getElementById("candidateList");
    summary.candidates.forEach(candidate => {
      const row = document.createElement("div");
      row.className = "candidate-row";
      row.innerHTML = `
        <div>
          <strong>${candidate.name}</strong>
          <span>${candidate.votes} valid vote(s)${candidate.tamperedVotes ? `, ${candidate.tamperedVotes} tampered demo vote(s)` : ""}</span>
        </div>
        <div class="badge">${candidate.votes}</div>
      `;
      candidateList.appendChild(row);
    });

    const treeLayout = d3.tree().nodeSize([120, 120]);
    treeLayout(root);

    const xExtent = d3.extent(root.descendants(), d => d.x);
    const yExtent = d3.extent(root.descendants(), d => d.y);
    const paddingX = 110;
    const paddingY = 90;
    const xOffset = paddingX - xExtent[0];
    const yOffset = paddingY;

    svg.attr("viewBox", [0, 0, width(), height()]);

    const zoomLayer = svg.append("g");
    const content = zoomLayer.append("g");

    let isApplyingClamp = false;
    const zoom = d3.zoom()
      .scaleExtent([0.35, 2.5])
      .on("zoom", event => {
        if (isApplyingClamp) return;
        const clamped = clampTransform(event.transform);
        zoomLayer.attr("transform", clamped);
        if (clamped.x !== event.transform.x || clamped.y !== event.transform.y || clamped.k !== event.transform.k) {
          isApplyingClamp = true;
          svg.call(zoom.transform, clamped);
          isApplyingClamp = false;
        }
      });

    svg.call(zoom);

    const linkGen = d3.linkVertical()
      .x(d => d.x + xOffset)
      .y(d => d.y + yOffset);

    content.selectAll(".link")
      .data(root.links())
      .join("path")
      .attr("class", d => d.target.data.deleted ? "link deleted-link" : "link")
      .attr("d", linkGen);

    const node = content.selectAll(".node")
      .data(root.descendants())
      .join("g")
      .attr("class", "node")
      .attr("transform", d => `translate(${d.x + xOffset},${d.y + yOffset})`);

    const strokeFor = data => {
      if (data.kind === "root") return "var(--root)";
      if (data.deleted) return "var(--deleted)";
      if (data.tampered) return "var(--tampered)";
      if (data.kind === "leaf") return "var(--leaf)";
      return "var(--internal)";
    };

    const fillFor = data => {
      if (data.kind === "root") return "#fff7d6";
      if (data.deleted) return "#f6e3e1";
      if (data.tampered) return "#fff0df";
      if (data.kind === "leaf") return "#e8f7ee";
      return "#edf5f7";
    };

    node.append("rect")
      .attr("class", "node-card")
      .attr("x", -66)
      .attr("y", -22)
      .attr("width", 132)
      .attr("height", 44)
      .attr("fill", d => fillFor(d.data))
      .attr("stroke", d => strokeFor(d.data));

    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", "0.35em")
      .text(d => d.data.name);

    node.on("mousemove", (event, d) => {
      const data = d.data;
      const lines = [
        `<strong>${data.name}</strong>`,
        `Full hash: ${data.hash}`
      ];
      if (typeof data.leafIndex === "number") lines.push(`Leaf index: ${data.leafIndex}`);
      if (data.voterId) lines.push(`Voter ID: ${data.voterId}`);
      if (data.candidate) lines.push(`Candidate: ${data.candidate}`);
      if (data.receiptId) lines.push(`Receipt ID: ${data.receiptId}`);
      if (data.deleted) lines.push(`Status: This ballot was deleted or invalidated.`);
      else if (data.tampered) lines.push(`Status: This ballot is flagged as tampered.`);

      tooltip
        .html(lines.join("<br>"))
        .style("left", `${event.offsetX + 18}px`)
        .style("top", `${event.offsetY + 18}px`)
        .style("opacity", 1)
        .style("transform", "translateY(0)");
    }).on("mouseleave", () => {
      tooltip.style("opacity", 0).style("transform", "translateY(6px)");
    });

    function clampTransform(transform) {
      const bounds = content.node().getBBox();
      const fullWidth = width();
      const fullHeight = height();
      const scale = transform.k;
      const contentWidth = bounds.width * scale;
      const contentHeight = bounds.height * scale;
      const centerX = fullWidth / 2 - (bounds.x + bounds.width / 2) * scale;
      const baseTop = 48 - bounds.y * scale;

      let minX;
      let maxX;
      if (contentWidth < fullWidth - 240) {
        minX = centerX - 90;
        maxX = centerX + 90;
      } else {
        minX = fullWidth - 120 - (bounds.x + bounds.width) * scale;
        maxX = 120 - bounds.x * scale;
      }

      let minY;
      let maxY;
      if (contentHeight < fullHeight - 180) {
        minY = baseTop - 40;
        maxY = baseTop + 120;
      } else {
        minY = fullHeight - 90 - (bounds.y + bounds.height) * scale;
        maxY = 40 - bounds.y * scale;
      }

      return d3.zoomIdentity
        .translate(
          Math.max(minX, Math.min(maxX, transform.x)),
          Math.max(minY, Math.min(maxY, transform.y))
        )
        .scale(scale);
    }

    function fitToScreen() {
      const bounds = content.node().getBBox();
      const fullWidth = width();
      const fullHeight = height();
      const scale = Math.min(
        1.1,
        0.88 / Math.max(bounds.width / fullWidth, bounds.height / fullHeight)
      );
      const tx = (fullWidth - bounds.width * scale) / 2 - bounds.x * scale;
      const ty = 50 - bounds.y * scale;
      svg.transition().duration(500).call(zoom.transform, clampTransform(
        d3.zoomIdentity.translate(tx, ty).scale(scale)
      ));
    }

    document.getElementById("fitBtn").addEventListener("click", fitToScreen);
    document.getElementById("hubBtn").addEventListener("click", () => {
      window.location.href = "/";
    });
    window.addEventListener("resize", () => {
      svg.attr("viewBox", [0, 0, width(), height()]);
      fitToScreen();
    });
    fitToScreen();
  </script>
</body>
</html>)HTML";
        return html.str();
    }

    static std::string visualization_launcher_html_template() {
        return R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Visualization Hub</title>
  <style>
    :root {
      --bg: #f4efe3;
      --ink: #163038;
      --muted: #5c6f73;
      --card: rgba(255, 252, 245, 0.92);
      --line: rgba(22, 48, 56, 0.10);
      --accent: #c78f2b;
      --accent-2: #2f7a5f;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #fff2c7 0%, transparent 30%),
        radial-gradient(circle at top right, #d7eaee 0%, transparent 28%),
        linear-gradient(180deg, #f5efe2 0%, #edf4f2 100%);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .shell {
      width: min(1100px, 100%);
      display: grid;
      gap: 18px;
    }
    .hero, .cards {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: 0 20px 50px rgba(22, 48, 56, 0.10);
      backdrop-filter: blur(10px);
    }
    .hero {
      padding: 28px;
    }
    .hero h1 {
      margin: 0 0 10px;
      font-size: clamp(2rem, 5vw, 3rem);
    }
    .hero p {
      margin: 0;
      max-width: 700px;
      color: var(--muted);
      line-height: 1.6;
      font-size: 1rem;
    }
    .cards {
      padding: 20px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 18px;
    }
    .card {
      border-radius: 20px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.72);
      padding: 22px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-height: 240px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      width: fit-content;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(22, 48, 56, 0.08);
      color: var(--muted);
      font-size: 0.85rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .card h2 {
      margin: 0;
      font-size: 1.45rem;
    }
    .card p {
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
      flex: 1;
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      padding: 11px 16px;
      text-decoration: none;
      color: white;
      font-weight: 600;
      box-shadow: 0 10px 24px rgba(22, 48, 56, 0.15);
    }
    .button.primary { background: linear-gradient(135deg, var(--accent), #e2ae4c); }
    .button.secondary { background: linear-gradient(135deg, var(--accent-2), #3c9a77); }
    .hint {
      font-size: 0.92rem;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <h1>Voting Visualization Hub</h1>
      <p>Use one shared frontend entry point for both visual tracks. Open the classic Merkle Tree explorer for the voting workflow, or jump into the separate Merkle Mountain Range simulation when you want the interval-audit demo.</p>
    </section>
    <section class="cards">
      <article class="card">
        <span class="chip">Current System</span>
        <h2>Merkle Tree View</h2>
        <p>Live view for the existing voting app. It reads the state from the running CLI session on this server, including votes, tampering, invalidation, and receipt-linked leaf metadata.</p>
        <div class="actions">
          <a class="button primary" href="/merkle">Open Merkle Tree</a>
        </div>
      </article>
      <article class="card">
        <span class="chip">Separate Demo</span>
        <h2>MMR View</h2>
        <p>Launchpad for the Merkle Mountain Range simulator. This keeps the MMR experience reachable from the same frontend while the backend remains separate for now.</p>
        <div class="actions">
          <a class="button secondary" href="/mmr">Open MMR View</a>
          <a class="button secondary" href="http://127.0.0.1:9090/" target="_blank" rel="noreferrer">Open 9090 Directly</a>
        </div>
        <div class="hint">The MMR simulator must be running on port 9090 for the embedded view to load.</div>
      </article>
    </section>
  </div>
</body>
</html>)HTML";
    }

    static std::string mmr_bridge_html_template() {
        return R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MMR Visualization</title>
  <style>
    :root {
      --bg: #eff4f1;
      --ink: #133038;
      --muted: #5c6f73;
      --panel: rgba(255, 252, 245, 0.92);
      --line: rgba(19, 48, 56, 0.10);
      --accent: #2f7a5f;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #d8eee2 0%, transparent 28%),
        radial-gradient(circle at top right, #fff2c7 0%, transparent 22%),
        linear-gradient(180deg, #eef4f2 0%, #f6f1e4 100%);
      display: grid;
      grid-template-rows: auto 1fr;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 16px 18px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      box-shadow: 0 12px 30px rgba(19, 48, 56, 0.08);
    }
    .title h1, .title p { margin: 0; }
    .title p {
      color: var(--muted);
      margin-top: 4px;
      font-size: 0.94rem;
    }
    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      padding: 10px 14px;
      text-decoration: none;
      color: white;
      font-weight: 600;
      background: linear-gradient(135deg, var(--accent), #3f9a79);
      box-shadow: 0 10px 22px rgba(19, 48, 56, 0.14);
    }
    .frame-wrap {
      padding: 18px;
      height: calc(100vh - 86px);
    }
    iframe {
      width: 100%;
      height: 100%;
      border: 1px solid var(--line);
      border-radius: 20px;
      background: white;
      box-shadow: 0 20px 40px rgba(19, 48, 56, 0.08);
    }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="title">
      <h1>MMR Visualization</h1>
      <p>This page embeds the separate MMR simulator so both demos stay reachable from the same frontend hub.</p>
    </div>
    <div class="actions">
      <a class="button" href="/">Back to Hub</a>
      <a class="button" href="http://127.0.0.1:9090/" target="_blank" rel="noreferrer">Open 9090 Directly</a>
    </div>
  </div>
  <div class="frame-wrap">
    <iframe src="http://127.0.0.1:9090/" title="MMR Simulation"></iframe>
  </div>
</body>
</html>)HTML";
    }

    static std::string live_visualization_html_template() {
        std::ostringstream html;
        html << R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Merkle Tree Visualization</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
  <style>
    :root {
      --bg: #f6f3ea;
      --panel: rgba(255, 252, 245, 0.9);
      --ink: #132a2f;
      --muted: #5b6c70;
      --edge: #a8b6b2;
      --root: #d9a404;
      --internal: #7ca6b1;
      --leaf: #2d8f5a;
      --deleted: #c84b3f;
      --tampered: #f28c28;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #fff4cd 0%, transparent 28%),
        radial-gradient(circle at top right, #dceef0 0%, transparent 24%),
        linear-gradient(180deg, #f3efe4 0%, #eef4f3 100%);
      min-height: 100vh;
    }
    .shell {
      display: grid;
      grid-template-columns: minmax(260px, 320px) 1fr;
      gap: 18px;
      padding: 18px;
      min-height: 100vh;
    }
    .panel {
      background: var(--panel);
      border: 1px solid rgba(19, 42, 47, 0.08);
      border-radius: 18px;
      box-shadow: 0 18px 45px rgba(19, 42, 47, 0.08);
      backdrop-filter: blur(10px);
    }
    .sidebar {
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      overflow-y: auto;
    }
    h1, h2, p { margin: 0; }
    h1 { font-size: 1.4rem; }
    h2 { font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    .stat {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid rgba(19, 42, 47, 0.08);
      font-size: 0.95rem;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .helper-copy {
      color: var(--muted);
      font-size: 0.92rem;
      line-height: 1.5;
      padding: 12px 14px;
      background: rgba(19, 42, 47, 0.04);
      border-radius: 14px;
    }
    .candidate-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .candidate-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.62);
      border: 1px solid rgba(19, 42, 47, 0.08);
    }
    .candidate-row strong {
      display: block;
      font-size: 0.96rem;
    }
    .candidate-row span {
      color: var(--muted);
      font-size: 0.85rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 34px;
      padding: 6px 10px;
      border-radius: 999px;
      background: #17343b;
      color: white;
      font-weight: 600;
      font-size: 0.88rem;
    }
    .swatch {
      width: 14px;
      height: 14px;
      border-radius: 999px;
      border: 2px solid transparent;
      flex: none;
    }
    .workspace {
      position: relative;
      overflow: hidden;
      min-height: 78vh;
    }
    #chart {
      width: 100%;
      height: 100%;
      min-height: 78vh;
    }
    .node-card {
      fill: rgba(255,255,255,0.94);
      stroke-width: 2.5px;
      rx: 14px;
      ry: 14px;
    }
    .node text {
      font-size: 12px;
      fill: var(--ink);
      pointer-events: none;
    }
    .link {
      fill: none;
      stroke: var(--edge);
      stroke-width: 1.6px;
    }
    .link.deleted-link {
      stroke: var(--deleted);
      stroke-dasharray: 5 5;
    }
    .tooltip {
      position: absolute;
      pointer-events: none;
      opacity: 0;
      transform: translateY(6px);
      transition: opacity 140ms ease, transform 140ms ease;
      max-width: 320px;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(19, 42, 47, 0.94);
      color: #f9faf7;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.18);
      font-size: 0.9rem;
      line-height: 1.45;
    }
    .tooltip strong { color: #ffe28a; }
    .toolbar {
      position: absolute;
      right: 16px;
      top: 16px;
      display: flex;
      gap: 10px;
      z-index: 3;
    }
    button {
      border: 0;
      border-radius: 999px;
      background: #17343b;
      color: white;
      padding: 10px 14px;
      font-size: 0.9rem;
      cursor: pointer;
      box-shadow: 0 8px 20px rgba(19, 42, 47, 0.16);
    }
    button:hover { background: #20454d; }
    @media (max-width: 960px) {
      .shell { grid-template-columns: 1fr; }
      .workspace, #chart { min-height: 68vh; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="panel sidebar">
      <div class="hero-card">
        <div class="hero-top">
          <div>
            <h2>Voting Dashboard</h2>
            <h1>Merkle Tree Control Room</h1>
          </div>
          <div class="hero-badge">Live</div>
        </div>
        <p class="hero-copy">Drive the full voting workflow from this page, inspect the live tree, and watch integrity changes update in real time as ballots are cast, verified, tampered with, invalidated, or deleted.</p>
      </div>
      <div class="section-card helper-copy">
        The <strong>root</strong> is the final fingerprint of the whole election tree. Every ballot rolls upward into it, so if any leaf changes, the root hash changes too.
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Data Source</h2>
          <span class="section-note">Session provenance</span>
        </div>
        <div class="helper-copy">
          <strong id="sourceLabel">-</strong><br>
          <span id="sourceDetail">-</span>
        </div>
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Overview</h2>
          <span class="section-note" id="rootHash">-</span>
        </div>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Levels</div>
            <div class="stat-value" id="levelCount">-</div>
            <div class="stat-sub">Tree depth</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Leaf Nodes</div>
            <div class="stat-value" id="leafCount">-</div>
            <div class="stat-sub">Receipt-linked leaves</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Registered</div>
            <div class="stat-value" id="registeredVoters">-</div>
            <div class="stat-sub">Eligible voters</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Ballots</div>
            <div class="stat-value" id="ballotCount">-</div>
            <div class="stat-sub">Cast so far</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Valid</div>
            <div class="stat-value" id="validBallots">-</div>
            <div class="stat-sub">Counted in tally</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Invalidated</div>
            <div class="stat-value" id="invalidBallots">-</div>
            <div class="stat-sub">Removed from tally</div>
          </div>
        </div>
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Candidates</h2>
          <span class="section-note">Current valid tally</span>
        </div>
        <div id="candidateList" class="candidate-list"></div>
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Actions</h2>
          <span class="section-note">Frontend command center</span>
        </div>
        <div class="action-form">
          <div class="action-grid">
            <div class="field">
              <label for="registerVoterId">Register Voter</label>
              <input id="registerVoterId" placeholder="e.g. voter_51" />
            </div>
            <div class="field">
              <label>&nbsp;</label>
              <button class="action-btn" id="registerBtn" type="button">Register</button>
            </div>
          </div>
          <div class="action-grid">
            <div class="field">
              <label for="voteVoterId">Cast Vote: Voter ID</label>
              <input id="voteVoterId" placeholder="Registered voter ID" />
            </div>
            <div class="field">
              <label for="voteCandidate">Candidate</label>
              <select id="voteCandidate">
                <option>Sam</option>
                <option>Ali</option>
                <option>Sarah</option>
              </select>
            </div>
          </div>
          <button class="action-btn alt" id="castVoteBtn" type="button">Cast Vote</button>
          <div class="action-row">
            <button class="action-btn" id="loadDatasetBtn" type="button">Load Sample Dataset</button>
            <button class="action-btn" id="buildTreeBtn" type="button">Build Merkle Tree</button>
            <button class="action-btn" id="showSummaryBtn" type="button">Show Summary</button>
            <button class="action-btn" id="showRegistryBtn" type="button">Show Registry</button>
          </div>
          <div class="action-grid">
            <div class="field">
              <label for="receiptSelect">Receipt</label>
              <select id="receiptSelect"></select>
            </div>
            <div class="field">
              <label for="receiptCandidate">Replacement Candidate</label>
              <select id="receiptCandidate">
                <option>Sam</option>
                <option>Ali</option>
                <option>Sarah</option>
              </select>
            </div>
          </div>
          <div class="action-row">
            <button class="action-btn" id="verifyBtn" type="button">Verify</button>
            <button class="action-btn warn" id="tamperBtn" type="button">Tamper</button>
            <button class="action-btn" id="invalidateBtn" type="button">Invalidate</button>
            <button class="action-btn warn" id="deleteBtn" type="button">Delete</button>
          </div>
          <div class="field">
            <label for="actionOutput">Backend Output</label>
            <textarea id="actionOutput" readonly placeholder="Action feedback from the voting workflow will appear here."></textarea>
          </div>
        </div>
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Receipts</h2>
          <span class="section-note">Ballot audit handles</span>
        </div>
        <div class="table-shell">
          <table class="data-table">
            <thead>
              <tr><th>Receipt</th><th>Voter</th><th>Vote</th><th>Status</th></tr>
            </thead>
            <tbody id="receiptTableBody"></tbody>
          </table>
        </div>
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Registry</h2>
          <span class="section-note">Eligibility ledger</span>
        </div>
        <div class="table-shell">
          <table class="data-table">
            <thead>
              <tr><th>Voter</th><th>Status</th></tr>
            </thead>
            <tbody id="registryTableBody"></tbody>
          </table>
        </div>
      </div>
      <div class="section-card helper-copy">
        Live data comes from a lightweight local server started by option 5. The browser asks for a fresh JSON snapshot every second and redraws when the election state changes.
      </div>
      <div class="section-card">
        <div class="section-head">
          <h2>Legend</h2>
          <span class="section-note">Node color semantics</span>
        </div>
        <div class="legend-item"><span class="swatch" style="background:#fff7d6;border-color:var(--root);"></span><span>Root node</span></div>
        <div class="legend-item"><span class="swatch" style="background:#edf5f7;border-color:var(--internal);"></span><span>Internal node</span></div>
        <div class="legend-item"><span class="swatch" style="background:#e8f7ee;border-color:var(--leaf);"></span><span>Valid ballot leaf</span></div>
        <div class="legend-item"><span class="swatch" style="background:#f6e3e1;border-color:var(--deleted);"></span><span>Invalidated or deleted leaf</span></div>
        <div class="legend-item"><span class="swatch" style="background:#fff0df;border-color:var(--tampered);"></span><span>Tampered ballot marker</span></div>
      </div>
    </aside>
    <main class="panel workspace">
      <div class="toolbar">
        <button id="fitBtn">Fit to Screen</button>
      </div>
      <svg id="chart"></svg>
      <div id="tooltip" class="tooltip"></div>
    </main>
  </div>
  <script>
    if (typeof d3 === "undefined") {
      document.body.innerHTML = `
        <div style="padding:24px;font-family:Segoe UI,Tahoma,sans-serif;color:#132a2f;">
          <h2>Visualization Dependency Failed To Load</h2>
          <p>This page needs D3.js from jsDelivr, but your browser could not load it.</p>
          <p>Try refreshing once, checking whether the network blocks <code>cdn.jsdelivr.net</code>, or use the ASCII tree view from option 4 for now.</p>
        </div>`;
      throw new Error("D3 failed to load");
    }

    const svg = d3.select("#chart");
    const workspace = document.querySelector(".workspace");
    const tooltip = d3.select("#tooltip");
    const width = () => workspace.clientWidth;
    const height = () => Math.max(workspace.clientHeight, 620);

    svg.attr("viewBox", [0, 0, width(), height()]);

    const zoomLayer = svg.append("g");
    let currentContent = null;
    let lastSignature = "";
    let isApplyingClamp = false;
    let latestState = null;

    const zoom = d3.zoom()
      .scaleExtent([0.35, 2.5])
      .on("zoom", event => {
        if (isApplyingClamp) return;
        const clamped = clampTransform(event.transform);
        zoomLayer.attr("transform", clamped);
        if (clamped.x !== event.transform.x || clamped.y !== event.transform.y || clamped.k !== event.transform.k) {
          isApplyingClamp = true;
          svg.call(zoom.transform, clamped);
          isApplyingClamp = false;
        }
      });

    svg.call(zoom);

    function strokeFor(data) {
      if (data.kind === "root") return "var(--root)";
      if (data.deleted) return "var(--deleted)";
      if (data.tampered) return "var(--tampered)";
      if (data.kind === "leaf") return "var(--leaf)";
      return "var(--internal)";
    }

    function fillFor(data) {
      if (data.kind === "root") return "#fff7d6";
      if (data.deleted) return "#f6e3e1";
      if (data.tampered) return "#fff0df";
      if (data.kind === "leaf") return "#e8f7ee";
      return "#edf5f7";
    }

    function attachTooltip(nodeSelection) {
      nodeSelection.on("mousemove", (event, d) => {
        const data = d.data;
        const lines = [
          `<strong>${data.name}</strong>`,
          `Full hash: ${data.hash}`
        ];
        if (typeof data.leafIndex === "number") lines.push(`Leaf index: ${data.leafIndex}`);
        if (data.voterId) lines.push(`Voter ID: ${data.voterId}`);
        if (data.candidate) lines.push(`Candidate: ${data.candidate}`);
        if (data.receiptId) lines.push(`Receipt ID: ${data.receiptId}`);
        if (data.deleted) lines.push(`Status: This ballot was deleted or invalidated.`);
        else if (data.tampered) lines.push(`Status: This ballot is flagged as tampered.`);

        tooltip
          .html(lines.join("<br>"))
          .style("left", `${event.offsetX + 18}px`)
          .style("top", `${event.offsetY + 18}px`)
          .style("opacity", 1)
          .style("transform", "translateY(0)");
      }).on("mouseleave", () => {
        tooltip.style("opacity", 0).style("transform", "translateY(6px)");
      });
    }

    function updateSummary(state) {
      const treeData = state.tree;
      const summary = state.summary;
      const root = d3.hierarchy(treeData);
      const sourceLabel = document.getElementById("sourceLabel");
      const sourceDetail = document.getElementById("sourceDetail");
      if (sourceLabel) sourceLabel.textContent = summary.sourceLabel || "-";
      if (sourceDetail) sourceDetail.textContent = summary.sourceDetail || "-";
      document.getElementById("rootHash").textContent = treeData.shortHash || "-";
      document.getElementById("levelCount").textContent = String(root.height + 1);
      document.getElementById("leafCount").textContent = String(root.leaves().length);
      document.getElementById("registeredVoters").textContent = String(summary.registeredVoters);
      document.getElementById("ballotCount").textContent = String(summary.ballotCount);
      document.getElementById("validBallots").textContent = String(summary.validBallots);
      document.getElementById("invalidBallots").textContent = String(summary.invalidBallots);

      const candidateList = document.getElementById("candidateList");
      candidateList.innerHTML = "";
      summary.candidates.forEach(candidate => {
        const row = document.createElement("div");
        row.className = "candidate-row";
        row.innerHTML = `
          <div>
            <strong>${candidate.name}</strong>
            <span>${candidate.votes} valid vote(s)${candidate.tamperedVotes ? `, ${candidate.tamperedVotes} tampered demo vote(s)` : ""}</span>
          </div>
          <div class="badge">${candidate.votes}</div>
        `;
        candidateList.appendChild(row);
      });

      const receiptSelect = document.getElementById("receiptSelect");
      receiptSelect.innerHTML = "";
      summary.receipts.forEach(receipt => {
        const option = document.createElement("option");
        option.value = receipt.receiptId;
        option.textContent = `${receipt.receiptId} | ${receipt.voterId}`;
        receiptSelect.appendChild(option);
      });

      const receiptTableBody = document.getElementById("receiptTableBody");
      receiptTableBody.innerHTML = "";
      summary.receipts.forEach(receipt => {
        const row = document.createElement("tr");
        const voteLabel = receipt.tampered && receipt.preTamperCandidate
          ? `${receipt.preTamperCandidate} -> ${receipt.candidate}`
          : receipt.candidate;
        const statusBits = [];
        statusBits.push(receipt.valid ? "Valid" : "Invalidated");
        if (receipt.tampered) statusBits.push("Tampered");
        row.innerHTML = `
          <td>${receipt.receiptId}</td>
          <td>${receipt.voterId}</td>
          <td>${voteLabel}</td>
          <td><span class="status-pill">${statusBits.join(" / ")}</span></td>
        `;
        receiptTableBody.appendChild(row);
      });

      const registryTableBody = document.getElementById("registryTableBody");
      registryTableBody.innerHTML = "";
      summary.registry.forEach(entry => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${entry.voterId}</td>
          <td><span class="status-pill">${entry.hasVoted ? "Voted" : "Eligible"}</span></td>
        `;
        registryTableBody.appendChild(row);
      });
    }

    function renderTree(treeData) {
      zoomLayer.selectAll("*").remove();
      const content = zoomLayer.append("g");
      currentContent = content;

      const root = d3.hierarchy(treeData);
      const treeLayout = d3.tree().nodeSize([120, 120]);
      treeLayout(root);

      const xExtent = d3.extent(root.descendants(), d => d.x);
      const paddingX = 110;
      const paddingY = 90;
      const xOffset = paddingX - xExtent[0];
      const yOffset = paddingY;

      const linkGen = d3.linkVertical()
        .x(d => d.x + xOffset)
        .y(d => d.y + yOffset);

      content.selectAll(".link")
        .data(root.links())
        .join("path")
        .attr("class", d => d.target.data.deleted ? "link deleted-link" : "link")
        .attr("d", linkGen);

      const node = content.selectAll(".node")
        .data(root.descendants())
        .join("g")
        .attr("class", "node")
        .attr("transform", d => `translate(${d.x + xOffset},${d.y + yOffset})`);

      node.append("rect")
        .attr("class", "node-card")
        .attr("x", -66)
        .attr("y", -22)
        .attr("width", 132)
        .attr("height", 44)
        .attr("fill", d => fillFor(d.data))
        .attr("stroke", d => strokeFor(d.data));

      node.append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "0.35em")
        .text(d => d.data.name);

      attachTooltip(node);
    }

    function clampTransform(transform) {
      if (!currentContent) return transform;

      const bounds = currentContent.node().getBBox();
      const fullWidth = width();
      const fullHeight = height();
      const scale = transform.k;
      const contentWidth = bounds.width * scale;
      const contentHeight = bounds.height * scale;
      const centerX = fullWidth / 2 - (bounds.x + bounds.width / 2) * scale;
      const baseTop = 48 - bounds.y * scale;

      let minX;
      let maxX;
      if (contentWidth < fullWidth - 240) {
        minX = centerX - 90;
        maxX = centerX + 90;
      } else {
        minX = fullWidth - 120 - (bounds.x + bounds.width) * scale;
        maxX = 120 - bounds.x * scale;
      }

      let minY;
      let maxY;
      if (contentHeight < fullHeight - 180) {
        minY = baseTop - 40;
        maxY = baseTop + 120;
      } else {
        minY = fullHeight - 90 - (bounds.y + bounds.height) * scale;
        maxY = 40 - bounds.y * scale;
      }

      return d3.zoomIdentity
        .translate(
          Math.max(minX, Math.min(maxX, transform.x)),
          Math.max(minY, Math.min(maxY, transform.y))
        )
        .scale(scale);
    }

    function fitToScreen() {
      if (!currentContent) return;
      const bounds = currentContent.node().getBBox();
      const fullWidth = width();
      const fullHeight = height();
      const scale = Math.min(
        1.1,
        0.88 / Math.max(bounds.width / fullWidth, bounds.height / fullHeight)
      );
      const tx = (fullWidth - bounds.width * scale) / 2 - bounds.x * scale;
      const ty = 50 - bounds.y * scale;
      svg.transition().duration(350).call(
        zoom.transform,
        clampTransform(d3.zoomIdentity.translate(tx, ty).scale(scale))
      );
    }

    function applyState(state) {
      latestState = state;
      if (!state) return;
      if (state.summary) updateSummary(state);
      if (!state.tree) {
        zoomLayer.selectAll("*").remove();
        currentContent = null;
        return;
      }
      renderTree(state.tree);
      fitToScreen();
    }

    async function runAction(params) {
      const query = new URLSearchParams(params);
      const response = await fetch(`/api/action?${query.toString()}`, { cache: "no-store" });
      const result = await response.json();
      document.getElementById("actionOutput").value = result.message || "";
      await refreshState(true);
      return result;
    }

    async function refreshState(force = false) {
      try {
        const response = await fetch("/api/state", { cache: "no-store" });
        if (!response.ok) return;
        const state = await response.json();
        const signature = JSON.stringify(state);
        if (!force && signature === lastSignature) return;
        lastSignature = signature;
        applyState(state);
      } catch (error) {
        console.error("Visualization refresh failed:", error);
      }
    }

    document.getElementById("fitBtn").addEventListener("click", fitToScreen);
    document.getElementById("registerBtn").addEventListener("click", async () => {
      await runAction({ cmd: "register", voter_id: document.getElementById("registerVoterId").value });
    });
    document.getElementById("castVoteBtn").addEventListener("click", async () => {
      await runAction({
        cmd: "cast_vote",
        voter_id: document.getElementById("voteVoterId").value,
        candidate: document.getElementById("voteCandidate").value
      });
    });
    document.getElementById("loadDatasetBtn").addEventListener("click", async () => {
      await runAction({ cmd: "load_dataset", path: "sample" });
    });
    document.getElementById("buildTreeBtn").addEventListener("click", async () => {
      await runAction({ cmd: "build_tree" });
    });
    document.getElementById("showSummaryBtn").addEventListener("click", async () => {
      await runAction({ cmd: "summary" });
    });
    document.getElementById("showRegistryBtn").addEventListener("click", async () => {
      await runAction({ cmd: "registry" });
    });
    document.getElementById("verifyBtn").addEventListener("click", async () => {
      await runAction({ cmd: "verify", receipt_id: document.getElementById("receiptSelect").value });
    });
    document.getElementById("tamperBtn").addEventListener("click", async () => {
      await runAction({
        cmd: "tamper",
        receipt_id: document.getElementById("receiptSelect").value,
        candidate: document.getElementById("receiptCandidate").value
      });
    });
    document.getElementById("invalidateBtn").addEventListener("click", async () => {
      await runAction({ cmd: "invalidate", receipt_id: document.getElementById("receiptSelect").value });
    });
    document.getElementById("deleteBtn").addEventListener("click", async () => {
      await runAction({ cmd: "delete", receipt_id: document.getElementById("receiptSelect").value });
    });
    window.addEventListener("resize", () => {
      svg.attr("viewBox", [0, 0, width(), height()]);
      fitToScreen();
    });

    refreshState();
    setInterval(refreshState, 1000);
  </script>
</body>
</html>)HTML";
        return html.str();
    }

    // Returns the hash that should represent this ballot in the Merkle Tree.
    // Valid ballots → their SHA-256 ballot hash.
    // Invalidated ballots → the sentinel hash (so the tree stays consistent
    //   when build_tree() is called after some ballots have been deleted).
    static std::string ballot_leaf_hash(const Ballot& b) {
        return b.valid ? b.to_hash() : MerkleTree::deleted_sentinel();
    }

    std::string source_label_unlocked() const {
        if (dataset_loaded_) {
            return changed_after_dataset_load_
                ? "Loaded dataset + CLI changes"
                : "Loaded dataset";
        }
        return "Manual live session";
    }

    std::string source_detail_unlocked() const {
        if (dataset_loaded_) {
            return dataset_source_;
        }
        return "Built from actions in this currently running CLI session.";
    }

    std::string visualization_state_json_unlocked() const {
        if (!tree_built_ || !tree_.is_built()) {
            std::ostringstream empty;
            empty << "{";
            empty << "\"tree\":null,";
            empty << "\"summary\":{"
                  << "\"sourceLabel\":\"" << json_escape(source_label_unlocked()) << "\","
                  << "\"sourceDetail\":\"" << json_escape(source_detail_unlocked()) << "\","
                  << "\"treeBuilt\":false,"
                  << "\"registeredVoters\":0,"
                  << "\"ballotCount\":0,"
                  << "\"validBallots\":0,"
                  << "\"invalidBallots\":0,"
                  << "\"candidates\":[],"
                  << "\"receipts\":[],"
                  << "\"registry\":[";
            bool first = true;
            for (const auto& entry : registry_.entries()) {
                if (!first) empty << ",";
                first = false;
                empty << "{"
                      << "\"voterId\":\"" << json_escape(entry.first) << "\","
                      << "\"hasVoted\":" << (entry.second ? "true" : "false")
                      << "}";
            }
            empty << "]"
                  << "}}";
            return empty.str();
        }

        std::vector<std::string> voter_ids;
        std::vector<std::string> candidates;
        std::vector<std::string> receipt_ids;
        std::vector<bool> tampered_flags;
        std::unordered_map<std::string, int> tally;
        std::unordered_map<std::string, int> tampered_tally;
        int valid_ballots = 0;
        int invalid_ballots = 0;

        voter_ids.reserve(ballots_.size());
        candidates.reserve(ballots_.size());
        receipt_ids.reserve(ballots_.size());
        tampered_flags.reserve(ballots_.size());

        for (const auto& b : ballots_) {
            voter_ids.push_back(b.voter_id);
            candidates.push_back(b.valid ? b.candidate : "NULLIFIED");
            receipt_ids.push_back(b.receipt_id);
            tampered_flags.push_back(b.valid && b.tampered);
            if (b.valid) {
                ++valid_ballots;
                ++tally[b.candidate];
                if (b.tampered) ++tampered_tally[b.candidate];
            } else {
                ++invalid_ballots;
            }
        }

        std::ostringstream summary;
        summary << "{";
        summary << "\"sourceLabel\":\"" << json_escape(source_label_unlocked()) << "\",";
        summary << "\"sourceDetail\":\"" << json_escape(source_detail_unlocked()) << "\",";
        summary << "\"treeBuilt\":" << (tree_built_ ? "true" : "false") << ",";
        summary << "\"registeredVoters\":" << registry_.voter_count() << ",";
        summary << "\"ballotCount\":" << ballots_.size() << ",";
        summary << "\"validBallots\":" << valid_ballots << ",";
        summary << "\"invalidBallots\":" << invalid_ballots << ",";
        summary << "\"merkleRoot\":\"" << json_escape(tree_.get_root()) << "\",";
        summary << "\"candidates\":[";
        bool first = true;
        for (const auto& kv : tally) {
            if (!first) summary << ",";
            first = false;
            summary << "{"
                    << "\"name\":\"" << json_escape(kv.first) << "\","
                    << "\"votes\":" << kv.second << ","
                    << "\"tamperedVotes\":" << tampered_tally[kv.first]
                    << "}";
        }
        summary << "],";
        summary << "\"receipts\":[";
        for (size_t i = 0; i < ballots_.size(); ++i) {
            if (i) summary << ",";
            const auto& b = ballots_[i];
            summary << "{"
                    << "\"receiptId\":\"" << json_escape(b.receipt_id) << "\","
                    << "\"voterId\":\"" << json_escape(b.voter_id) << "\","
                    << "\"candidate\":\"" << json_escape(b.candidate) << "\","
                    << "\"preTamperCandidate\":\"" << json_escape(b.pre_tamper_candidate) << "\","
                    << "\"valid\":" << (b.valid ? "true" : "false") << ","
                    << "\"tampered\":" << (b.tampered ? "true" : "false")
                    << "}";
        }
        summary << "],";
        summary << "\"registry\":[";
        bool first_voter = true;
        for (const auto& entry : registry_.entries()) {
            if (!first_voter) summary << ",";
            first_voter = false;
            summary << "{"
                    << "\"voterId\":\"" << json_escape(entry.first) << "\","
                    << "\"hasVoted\":" << (entry.second ? "true" : "false")
                    << "}";
        }
        summary << "]}";

        std::ostringstream out;
        out << "{";
        out << "\"tree\":" << tree_.export_visualization_json(
            voter_ids, candidates, receipt_ids, tampered_flags) << ",";
        out << "\"summary\":" << summary.str();
        out << "}";
        return out.str();
    }

    std::string visualization_state_json() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return visualization_state_json_unlocked();
    }

    std::string action_result_json(bool ok, const std::string& message) const {
        std::ostringstream out;
        out << "{"
            << "\"ok\":" << (ok ? "true" : "false") << ","
            << "\"message\":\"" << json_escape(message) << "\""
            << "}";
        return out.str();
    }

    std::string visualization_action_json(const std::string& path) {
        const std::string action = query_param(path, "cmd");
        try {
            if (action == "register") {
                const std::string voter_id = query_param(path, "voter_id");
                bool ok = false;
                const std::string output = capture_stdout([&]() {
                    ok = this->register_voter(voter_id);
                });
                return action_result_json(ok, output.empty() ? (ok ? "Voter registered." : "Registration failed.") : output);
            }
            if (action == "cast_vote") {
                const std::string voter_id = query_param(path, "voter_id");
                const std::string candidate = query_param(path, "candidate");
                std::string receipt_id;
                const std::string output = capture_stdout([&]() {
                    receipt_id = this->cast_vote(voter_id, candidate);
                });
                const bool ok = !receipt_id.empty();
                return action_result_json(ok, output.empty() ? (ok ? "Vote cast." : "Vote failed.") : output);
            }
            if (action == "build_tree") {
                const std::string output = capture_stdout([&]() {
                    this->build_tree();
                });
                return action_result_json(is_tree_built(), output.empty() ? "Tree build requested." : output);
            }
            if (action == "load_dataset") {
                std::string path_value = query_param(path, "path");
                if (path_value.empty() || path_value == "sample")
                    path_value = "data/dataset.csv";
                const std::string output = capture_stdout([&]() {
                    this->load_dataset(path_value);
                });
                const bool ok = output.find("loaded successfully") != std::string::npos;
                return action_result_json(ok, output.empty() ? "Dataset load requested." : output);
            }
            if (action == "verify") {
                const std::string receipt_id = query_param(path, "receipt_id");
                const std::string output = capture_stdout([&]() {
                    this->verify_vote(receipt_id);
                });
                const bool ok = output.find("[OK]") != std::string::npos || output.find("MATCH") != std::string::npos;
                return action_result_json(ok, output.empty() ? "Verification requested." : output);
            }
            if (action == "tamper") {
                const std::string receipt_id = query_param(path, "receipt_id");
                const std::string candidate = query_param(path, "candidate");
                const std::string output = capture_stdout([&]() {
                    this->tamper_vote(receipt_id, candidate);
                });
                const bool ok = output.find("TAMPER DETECTED") != std::string::npos;
                return action_result_json(ok, output.empty() ? "Tamper simulation requested." : output);
            }
            if (action == "invalidate") {
                const std::string receipt_id = query_param(path, "receipt_id");
                const std::string output = capture_stdout([&]() {
                    this->invalidate_ballot(receipt_id);
                });
                const bool ok = output.find("[OK] Ballot invalidated") != std::string::npos;
                return action_result_json(ok, output.empty() ? "Invalidation requested." : output);
            }
            if (action == "delete") {
                const std::string receipt_id = query_param(path, "receipt_id");
                const std::string output = capture_stdout([&]() {
                    this->delete_ballot(receipt_id);
                });
                const bool ok = output.find("[OK] Ballot deleted") != std::string::npos;
                return action_result_json(ok, output.empty() ? "Deletion requested." : output);
            }
            if (action == "summary") {
                const std::string output = capture_stdout([&]() {
                    this->display_summary();
                });
                return action_result_json(true, output);
            }
            if (action == "registry") {
                const std::string output = capture_stdout([&]() {
                    this->print_registry();
                });
                return action_result_json(true, output);
            }
            return action_result_json(false, "Unknown action.");
        } catch (const std::exception& ex) {
            return action_result_json(false, ex.what());
        }
    }

public:

    // ------------------------------------------------------------------
    // Register a voter  —  O(1) average (hash table insert)
    // ------------------------------------------------------------------
    bool register_voter(const std::string& voter_id) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        // ── Input validation ──────────────────────────────────────────
        if (voter_id.size() < 2) {
            std::cout << "  [!] Voter ID is too short (minimum 2 characters).\n";
            std::cout << "      Example IDs: V001, alice, voter_7\n";
            return false;
        }
        if (voter_id.find('|') != std::string::npos) {
            std::cout << "  [!] Voter ID must not contain the '|' character.\n";
            return false;
        }
        for (char c : voter_id) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                std::cout << "  [!] Voter ID must not contain spaces.\n";
                std::cout << "      Tip: use underscores instead, e.g. \"john_doe\"\n";
                return false;
            }
        }

        // ── Duplicate check ───────────────────────────────────────────
        if (!registry_.register_voter(voter_id)) {
            bool already_voted = registry_.has_voted(voter_id);
            std::cout << "  [!] '" << voter_id << "' is already registered.\n";
            if (already_voted)
                std::cout << "      This voter has already cast their ballot.\n";
            else
                std::cout << "      This voter is registered but has not voted yet.\n"
                          << "      They may cast a vote using option 2.\n";
            return false;
        }

        // ── Success ───────────────────────────────────────────────────
        int total = registry_.voter_count();
        std::cout << "\n";
        std::cout << "  +-------- Registration Confirmed ----------------------------+\n";
        std::cout << "  |  Voter ID  : " << voter_id                                << "\n";
        std::cout << "  |  Status    : Eligible to vote                             |\n";
        std::cout << "  |  Registry  : " << total << " voter(s) now registered\n";
        std::cout << "  +------------------------------------------------------------+\n";
        std::cout << "  [>] Next: use option 2 to cast a vote for this voter.\n";
        if (dataset_loaded_)
            changed_after_dataset_load_ = true;
        return true;
    }

    // ------------------------------------------------------------------
    // Cast a vote  —  O(1) eligibility check + O(log n) / O(n) tree insert
    //
    // If the Merkle Tree is already built, the new ballot's hash is inserted
    // as a leaf node using tree_.insert(), which:
    //   - Takes O(log n) when the current leaf count is odd
    //     (attaches the new leaf as right child of the last "duplicated" leaf,
    //      then walks up via parent pointers recomputing each ancestor).
    //   - Takes O(n) when the current leaf count is even
    //     (full rebuild, because integrating a new "duplicate" subtree may
    //      restructure the entire right spine).
    //
    // If the tree has not been built yet, the ballot is queued and the tree
    // will be built in full on the next build_tree() call.
    // ------------------------------------------------------------------
    std::string cast_vote(const std::string& voter_id,
                          const std::string& candidate) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!registry_.is_registered(voter_id)) {
            std::cout << "  [!] '" << voter_id << "' is not registered.\n";
            return "";
        }
        if (registry_.has_voted(voter_id)) {
            std::cout << "  [!] '" << voter_id << "' has already voted.\n";
            return "";
        }

        Ballot b;
        b.voter_id   = voter_id;
        b.candidate  = candidate;
        b.salt       = make_salt();
        b.timestamp  = make_timestamp();
        b.receipt_id = make_receipt_id(voter_id);

        int index = static_cast<int>(ballots_.size());
        ballots_.push_back(b);

        registry_.mark_voted(voter_id);
        registry_.store_receipt(b.receipt_id, index);

        std::cout << "  [+] Vote cast  |  candidate: " << candidate
                  << "  |  receipt: " << b.receipt_id << "\n";
        std::cout << "      Ballot hash: " << short_h(b.to_hash()) << "\n";

        if (tree_built_) {
            // Tree is live — insert the new leaf incrementally using node pointers.
            int prev_count = tree_.leaf_count();
            tree_.insert(b.to_hash());
            last_built_root_ = tree_.get_root();

            bool was_log_n = (prev_count % 2 == 1);
            std::cout << "      Leaf inserted into Merkle Tree  ("
                      << (was_log_n ? "O(log n) — odd-count fast path"
                                    : "O(n) — even-count rebuild")
                      << ")\n";
            std::cout << "      New root: " << short_h(tree_.get_root()) << "\n";
        } else {
            std::cout << "      [Tree not yet built -- use option 3 to build]\n";
        }

        if (dataset_loaded_)
            changed_after_dataset_load_ = true;

        return b.receipt_id;
    }

    // ------------------------------------------------------------------
    // Build the global Merkle Tree from scratch  —  O(n)
    // ------------------------------------------------------------------
    void build_tree() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (ballots_.empty()) {
            std::cout << "  [!] No ballots to build a tree from.\n";
            return;
        }

        std::vector<std::string> leaves;
        leaves.reserve(ballots_.size());
        for (const auto& b : ballots_)
            leaves.push_back(ballot_leaf_hash(b));   // sentinel for invalidated

        tree_.build(leaves);
        last_built_root_ = tree_.get_root();
        tree_built_      = true;

        std::cout << "  [+] Merkle Tree built  |  " << ballots_.size()
                  << " ballot(s)  |  levels: " << tree_.level_count() << "\n";
        std::cout << "      Root: " << tree_.get_root() << "\n";

        int tampered_n = 0;
        for (const auto& b : ballots_)
            if (b.valid && b.tampered) ++tampered_n;
        if (tampered_n > 0) {
            std::cout << "  [!] " << tampered_n << " ballot(s) marked [*** TAMPERED ***].\n";
            std::cout << "      This build sets a NEW published root that includes those changes.\n";
            std::cout << "      Option 5 will now MATCH for those ballots against this snapshot.\n";
        }
    }

    // ------------------------------------------------------------------
    // Load Dataset (Batch Registration and Voting)
    // ------------------------------------------------------------------
    void load_dataset(const std::string& filepath) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        std::ifstream file(filepath);
        if (!file.is_open()) {
            std::cout << "  [!] Failed to open dataset file: " << filepath << "\n";
            return;
        }

        std::string line;
        int registered_count = 0;
        int voted_count = 0;

        std::getline(file, line);   // skip header
        std::cout << "  [*] Loading dataset from " << filepath << "...\n";

        while (std::getline(file, line)) {
            if (line.empty()) continue;

            std::stringstream ss(line);
            std::string voter_id, candidate;

            if (std::getline(ss, voter_id, ',') && std::getline(ss, candidate)) {
                if (!candidate.empty() && candidate.back() == '\r')
                    candidate.pop_back();

                if (registry_.register_voter(voter_id))
                    registered_count++;

                if (!registry_.has_voted(voter_id)) {
                    Ballot b;
                    b.voter_id   = voter_id;
                    b.candidate  = candidate;
                    b.salt       = make_salt();
                    b.timestamp  = make_timestamp();
                    b.receipt_id = make_receipt_id(voter_id);

                    int index = static_cast<int>(ballots_.size());
                    ballots_.push_back(b);

                    registry_.mark_voted(voter_id);
                    registry_.store_receipt(b.receipt_id, index);
                    voted_count++;
                }
            }
        }

        tree_built_ = false;   // batch load: require explicit build_tree()
        dataset_loaded_ = true;
        dataset_source_ = filepath;
        changed_after_dataset_load_ = false;

        std::cout << "  [+] Dataset loaded successfully!\n";
        std::cout << "      - Voters registered: " << registered_count << "\n";
        std::cout << "      - Votes cast:        " << voted_count << "\n";
        std::cout << "  [*] Don't forget to build the Merkle Tree (Option 3)!\n";
    }

    // ------------------------------------------------------------------
    // Verify a vote by receipt ID  —  O(log n)
    //
    // Generates a Merkle proof by walking UP via parent pointers, then
    // verifies it against last_built_root_.
    // If the ballot has been invalidated, the proof shows a MISMATCH
    // (the tree holds the sentinel hash, not the original ballot hash).
    // ------------------------------------------------------------------
    void verify_vote(const std::string& receipt_id) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }

        const Ballot& b = ballots_[idx];

        if (!b.valid) {
            std::cout << "  [!] This ballot has been INVALIDATED by an election authority.\n";
            std::cout << "      Proof will show MISMATCH (sentinel hash vs. original hash).\n";
        }
        if (b.tampered) {
            std::cout << "  [!!!] This ballot is flagged [*** TAMPERED ***].\n";
            std::cout << "        The candidate field was altered after the tree was built.\n";
            std::cout << "        The proof below will show MISMATCH against the original root.\n";
        }

        // Leaf + proof follow the LIVE tree; last_built_root_ is the published
        // snapshot. After tamper_vote(), snapshot != live root → MISMATCH.
        std::string leaf  = b.to_hash();
        auto        proof = tree_.generate_proof(idx);
        bool ok = tree_.print_proof_path(receipt_id, leaf, proof, last_built_root_);

        if (!ok && b.tampered && b.valid) {
            std::cout << "  +------ Why this failed (tamper demo) -----------------------+\n";
            std::cout << "  | The ballot was changed after the published root snapshot.   |\n";
            std::cout << "  | Proof steps still combine to the LIVE tree root:            |\n";
            std::cout << "  |   " << short_h(tree_.get_root()) << "\n";
            std::cout << "  | but verification checks against the PUBLISHED snapshot:     |\n";
            std::cout << "  |   " << short_h(last_built_root_) << "\n";
            std::cout << "  | Holders of the old snapshot see MISMATCH = tamper detected. |\n";
            std::cout << "  +-------------------------------------------------------------+\n\n";
        }
    }

    // True iff Merkle proof for this receipt matches the published snapshot (no I/O).
    // For dry-run / tests: false after tamper_vote() until build_tree() refreshes snapshot.
    bool proof_matches_published_snapshot(const std::string& receipt_id) const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!tree_built_) return false;
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) return false;
        const Ballot& b = ballots_[idx];
        auto proof = tree_.generate_proof(idx);
        return MerkleTree::verify_proof(b.to_hash(), proof, last_built_root_);
    }

    // ------------------------------------------------------------------
    // Tamper simulation  —  O(log n) via tree_.update()
    // ------------------------------------------------------------------
    void tamper_vote(const std::string& receipt_id,
                     const std::string& new_candidate) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        // ── Guards ────────────────────────────────────────────────────
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            std::cout << "      The tree must exist so the tampered hash can propagate.\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already invalidated -- cannot tamper.\n";
            return;
        }
        if (ballots_[idx].candidate == new_candidate) {
            std::cout << "  [!] New candidate is identical to the current one -- no change made.\n";
            return;
        }

        std::string old_root    = tree_.get_root();
        std::string orig_cand   = ballots_[idx].candidate;
        std::string orig_hash   = ballots_[idx].to_hash();

        std::cout << "\n";
        std::cout << "  +====== TAMPERING SIMULATION ===============================+\n";
        std::cout << "  | Target receipt  : " << receipt_id                       << "\n";
        std::cout << "  | Voter           : " << ballots_[idx].voter_id           << "\n";
        std::cout << "  | Original vote   : " << orig_cand                        << "\n";
        std::cout << "  | Original hash   : " << short_h(orig_hash)               << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";

        // ── Mutate the ballot in memory ───────────────────────────────
        if (!ballots_[idx].tampered)
            ballots_[idx].pre_tamper_candidate = ballots_[idx].candidate;
        ballots_[idx].candidate = new_candidate;
        ballots_[idx].tampered  = true;           // mark for all future displays

        std::cout << "  | Tampered vote   : " << ballots_[idx].candidate          << "\n";
        std::cout << "  | New hash        : " << short_h(ballots_[idx].to_hash()) << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Propagating tampered hash up the tree via parent pointers...\n";

        // O(log n): mutates leaf node, then follows parent pointers upward.
        tree_.update(idx, ballots_[idx].to_hash());

        // Intentionally do NOT update last_built_root_ — the snapshot keeps
        // the pre-tamper root so verify_vote() correctly shows MISMATCH.
        std::string new_root = tree_.get_root();
        std::cout << "  | Old root (snapshot) : " << old_root  << "\n";
        std::cout << "  | New root (live)     : " << new_root  << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | [!!] TAMPER DETECTED: Root hash has CHANGED.\n";
        std::cout << "  |      This ballot is now flagged [*** TAMPERED ***].\n";
        std::cout << "  |      It will appear tagged in all receipt lists and summary.\n";
        std::cout << "  |      Run option 5 (Verify vote) on this receipt to see\n";
        std::cout << "  |      the proof MISMATCH that exposes the tampering.\n";
        std::cout << "  +===========================================================+\n\n";

        if (dataset_loaded_)
            changed_after_dataset_load_ = true;
    }

    // ------------------------------------------------------------------
    // Invalidate a ballot  —  O(log n) via tree_.delete_leaf()
    //
    // Marks the ballot as invalid, replaces its leaf node hash with the
    // sentinel value, then walks UP via parent pointers recomputing each
    // ancestor.  The leaf node STAYS in the tree at its original position,
    // preserving all other ballots' proofs.
    //
    // After invalidation:
    //   • The election root changes (detectable by anyone holding the old root).
    //   • verify_vote() on this ballot shows MISMATCH, proving invalidation.
    //   • The vote tally excludes this ballot.
    // ------------------------------------------------------------------
    void invalidate_ballot(const std::string& receipt_id) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already invalidated.\n";
            return;
        }

        std::string old_root = tree_.get_root();

        std::cout << "\n";
        std::cout << "  +====== BALLOT INVALIDATION ================================+\n";
        std::cout << "  | Receipt   : " << receipt_id                               << "\n";
        std::cout << "  | Voter     : " << ballots_[idx].voter_id                   << "\n";
        std::cout << "  | Candidate : " << ballots_[idx].candidate                  << "\n";
        std::cout << "  | Leaf hash : " << short_h(ballots_[idx].to_hash())         << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | Replacing leaf with sentinel & propagating via parent ptrs...\n";

        // Mark the Ballot struct as invalid
        ballots_[idx].valid     = false;
        ballots_[idx].tampered  = false;
        ballots_[idx].pre_tamper_candidate.clear();

        // O(log n): sets sentinel hash on leaf node, walks up via parent pointers
        tree_.delete_leaf(idx);

        last_built_root_ = tree_.get_root();   // root has changed — update snapshot

        std::cout << "  | Sentinel  : " << short_h(MerkleTree::deleted_sentinel()) << "\n";
        std::cout << "  | Old root  : " << old_root                                << "\n";
        std::cout << "  | New root  : " << last_built_root_                        << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | [OK] Ballot invalidated. Root has changed.\n";
        std::cout << "  |      Verify vote to confirm (MISMATCH expected).\n";
        std::cout << "  +===========================================================+\n\n";

        if (dataset_loaded_)
            changed_after_dataset_load_ = true;
    }

    // ------------------------------------------------------------------
    // Delete a ballot  --  O(log n) via tree_.delete_leaf()
    //
    // Similar to invalidate_ballot, but completely removes the vote AND
    // unmarks the voter so they can vote again.
    // ------------------------------------------------------------------
    void delete_ballot(const std::string& receipt_id) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return;
        }
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) {
            std::cout << "  [!] Receipt ID not found: " << receipt_id << "\n";
            return;
        }
        if (!ballots_[idx].valid) {
            std::cout << "  [!] Ballot is already deleted or invalidated.\n";
            return;
        }

        std::string old_root = tree_.get_root();

        std::cout << "\n";
        std::cout << "  +====== BALLOT DELETION ====================================+\n";
        std::cout << "  | Receipt   : " << receipt_id                               << "\n";
        std::cout << "  | Voter     : " << ballots_[idx].voter_id                   << "\n";
        std::cout << "  | Candidate : " << ballots_[idx].candidate                  << "\n";
        std::cout << "  | Leaf hash : " << short_h(ballots_[idx].to_hash())         << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | 1. Freeing voter to vote again...\n";
        
        registry_.unmark_voted(ballots_[idx].voter_id);
        ballots_[idx].valid     = false;
        ballots_[idx].tampered  = false;
        ballots_[idx].pre_tamper_candidate.clear();

        std::cout << "  | 2. Nullifying leaf and updating tree via parent ptrs...\n";

        // O(log n): sets sentinel hash on leaf node, walks up via parent pointers
        tree_.delete_leaf(idx);

        last_built_root_ = tree_.get_root();   // root has changed — update snapshot

        std::cout << "  | Sentinel  : " << short_h(MerkleTree::deleted_sentinel()) << "\n";
        std::cout << "  | Old root  : " << old_root                                << "\n";
        std::cout << "  | New root  : " << last_built_root_                        << "\n";
        std::cout << "  +-----------------------------------------------------------+\n";
        std::cout << "  | [OK] Ballot deleted. The voter may now cast a new vote.\n";
        std::cout << "  +===========================================================+\n\n";

        if (dataset_loaded_)
            changed_after_dataset_load_ = true;
    }

    // ------------------------------------------------------------------
    // Display a summary of the current election state.
    // ------------------------------------------------------------------
    void display_summary() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        std::unordered_map<std::string, int> tally;
        int valid_count    = 0;
        int invalid_count  = 0;
        int tampered_count = 0;

        for (const auto& b : ballots_) {
            if (b.valid) {
                tally[b.candidate]++;
                valid_count++;
                if (b.tampered) tampered_count++;
            } else {
                invalid_count++;
            }
        }

        std::cout << "\n";
        std::cout << "  +-------- Election Summary ----------------------------------+\n";
        std::cout << "  | Registered voters  : " << registry_.voter_count()         << "\n";
        std::cout << "  | Total ballots cast : " << ballots_.size()                 << "\n";
        std::cout << "  |   Valid            : " << valid_count                     << "\n";
        std::cout << "  |   Invalidated      : " << invalid_count                   << "\n";
        if (tampered_count > 0)
            std::cout << "  |   Tampered (demo)  : " << tampered_count
                      << "  <-- integrity compromised!\n";
        std::cout << "  | Vote tally (valid ballots — including any tampered ones):\n";
        for (const auto& kv : tally) {
            int tcount = 0;
            for (const auto& b : ballots_)
                if (b.valid && b.tampered && b.candidate == kv.first) ++tcount;
            std::cout << "  |   " << kv.first << " : " << kv.second << " vote(s)";
            if (tcount > 0)
                std::cout << "  (" << tcount << " tampered)  [*** TAMPERED ***]";
            std::cout << "\n";
        }
        if (tree_built_)
            std::cout << "  | Merkle root : " << tree_.get_root() << "\n";
        else
            std::cout << "  | Merkle root : (not yet built -- run option 3)\n";
        std::cout << "  +------------------------------------------------------------+\n\n";
    }

    // ------------------------------------------------------------------
    // Accessors / helpers for main.cpp
    // ------------------------------------------------------------------

    void print_tree() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        tree_.print_tree();
    }

    void print_registry() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        registry_.print_registry();
    }

    bool export_web_visualization(const std::string& output_path = "merkle_tree_vis.html") {
        std::lock_guard<std::mutex> lock(state_mutex_);
        (void)output_path;

        if (!tree_built_) {
            std::cout << "  [!] Build the Merkle Tree first (option 3).\n";
            return false;
        }

        try {
            const std::string merkle_html = live_visualization_html_template();
            const std::string launcher_html = visualization_launcher_html_template();
            const std::string mmr_html = mmr_bridge_html_template();
            if (!vis_server_.is_running()) {
                std::cout << "  [*] Starting local visualization server...\n";
                const bool started = vis_server_.start(
                    merkle_html,
                    [this]() { return this->visualization_state_json(); },
                    [this](const std::string& path) { return this->visualization_action_json(path); },
                    launcher_html,
                    mmr_html,
                    8080);
                if (!started) {
                    std::cout << "  [!] Failed to start local visualization server.\n";
                    return false;
                }
                std::cout << "  [+] Visualization hub running at " << vis_server_.url() << "\n";
            } else {
                std::cout << "  [*] Visualization hub already running at " << vis_server_.url() << "\n";
            }

            std::cout << "  [*] Opening in your default web browser...\n";
            if (!open_in_browser(vis_server_.url())) {
                std::cout << "  [!] Browser launch failed. Open this URL manually: "
                          << vis_server_.url() << "\n";
            }
            return true;
        } catch (const std::exception& ex) {
            std::cout << "  [!] Visualization launch failed: " << ex.what() << "\n";
            return false;
        }
    }

    bool is_tree_built() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return tree_built_;
    }

    int ballot_count() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return static_cast<int>(ballots_.size());
    }

    // Returns all receipt IDs with status tags for display in the menu.
    struct ReceiptInfo {
        std::string receipt_id;
        std::string voter_id;
        std::string candidate;
        std::string pre_tamper_candidate;
        bool        valid;
        bool        tampered;
    };

    std::vector<ReceiptInfo> all_receipt_info() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        std::vector<ReceiptInfo> out;
        out.reserve(ballots_.size());
        for (const auto& b : ballots_)
            out.push_back({ b.receipt_id, b.voter_id, b.candidate,
                            b.pre_tamper_candidate, b.valid, b.tampered });
        return out;
    }

    bool receipt_info_for(const std::string& receipt_id, ReceiptInfo& out) const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        int idx = registry_.get_ballot_index(receipt_id);
        if (idx < 0) return false;
        const auto& b = ballots_[idx];
        out = { b.receipt_id, b.voter_id, b.candidate,
                b.pre_tamper_candidate, b.valid, b.tampered };
        return true;
    }

    // Plain receipt list (backward-compatible helper).
    std::vector<std::string> all_receipts() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        std::vector<std::string> out;
        out.reserve(ballots_.size());
        for (const auto& b : ballots_)
            out.push_back(b.receipt_id);
        return out;
    }
};
