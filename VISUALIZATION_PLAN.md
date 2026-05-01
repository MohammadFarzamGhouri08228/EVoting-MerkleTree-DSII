# Merkle Tree Visualization Plan (HTML / D3.js)

This document outlines the strategy for visualizing our 50+ leaf Merkle Tree using a modern, interactive web-based approach.

The current direction is a **live local web visualization**. Instead of only exporting a static HTML snapshot, the C++ application acts as the **data engine and local server**, serving the page and exposing live JSON endpoints that the frontend polls for updates.

---

## 1. The Architecture (How it works)

1.  **Local Server (C++):** When the user selects the visualization option in the CLI, the application starts a lightweight HTTP server on `localhost`.
2.  **Live JSON State:** The backend exposes endpoints such as `/api/state`, containing:
    * registered voters
    * candidate totals
    * ballot count
    * Merkle root
    * full tree structure
3.  **Frontend Fetching:** The browser loads a single HTML page from the local server, and JavaScript polls the JSON endpoint every second.
4.  **Auto-Launch:** The C++ program automatically opens the local visualization URL in the user's default browser.
5.  **Real-Time Updates:** When the user registers voters, casts votes, invalidates ballots, or rebuilds the tree in the CLI, the frontend reflects those changes without restarting the browser.

---

## 2. Visual Elements & Layout

The visualization needs to clearly communicate the cryptographic structure of the Merkle Tree, especially highlighting the differences between valid ballots, tampered ballots, and invalidated (deleted) ballots.

### Layout Style
*   **Top-Down Hierarchical Tree:** The Root node at the top, branching down to the 50+ leaves at the bottom.
*   **Interactive Zoom & Pan:** Because a 50-leaf tree is wide, the user must be able to scroll to zoom in and drag to pan across the tree.
*   **Collapsible Nodes (Optional):** Clicking an internal node could collapse/expand its children to help focus on specific subtrees.

### Node Representation (Shapes & Colors)
Each node will be represented as a circle or rounded rectangle containing a truncated version of its SHA-256 hash (e.g., `5db186...`).

*   **Root Node:** 
    *   *Visual:* Large, bold outline, distinct color (e.g., Gold/Yellow).
    *   *Label:* `ROOT: 5db186...`
*   **Internal Nodes (Levels 1 to N-1):**
    *   *Visual:* Standard size, neutral color (e.g., Light Blue or Gray).
    *   *Label:* `Lvl X: cb091c...`
*   **Valid Leaf Nodes (Ballots):**
    *   *Visual:* Green outline.
    *   *Label:* `LEAF: 04a447...`
    *   *Tooltip (Hover):* Displays the full Voter ID, Candidate, and Receipt ID.
*   **Invalidated/Deleted Leaf Nodes (Tombstones):**
    *   *Visual:* Red outline, grayed-out background, dashed line connecting to parent.
    *   *Label:* `[NULLIFIED]`
    *   *Tooltip (Hover):* "This ballot was deleted/invalidated."

### Edge Representation (Connecting Lines)
*   **Standard Edges:** Solid, thin gray lines connecting parents to children.
*   **Proof Path Edges (If applicable):** If the visualization is triggered *after* a proof generation, the edges connecting the specific leaf to the root could be highlighted in a bright color (e.g., Orange) to visually trace the Merkle Proof.

---

## 3. Integration with the C++ CLI

The visualization feature will be seamlessly integrated into the existing C++ command-line interface.

### Menu Updates
The current option `4. Display Merkle Tree (visualise levels)` will be split or updated:

```text
  |  4.  Display Merkle Tree (ASCII Terminal View)              |
  |  5.  Open Live Interactive Web Visualization                |
```

### User Flow
1.  User loads the dataset (Option 12).
2.  User builds the tree (Option 3).
3.  User selects the live Web Visualization option.
4.  The CLI displays:
    ```text
    [*] Starting local visualization server...
    [+] Live server running at http://127.0.0.1:8080/
    [*] Opening in your default web browser...
    ```
5.  The browser opens, displaying the interactive D3.js graph.
6.  The user continues using the CLI, and the frontend refreshes automatically.

---

## 4. Implementation Steps (For the Developer)

1.  **Create the HTML/JS Template:** Serve a single HTML page from the local backend.
2.  **C++ JSON Serializer:** Use `MerkleTree` traversal to build a JSON tree such as `{"name": "Root", "children": [...]}`.
3.  **Live Summary Endpoint:** Expose election summary JSON for counts, candidates, and root hash.
4.  **Polling Logic:** Have the frontend poll `/api/state` and redraw when the state changes.
5.  **System Call:** Open the `localhost` URL automatically.

---

## 5. Next Frontend Improvements

These are intentionally not implemented yet, but should stay on the roadmap:

1.  Add click-to-focus on a node so clicking a leaf highlights its path up to the root.
2.  Add a proof mode for option 6, where the verified ballot path is colored differently in the visualization.
3.  Add labels below leaves for voter/candidate in demo mode, with a toggle to hide sensitive info.
4.  Add smooth collapse/expand for deeper trees so 50+ leaves stay readable.
5.  Add a mini overview map or reset button cluster for easier navigation on large trees.
6.  Add a status filter panel so only valid, tampered, or invalidated ballots are shown.
7.  Improve the typography and spacing further so the sidebar feels denser and more polished on large datasets.
