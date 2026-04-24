# Merkle Tree Visualization Plan (HTML / D3.js)

This document outlines the strategy for visualizing our 50+ leaf Merkle Tree using a modern, interactive web-based approach. 

Since C++ lacks native, lightweight graphical libraries for complex tree rendering, our C++ application will act as the **data engine**, generating a standalone HTML file containing the tree structure and a lightweight JavaScript rendering library (D3.js).

---

## 1. The Architecture (How it works)

1.  **Data Generation (C++):** When the user selects the "Visualize Tree" option in the CLI, the `MerkleTree` class will perform a Breadth-First Search (BFS) or Depth-First Search (DFS) traversal.
2.  **JSON Export:** During traversal, the C++ code will format the nodes and their parent-child relationships into a JSON string.
3.  **HTML Generation:** The C++ code will write this JSON string directly into a pre-defined HTML template (which includes the D3.js library via CDN).
4.  **Auto-Launch:** The C++ program will save this file as `merkle_tree_vis.html` in the project directory and automatically open it in the user's default web browser using a system call (e.g., `system("start merkle_tree_vis.html")` on Windows).

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
  |  5.  Export & Open Interactive Web Visualization            |
```

### User Flow
1.  User loads the dataset (Option 12).
2.  User builds the tree (Option 3).
3.  User selects the new Web Visualization option.
4.  The CLI displays:
    ```text
    [*] Generating tree data...
    [*] Writing merkle_tree_vis.html...
    [+] Success! Opening in your default web browser...
    ```
5.  The browser opens, displaying the interactive D3.js graph.

---

## 4. Implementation Steps (For the Developer)

1.  **Create the HTML/JS Template:** Write a standalone HTML file containing the D3.js logic required to render a hierarchical tree from a JSON object.
2.  **C++ JSON Serializer:** Add a method to `MerkleTree` (e.g., `export_json()`) that traverses the tree pointers and builds a string formatted as `{"name": "Root", "children": [...]}`.
3.  **C++ File Writer:** Add a method to `VotingSystem` that takes the JSON string, injects it into the HTML template string, and writes it to disk.
4.  **System Call:** Add the OS-specific command to launch the generated HTML file automatically.