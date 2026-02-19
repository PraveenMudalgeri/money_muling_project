# Financial Forensics Engine

> **RIFT 2026 Hackathon** — Graph-based money laundering detection system that identifies suspicious transaction patterns, fraud rings, and mule networks from raw financial CSV data.

**Team:** NOCTABYTE'S

**Live Demo:** [https://money-muling-detection.vercel.app/](https://money-muling-detection.vercel.app/)

**Repository:** [github.com/PraveenMudalgeri/v0-financial-forensics-engine](https://github.com/PraveenMudalgeri/v0-financial-forensics-engine)

---

## Table of Contents

1. [Tech Stack](#tech-stack)
2. [System Architecture](#system-architecture)
3. [Algorithm Approach & Complexity Analysis](#algorithm-approach--complexity-analysis)
4. [Suspicion Score Methodology](#suspicion-score-methodology)
5. [Installation & Setup](#installation--setup)
6. [Usage Instructions](#usage-instructions)
7. [API Reference](#api-reference)
8. [CSV Schema](#csv-schema)
9. [Output Format](#output-format)
10. [Known Limitations](#known-limitations)
11. [Team Members](#team-members)

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Next.js 16, React 19, TypeScript 5.7 | Dashboard UI with SSR/Turbopack |
| **Graph Visualization** | Cytoscape.js 3.30 | Interactive network graph rendering |
| **UI Components** | Radix UI, shadcn/ui, Tailwind CSS 4 | Accessible, themed component library |
| **Charts** | Recharts 2.15 | Metrics dashboard charts |
| **Backend** | Node.js, Express 4.21, TypeScript 5.7 | REST API and detection pipeline |
| **File Upload** | Multer | In-memory CSV file processing |
| **Build Tools** | tsx (dev), tsc (build), Turbopack | Fast TypeScript execution |
| **Monorepo** | Concurrently | Parallel frontend + backend dev |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND (Next.js)                      │
│  ┌──────────┐ ┌──────────────┐ ┌───────────┐ ┌──────────────┐  │
│  │  CSV     │ │   Metrics    │ │  Fraud    │ │  Network     │  │
│  │  Upload  │ │  Dashboard   │ │  Ring     │ │  Graph       │  │
│  │          │ │  (Recharts)  │ │  Table    │ │  (Cytoscape) │  │
│  └────┬─────┘ └──────────────┘ └───────────┘ └──────────────┘  │
│       │                                                         │
│       │  POST /api/analyze   GET /api/sample-data               │
└───────┼─────────────────────────────────────────────────────────┘
        │  HTTP (JSON)
┌───────▼─────────────────────────────────────────────────────────┐
│                      BACKEND (Express)                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────┐   │
│  │ CSV Validator │───▶│       DETECTION PIPELINE             │   │
│  │ (Schema +     │    │                                      │   │
│  │  type check)  │    │  1. Build Adjacency List  O(T)       │   │
│  └──────────────┘    │  2. Cycle Detection       O(V·(V+E)) │   │
│                      │  3. Fan-In Detection      O(T log T)  │   │
│                      │  4. Fan-Out Detection     O(T log T)  │   │
│                      │  5. Shell Chain Detection  O(V+E)     │   │
│                      │  6. Suspicion Scoring     O(V·T)      │   │
│                      │  7. Fraud Ring Builder                │   │
│                      │  8. Relationship Intelligence         │   │
│                      │  9. Temporal Cycle Validation          │   │
│                      │ 10. Ring Leadership (Centrality)       │   │
│                      │ 11. Multi-Stage Flow Detection         │   │
│                      │ 12. Mule Community Detection  O(V+E)  │   │
│                      │ 13. Two-Phase Fan-In Validation        │   │
│                      │ 14. Shell Chain Ring Collapsing        │   │
│                      └──────────────────────────────────────┘   │
│                              │                                  │
│                    ┌─────────▼─────────┐                        │
│                    │  Hackathon JSON   │                        │
│                    │  + Cytoscape Data │                        │
│                    └───────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Algorithm Approach & Complexity Analysis

### 1. Cycle Detection (Johnson Variant)

**Purpose:** Detect circular money flows (A → B → C → A) indicating classic laundering circuits.

**Approach:** DFS-based traversal from every node, bounded by maximum cycle length of 5. Duplicate cycles eliminated via sorted-node-set signatures.

| Metric | Value |
|--------|-------|
| Cycle length | 3–5 nodes |
| Deduplication | Sorted node-set hashing |
| Time Complexity | O(V · (V + E)), pruned by depth limit |
| Space Complexity | O(V + C) where C = number of cycles |

### 2. Fan-In Detection (Smurfing)

**Purpose:** Identify accounts receiving funds from many unique senders within a short window — a signature of structuring/smurfing.

**Approach:** 72-hour sliding window over transactions grouped by receiver. Triggers when ≥ 10 unique senders are found in any window.

| Metric | Value |
|--------|-------|
| Window size | 72 hours (configurable) |
| Threshold | ≥ 10 unique senders |
| Time Complexity | O(T log T) per receiver (sort + scan) |

### 3. Fan-Out Detection

**Purpose:** Detect rapid fund dispersal — one account sending to many recipients within a short window.

**Approach:** Mirror of fan-in: 72-hour sliding window over transactions grouped by sender. Triggers at ≥ 10 unique receivers.

| Metric | Value |
|--------|-------|
| Window size | 72 hours |
| Threshold | ≥ 10 unique receivers |
| Time Complexity | O(T log T) per sender |

### 4. Shell Chain Detection

**Purpose:** Trace money flowing through low-activity intermediary accounts (shell accounts) used to obscure the trail.

**Approach:** BFS from each node, looking for paths ≥ 3 hops where all intermediate nodes have ≤ 3 total transactions. Chains are collapsed to one ring per connected component (longest path retained).

| Metric | Value |
|--------|-------|
| Min chain length | 3 hops (4 nodes) |
| Max chain length | 6 hops |
| Shell threshold | ≤ 3 total transactions |
| Ring collapsing | One ring per connected component |
| Time Complexity | O(V + E) per BFS |

### 5. Transaction Velocity Analysis

**Purpose:** Flag accounts with abnormally high transaction frequency.

**Approach:** Compute transactions-per-day for each account. Accounts exceeding 15 tx/day receive a velocity score boost.

| Metric | Value |
|--------|-------|
| Threshold | > 15 transactions/day |
| Time Complexity | O(T) |

### 6. Relationship Intelligence (False Positive Reduction)

**Purpose:** Reduce false positives by identifying legitimate recurring relationships (rent, payroll, subscriptions).

**Approach:** Four sub-analyses — recurring pair detection, relationship duration, amount consistency, and periodicity. Score adjustments applied only to non-cycle accounts.

| Sub-Analysis | Signal |
|-------------|--------|
| Recurring pairs | Same sender-receiver with > N transactions |
| Duration | Relationship spanning significant time |
| Amount consistency | Low variance in transaction amounts |
| Periodicity | Regular intervals between transactions |

### 7. Temporal Cycle Validation

**Purpose:** Verify that detected cycles represent plausible money flows in time.

**Approach:** For each cycle ring, check: (1) Chronological ordering of hop timestamps, (2) Amount continuity — no hop drops > 50%. Invalid cycles are removed and member scores adjusted.

| Metric | Value |
|--------|-------|
| Ordering | t(hop₁) ≤ t(hop₂) ≤ ... ≤ t(hopₙ) |
| Amount continuity | Each hop ≥ 50% of previous |
| Action on failure | Ring removed, scores recalculated |

### 8. Ring Leadership Detection (Betweenness Centrality)

**Purpose:** Identify orchestrators, intermediaries, and peripheral members within each fraud ring.

**Approach:** Brandes' algorithm for betweenness centrality on ring-local subgraphs. Top node = ORCHESTRATOR (+10 score boost), middle tier = INTERMEDIARY, bottom tier = PERIPHERAL.

| Metric | Value |
|--------|-------|
| Algorithm | Brandes' betweenness centrality (unweighted, directed) |
| Roles | ORCHESTRATOR / INTERMEDIARY / PERIPHERAL |
| Orchestrator boost | +10 (capped at 100) |
| Time Complexity | O(V · E) per ring (effectively O(1) for small rings) |

### 9. Multi-Stage Flow Detection

**Purpose:** Identify accounts spanning multiple pattern types — strong indicator of structured laundering across placement → layering → integration phases.

**Approach:** For each account, collect distinct pattern types from its ring memberships. If ≥ 2 distinct patterns exist, compute temporal ordering and tag as MULTI_STAGE.

| Metric | Value |
|--------|-------|
| Threshold | ≥ 2 distinct pattern types |
| Score boost | +20 (capped at 100) |
| Output | Ordered flow pattern sequence |

### 10. Interconnected Mule Community Detection

**Purpose:** Detect coordinated laundering networks that span multiple fraud rings via connected component analysis on the suspicious subgraph.

**Approach:** BFS connected components over accounts with suspicion_score > 0. Each component validated with ≥ 2 independent evidence categories (cycle, fan-in, fan-out, shell chain, bridge nodes, edge density). Overlapping pattern-level rings merged under a single community ring ID.

| Metric | Value |
|--------|-------|
| Evidence categories | 6 (cycle, fan_in, fan_out, shell_chain, bridge, density) |
| Minimum evidence | ≥ 2 independent categories |
| Risk score formula | min(100, round(avg(member_scores) + log₂(member_count + 1) × 10)) |
| Time Complexity | O(V + E) over suspicious subgraph |

### 11. Two-Phase Fan-In Validation

**Purpose:** Prevent fan-in detection alone from being classified as fraud. Requires independent corroboration.

**Approach:**

- **Phase 1:** Sliding window (72h) identifies aggregation candidates (≥ 3 unique senders). No fraud flag.
- **Phase 2:** Four mandatory corroboration checks — if any pass, upgrade to `confirmed_money_laundering`; otherwise remain `aggregation_candidate`.

| Corroboration Check | Condition |
|--------------------|-----------|
| Shell Chain Involvement | Outward flow through low-activity intermediaries with amount preservation (±20%) |
| Cycle/Ring Participation | Direct cycle membership OR routes funds into a cycle node |
| Rapid Layered Outflow | ≥ 50% of received funds forwarded within 24h |
| Role Conflict | Account is both aggregation node AND relay (shell/fan-out/cycle) |

---

## Suspicion Score Methodology

Each account receives a **composite suspicion score** (0–100) based on detected pattern participation:

### Base Pattern Weights

| Pattern | Weight | Trigger Condition |
|---------|--------|-------------------|
| Cycle Participation | **+40** | Account is in any detected cycle (length 3–5) |
| Fan-In (Smurfing) | **+30** | ≥ 10 unique senders within 72h window |
| Fan-Out (Dispersal) | **+30** | ≥ 10 unique receivers within 72h window |
| Shell Chain | **+35** | Intermediate node with ≤ 3 total transactions |
| High Velocity | **+15** | > 15 transactions/day |

### Post-Detection Adjustments

| Adjustment | Score Change | Condition |
|-----------|-------------|-----------|
| False Positive Dampening | **−30** | Degree > 100, no cycles, >60% consistent intervals |
| Relationship Intelligence | Variable | Recurring pairs, amount consistency, periodicity |
| Orchestrator Boost | **+10** | Highest betweenness centrality in ring |
| Multi-Stage Boost | **+20** | Account spans ≥ 2 distinct pattern types |

### Score Formula

```
base_score = Σ (pattern_weights for triggered patterns)

adjustments = false_positive_dampening
            + relationship_intelligence
            + orchestrator_boost
            + multi_stage_boost

final_score = clamp(base_score + adjustments, 0, 100)
```

All scores are **deterministic** — identical input always produces identical output. No ML or probabilistic components.

---

## Installation & Setup

### Prerequisites

- **Node.js** ≥ 18.x
- **npm** ≥ 9.x

### Quick Start

```bash
# Clone the repository
git clone https://github.com/PraveenMudalgeri/v0-financial-forensics-engine.git
cd v0-financial-forensics-engine

# Install all dependencies (root + backend + frontend)
npm run install:all

# Start both backend and frontend in development mode
npm run dev
```

This launches:
- **Backend** → `http://localhost:8080`
- **Frontend** → `http://localhost:3001`

### Manual Setup

```bash
# Backend
cd backend
npm install
npm run dev          # Development (hot-reload via tsx)
# OR
npm run build        # Compile TypeScript
npm start            # Run compiled JS

# Frontend (separate terminal)
cd frontend
npm install
npm run dev          # Development (Turbopack)
# OR
npm run build        # Production build
npm start            # Serve production build
```

### Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Backend server port |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | Backend API base URL for frontend |

---

## Usage Instructions

### 1. Upload CSV Data

- Open the dashboard at `http://localhost:3001`
- Click **"Upload CSV"** and select a transaction CSV file
- OR click **"Load Sample Data"** to use built-in test data

### 2. Explore Results

The dashboard presents four tabs:

| Tab | Content |
|-----|---------|
| **Network Graph** | Interactive Cytoscape.js graph — nodes colored by suspicion score, edges by pattern type. Zoom, pan, click nodes for details. |
| **Metrics Dashboard** | Summary statistics — total accounts analyzed, suspicious accounts flagged, fraud rings detected, processing time. |
| **Fraud Rings** | Table of all detected fraud rings with pattern type, member count, risk score, and member list. |
| **Suspicious Accounts** | Sortable table of flagged accounts with scores, detected patterns, triggered algorithms, and explanations. |

### 3. Download Results

Click **"Download JSON"** to export the hackathon-format JSON output containing all suspicious accounts, fraud rings, and summary statistics.

### 4. Detection Modes

The API supports selective algorithm execution via query parameter:

```
POST /api/analyze?mode=all        # Run all algorithms (default)
POST /api/analyze?mode=fan-in     # Fan-in only
POST /api/analyze?mode=fan-out    # Fan-out only
POST /api/analyze?mode=cycles     # Cycle detection only
POST /api/analyze?mode=shell      # Shell chain only
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/analyze` | Upload CSV and run full detection pipeline |
| `POST` | `/api/validate` | Validate CSV schema without running detection |
| `GET` | `/api/sample-data` | Generate and analyze built-in sample data |

### POST /api/analyze

**Request:** Multipart form (file field `file`) OR JSON body `{ "csvContent": "..." }`

**Response:**
```json
{
  "success": true,
  "validation": { "errors": [], "warnings": [], "transactionCount": 500 },
  "analysis": {
    "accounts": [...],
    "fraudRings": [...],
    "summary": {
      "total_accounts_analyzed": 100,
      "total_transactions": 500,
      "suspicious_accounts_flagged": 15,
      "fraud_rings_detected": 4,
      "processing_time_seconds": 0.123
    },
    "hackathonOutput": {...},
    "graphData": { "nodes": [...], "edges": [...] }
  }
}
```

---

## CSV Schema

The input CSV must contain these columns (order-independent, case-insensitive headers):

| Column | Type | Format | Description |
|--------|------|--------|-------------|
| `transaction_id` | string | Any unique ID | Unique transaction identifier |
| `sender_id` | string | Any ID | Sending account identifier |
| `receiver_id` | string | Any ID | Receiving account identifier |
| `amount` | number | Positive decimal | Transaction amount |
| `timestamp` | string | `YYYY-MM-DD HH:MM:SS` | Transaction timestamp |

**Example:**
```csv
transaction_id,sender_id,receiver_id,amount,timestamp
TXN001,ACC_A,ACC_B,5000.00,2025-01-15 10:30:00
TXN002,ACC_B,ACC_C,4800.00,2025-01-15 14:45:00
TXN003,ACC_C,ACC_A,4600.00,2025-01-16 09:00:00
```

---

## Output Format

### Hackathon JSON Structure

```json
{
  "suspicious_accounts": [
    {
      "account_id": "ACC_B",
      "suspicion_score": 70,
      "detected_patterns": ["cycle", "fan_in"],
      "ring_id": "RING_001",
      "triggered_algorithms": ["DFS Cycle Detection (Johnson variant)", "72h Sliding Window Fan-In"],
      "explanation": "Part of 1 fraud ring(s): RING_001. Received from 12 unique senders within 72h"
    }
  ],
  "fraud_rings": [
    {
      "ring_id": "RING_001",
      "pattern_type": "cycle",
      "member_accounts": ["ACC_A", "ACC_B", "ACC_C"],
      "member_count": 3,
      "risk_score": 70
    }
  ],
  "summary": {
    "total_accounts_analyzed": 100,
    "total_transactions": 500,
    "suspicious_accounts_flagged": 15,
    "fraud_rings_detected": 4,
    "processing_time_seconds": 0.123
  }
}
```

---

## Known Limitations

1. **In-Memory Processing** — All transactions are held in memory. Datasets exceeding ~1M transactions may cause memory pressure on resource-constrained environments.

2. **Cycle Length Cap** — Cycle detection is bounded to cycles of length 3–5 nodes. Longer money circuits (6+ hops) are not detected as cycles, though they may be captured by shell chain or community detection.

3. **Static Time Windows** — Fan-in/fan-out windows are fixed at 72 hours. Sophisticated laundering schemes using longer time horizons may evade detection.

4. **No Persistent Storage** — The engine is stateless between requests. There is no database; each analysis runs independently from uploaded CSV data.

5. **Single-File Batch** — The system processes one CSV file per request. It does not support incremental/streaming analysis or multi-file correlation.

6. **Threshold Sensitivity** — Hard-coded thresholds (10 unique senders for fan-in, 3 transactions for shell accounts, 15 tx/day for velocity) may not generalize across all financial datasets without tuning.

7. **No Currency/Denomination Handling** — All amounts are treated as unitless numbers. Cross-currency transactions are not normalized.

---

## Team Members

| Name | GitHub |
|------|--------|
| **Praveen Mudalgeri** | [@PraveenMudalgeri](https://github.com/PraveenMudalgeri) |
| **Abhishek Hiremath** | — |
| **Chetankumar Ramesh Shiddappanavar** | — |
| **Mohammed Vasim Khasimasab Hawaldar** | — |

---

## License

This project was built for the **RIFT 2026 Hackathon**.
