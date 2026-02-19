// RIFT 2026 – Two-Phase Fan-In Validation
// ════════════════════════════════════════════════════════════════════════════════
//
// PURPOSE
//   Implement a strict two-phase fan-in validation mechanism that avoids bias
//   toward either legitimate behavior or fraud.  Fan-in detection alone MUST NOT
//   be classified as fraud.  An aggregation_candidate becomes confirmed fraud
//   ONLY if corroborated by independent laundering behavior.
//
// PHASE 1 — Fan-In Candidate Identification
//   Detect accounts receiving funds from multiple unique senders within a
//   configurable time window.  Mark such accounts as "aggregation_candidate".
//   No fraud flag, no business assumptions or exemptions.
//
// PHASE 2 — Corroboration Checks (Mandatory)
//   Upgrade an aggregation_candidate to confirmed_money_laundering ONLY IF at
//   least one of the following conditions is true:
//
//     1. Shell Chain Involvement
//        - Candidate forwards aggregated funds through low-activity intermediaries
//        - Amount preservation checked (± configurable tolerance)
//        - Directional flow must be outward from candidate
//
//     2. Cycle / Ring Participation
//        - Candidate is part of any transaction cycle (direct or indirect)
//        - OR routes funds into a cycle detected elsewhere in the graph
//
//     3. Rapid Layered Outflow
//        - Candidate forwards a majority of aggregated funds within a short
//          time interval after aggregation
//
//     4. Role Conflict
//        - Same account acts as both an aggregation node AND a laundering
//          relay node (shell intermediary, fan-out source, or cycle member)
//
// CONSTRAINTS
//   - No assumptions about businesses, charities, or user intent
//   - No hardcoded entity types
//   - Does not downgrade or override other fraud flags
//   - Does not change existing detection outputs
//   - Deterministic and explainable
//
// INTEGRATION
//   Called AFTER all pattern detection, scoring, and fraud ring construction so
//   that cycle, shell chain, fan-in, and fan-out data are available for
//   corroboration lookups.
// ════════════════════════════════════════════════════════════════════════════════

import { AccountNode, RawTransaction } from './types';

// ─── Configurable thresholds ────────────────────────────────────────────────

/** Time window (ms) within which fan-in senders are counted (Phase 1) */
const FAN_IN_WINDOW_MS = 72 * 60 * 60 * 1000; // 72 hours

/** Minimum unique senders in the window to qualify as aggregation candidate */
const MIN_UNIQUE_SENDERS = 3;

/** Amount preservation tolerance for shell chain hop comparison (± 20%) */
const AMOUNT_TOLERANCE = 0.20;

/** Rapid outflow: maximum time window (ms) in which outward flow must occur */
const RAPID_OUTFLOW_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

/** Rapid outflow: minimum fraction of received amount that must be forwarded */
const RAPID_OUTFLOW_RATIO = 0.50; // 50%

/** Maximum total transactions for an account to be considered a low-activity
 *  intermediary in the shell chain involvement check */
const LOW_ACTIVITY_TX_THRESHOLD = 3;

// ─── Internal types ─────────────────────────────────────────────────────────

type AdjList = Map<string, Map<string, RawTransaction[]>>;

interface AggregationCandidate {
  accountId: string;
  senders: Set<string>;
  totalReceived: number;
  windowStart: number;  // epoch ms
  windowEnd: number;    // epoch ms
}

// ─── Phase 1: Identify aggregation candidates ───────────────────────────────

function identifyAggregationCandidates(
  transactions: RawTransaction[]
): AggregationCandidate[] {
  const candidates: AggregationCandidate[] = [];

  // Group transactions by receiver
  const byReceiver = new Map<string, RawTransaction[]>();
  for (const tx of transactions) {
    if (!byReceiver.has(tx.receiver_id)) byReceiver.set(tx.receiver_id, []);
    byReceiver.get(tx.receiver_id)!.push(tx);
  }

  for (const [receiver, txs] of byReceiver) {
    // Sort chronologically
    const sorted = txs.slice().sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    // Sliding window: find any window with >= MIN_UNIQUE_SENDERS unique senders
    let left = 0;
    let bestSenders: Set<string> | null = null;
    let bestLeft = 0;
    let bestRight = 0;

    for (let right = 0; right < sorted.length; right++) {
      const rightTime = new Date(sorted[right].timestamp).getTime();

      // Slide left pointer to maintain window
      while (
        left < right &&
        rightTime - new Date(sorted[left].timestamp).getTime() > FAN_IN_WINDOW_MS
      ) {
        left++;
      }

      // Collect unique senders in current window
      const sendersInWindow = new Set<string>();
      for (let i = left; i <= right; i++) {
        sendersInWindow.add(sorted[i].sender_id);
      }

      if (sendersInWindow.size >= MIN_UNIQUE_SENDERS) {
        if (!bestSenders || sendersInWindow.size > bestSenders.size) {
          bestSenders = sendersInWindow;
          bestLeft = left;
          bestRight = right;
        }
      }
    }

    if (bestSenders) {
      // Compute total received from those senders in the window
      let totalReceived = 0;
      for (let i = bestLeft; i <= bestRight; i++) {
        if (bestSenders.has(sorted[i].sender_id)) {
          totalReceived += sorted[i].amount;
        }
      }

      candidates.push({
        accountId: receiver,
        senders: bestSenders,
        totalReceived,
        windowStart: new Date(sorted[bestLeft].timestamp).getTime(),
        windowEnd: new Date(sorted[bestRight].timestamp).getTime(),
      });
    }
  }

  return candidates;
}

// ─── Corroboration Check 1: Shell Chain Involvement ─────────────────────────
//   The candidate forwards aggregated funds through one or more low-activity
//   intermediary accounts.  Amount preservation across hops is checked
//   (± AMOUNT_TOLERANCE).  Directional flow must be outward from the candidate.

function checkShellChainInvolvement(
  candidateId: string,
  totalReceived: number,
  graph: AdjList,
  accountMap: Map<string, AccountNode>,
): boolean {
  const outNeighbors = graph.get(candidateId);
  if (!outNeighbors) return false;

  for (const [neighborId, txs] of outNeighbors) {
    const neighbor = accountMap.get(neighborId);
    if (!neighbor) continue;

    // Neighbor must be a low-activity intermediary
    if (neighbor.total_transactions > LOW_ACTIVITY_TX_THRESHOLD) continue;

    // Check amount preservation: sum of outgoing txs to this neighbor
    const outAmount = txs.reduce((sum, tx) => sum + tx.amount, 0);
    const lowerBound = totalReceived * (1 - AMOUNT_TOLERANCE);
    const upperBound = totalReceived * (1 + AMOUNT_TOLERANCE);

    // At least partial preservation: outgoing must be ≥ 50% of received
    // AND within tolerance range OR exceeds lower bound
    if (outAmount >= lowerBound * 0.5) {
      // Verify the intermediary also forwards onward (at least 1 more hop)
      const hopNeighbors = graph.get(neighborId);
      if (hopNeighbors && hopNeighbors.size > 0) {
        // Exclude back-flow to candidate
        for (const [nextHop] of hopNeighbors) {
          if (nextHop !== candidateId) return true;
        }
      }
    }
  }

  return false;
}

// ─── Corroboration Check 2: Cycle / Ring Participation ──────────────────────
//   The candidate is part of any transaction cycle (direct or indirect) OR
//   routes funds into a cycle node detected elsewhere in the graph.

function checkCycleParticipation(
  candidateId: string,
  cycleNodes: Set<string>,
  graph: AdjList,
): boolean {
  // Direct: candidate is itself a cycle member
  if (cycleNodes.has(candidateId)) return true;

  // Indirect: candidate routes funds INTO a node that is part of a cycle
  const outNeighbors = graph.get(candidateId);
  if (!outNeighbors) return false;

  for (const [neighborId] of outNeighbors) {
    if (cycleNodes.has(neighborId)) return true;
  }

  return false;
}

// ─── Corroboration Check 3: Rapid Layered Outflow ───────────────────────────
//   The candidate forwards a majority of aggregated funds within a short time
//   interval after receiving them.  No balance retention logic assumed.

function checkRapidLayeredOutflow(
  candidateId: string,
  candidate: AggregationCandidate,
  transactions: RawTransaction[],
): boolean {
  // Find all outgoing transactions from the candidate AFTER the fan-in window starts
  const outgoingAfterAggregation = transactions.filter(
    tx =>
      tx.sender_id === candidateId &&
      new Date(tx.timestamp).getTime() >= candidate.windowStart &&
      new Date(tx.timestamp).getTime() <= candidate.windowEnd + RAPID_OUTFLOW_WINDOW_MS
  );

  if (outgoingAfterAggregation.length === 0) return false;

  // Sort by timestamp
  const sorted = outgoingAfterAggregation.slice().sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  // Check if a majority of received funds are forwarded within the rapid outflow window
  let totalOutflow = 0;
  for (const tx of sorted) {
    totalOutflow += tx.amount;
  }

  return totalOutflow >= candidate.totalReceived * RAPID_OUTFLOW_RATIO;
}

// ─── Corroboration Check 4: Role Conflict ───────────────────────────────────
//   The same account acts as both an aggregation node (fan-in target) AND a
//   laundering relay node (shell chain intermediary, fan-out source, or cycle
//   member in another context).

function checkRoleConflict(
  candidateId: string,
  shellNodes: Set<string>,
  fanOutNodes: Set<string>,
  cycleNodes: Set<string>,
): boolean {
  // The account is already identified as an aggregation node (fan-in).
  // Check if it also serves as a laundering relay:
  if (shellNodes.has(candidateId)) return true;   // Also a shell intermediary
  if (fanOutNodes.has(candidateId)) return true;   // Also a fan-out source
  if (cycleNodes.has(candidateId)) return true;    // Also a cycle participant

  return false;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Two-Phase Fan-In Validation.
 *
 * Phase 1: Identify aggregation candidates from transaction data.
 * Phase 2: Run 4 corroboration checks.  Upgrade candidates to
 *          confirmed_money_laundering if ANY check passes.
 *
 * Mutates `accounts` in-place by setting:
 *   - fan_in_classification: 'aggregation_candidate' | 'confirmed_money_laundering'
 *   - corroboration_checks: string[]   (names of triggered checks)
 *
 * Does NOT modify suspicion_score, detected_patterns, or any other
 * existing detection output.
 */
export function validateFanInTwoPhase(
  accounts: AccountNode[],
  transactions: RawTransaction[],
  graph: AdjList,
  cycles: string[][],
  shellChains: string[][],
  fanOutMap: Map<string, { receivers: Set<string> }>,
): void {
  // Build lookup structures
  const accountMap = new Map<string, AccountNode>();
  for (const a of accounts) accountMap.set(a.account_id, a);

  const cycleNodes = new Set<string>();
  for (const cycle of cycles) {
    for (const n of cycle) cycleNodes.add(n);
  }

  const shellNodes = new Set<string>();
  for (const chain of shellChains) {
    for (const n of chain) shellNodes.add(n);
  }

  const fanOutNodes = new Set<string>(fanOutMap.keys());

  // ── Phase 1: Identify aggregation candidates ──────────────────────────
  const candidates = identifyAggregationCandidates(transactions);

  // ── Phase 2: Corroboration ────────────────────────────────────────────
  for (const candidate of candidates) {
    const account = accountMap.get(candidate.accountId);
    if (!account) continue;

    const triggeredChecks: string[] = [];

    // Check 1: Shell Chain Involvement
    if (checkShellChainInvolvement(
      candidate.accountId,
      candidate.totalReceived,
      graph,
      accountMap,
    )) {
      triggeredChecks.push('shell_chain_involvement');
    }

    // Check 2: Cycle / Ring Participation
    if (checkCycleParticipation(candidate.accountId, cycleNodes, graph)) {
      triggeredChecks.push('cycle_ring_participation');
    }

    // Check 3: Rapid Layered Outflow
    if (checkRapidLayeredOutflow(
      candidate.accountId,
      candidate,
      transactions,
    )) {
      triggeredChecks.push('rapid_layered_outflow');
    }

    // Check 4: Role Conflict
    if (checkRoleConflict(
      candidate.accountId,
      shellNodes,
      fanOutNodes,
      cycleNodes,
    )) {
      triggeredChecks.push('role_conflict');
    }

    // ── Classification ──────────────────────────────────────────────────
    account.corroboration_checks = triggeredChecks;

    if (triggeredChecks.length > 0) {
      account.fan_in_classification = 'confirmed_money_laundering';
    } else {
      account.fan_in_classification = 'aggregation_candidate';
    }

    // Append to triggered_algorithms (additive only)
    if (!account.triggered_algorithms.includes('Two-Phase Fan-In Validation')) {
      account.triggered_algorithms.push('Two-Phase Fan-In Validation');
    }

    // Append classification to explanation (additive only)
    const classLabel = account.fan_in_classification === 'confirmed_money_laundering'
      ? 'CONFIRMED MONEY LAUNDERING'
      : 'AGGREGATION CANDIDATE (unconfirmed)';
    const checksStr = triggeredChecks.length > 0
      ? `Corroboration: ${triggeredChecks.join(', ')}`
      : 'No corroboration evidence found';
    account.explanation += `. Fan-In Validation: ${classLabel}. ${checksStr}`;
  }
}
