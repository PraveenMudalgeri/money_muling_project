// ─── RELATIONSHIP INTELLIGENCE LAYER ─────────────────────────────────────────
// Post-detection module that reduces false positives by recognising legitimate
// recurring financial relationships (rent, payroll, subscriptions, vendor payouts).
//
// Runs AFTER all pattern detection, velocity scoring, and existing false-positive
// dampening.  It never increases a score — only decreases it when strong evidence
// of a benign recurring relationship is found.
//
// Complexity: O(T log T)  (dominated by per-pair timestamp sorting)
// ─────────────────────────────────────────────────────────────────────────────

import { AccountNode, RawTransaction } from './types';

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

/** Minimum number of transactions for a pair to be considered "recurring" */
const MIN_RECURRING_TX_COUNT = 3;

/** Minimum span (ms) a pair must cover to qualify as recurring (30 days) */
const MIN_RECURRING_SPAN_MS = 30 * 24 * 60 * 60 * 1000;

/** Maximum total score reduction per account from this module */
const MAX_TOTAL_REDUCTION = 50;

/** Duration thresholds (ms) for Relationship Duration Analysis */
const DURATION_TIER_1_MS = 60 * 24 * 60 * 60 * 1000;   // 60 days
const DURATION_TIER_2_MS = 120 * 24 * 60 * 60 * 1000;   // 120 days

/** Coefficient-of-variation threshold for Amount Consistency */
const CV_THRESHOLD = 0.20; // 20%

/** Fraction of intervals that must fall within ±25 % of the mean */
const PERIODICITY_MATCH_RATIO = 0.70; // 70%

/** Tolerance band around the mean interval for periodicity check */
const PERIODICITY_TOLERANCE = 0.25; // ±25 %

// ─── HELPER: parse timestamp to epoch ms ─────────────────────────────────────
function toEpoch(ts: string): number {
  return new Date(ts).getTime();
}

// ─── PAIR KEY ────────────────────────────────────────────────────────────────
// Directional key: A→B is different from B→A
function pairKey(sender: string, receiver: string): string {
  return `${sender}|${receiver}`;
}

// ─── TYPES ───────────────────────────────────────────────────────────────────

interface PairStats {
  sender: string;
  receiver: string;
  amounts: number[];
  timestamps: number[];  // sorted ascending (epoch ms)
  spanMs: number;        // latest - earliest
}

interface ScoreReduction {
  recurring: number;
  duration: number;
  consistency: number;
  periodicity: number;
}

// ─── MAIN EXPORT ─────────────────────────────────────────────────────────────

/**
 * Adjust suspicion scores downward for accounts that participate in
 * demonstrably legitimate recurring financial relationships.
 *
 * This function mutates the `suspicion_score`, `explanation`, and
 * `triggered_algorithms` fields on the supplied AccountNode objects.
 *
 * @param accounts        Array of all account nodes (will be mutated)
 * @param transactions    Full transaction dataset
 * @param cycleMembers    Set of account IDs that belong to detected fraud
 *                        cycles — these are NEVER adjusted
 * @returns               The same `accounts` array (mutated in-place)
 */
export function adjustScoresUsingRelationshipIntelligence(
  accounts: AccountNode[],
  transactions: RawTransaction[],
  cycleMembers: Set<string>,
): AccountNode[] {
  // ── Step 1: Build per-pair statistics ────────────────────────────────────
  // Group transactions by directed sender→receiver pair.
  // O(T) to group, O(T log T) total after per-pair sort.

  const pairMap = new Map<string, PairStats>();

  for (const tx of transactions) {
    const key = pairKey(tx.sender_id, tx.receiver_id);
    let stats = pairMap.get(key);
    if (!stats) {
      stats = {
        sender: tx.sender_id,
        receiver: tx.receiver_id,
        amounts: [],
        timestamps: [],
        spanMs: 0,
      };
      pairMap.set(key, stats);
    }
    stats.amounts.push(tx.amount);
    stats.timestamps.push(toEpoch(tx.timestamp));
  }

  // Sort timestamps per pair and compute span — O(T log T) total
  for (const stats of pairMap.values()) {
    stats.timestamps.sort((a, b) => a - b);
    stats.spanMs =
      stats.timestamps[stats.timestamps.length - 1] - stats.timestamps[0];
  }

  // ── Step 2: Identify qualifying recurring pairs ──────────────────────────
  // A pair qualifies if it has ≥3 transactions spanning ≥30 days.

  const qualifyingPairs: PairStats[] = [];
  for (const stats of pairMap.values()) {
    if (
      stats.amounts.length >= MIN_RECURRING_TX_COUNT &&
      stats.spanMs >= MIN_RECURRING_SPAN_MS
    ) {
      qualifyingPairs.push(stats);
    }
  }

  // ── Step 3: Pre-compute per-account reduction from all qualifying pairs ──
  // For each qualifying pair we compute reductions from four sub-analyses,
  // then aggregate the best reduction per account across all its pairs.

  const accountReductions = new Map<string, ScoreReduction>();

  const ensureReduction = (id: string): ScoreReduction => {
    let r = accountReductions.get(id);
    if (!r) {
      r = { recurring: 0, duration: 0, consistency: 0, periodicity: 0 };
      accountReductions.set(id, r);
    }
    return r;
  };

  for (const pair of qualifyingPairs) {
    // ── A) Recurring Pair Detection ────────────────────────────────────
    // At least 3 txns spanning ≥30 days → reduce up to 25 pts
    const recurringReduction = Math.min(
      25,
      // Scale: 3 txns = 10 pts, 6 txns = 17 pts, 10+ = 25 pts
      Math.round(10 + ((pair.amounts.length - 3) / 7) * 15),
    );

    // ── B) Relationship Duration Analysis ──────────────────────────────
    let durationReduction = 0;
    if (pair.spanMs >= DURATION_TIER_2_MS) {
      durationReduction = 20;
    } else if (pair.spanMs >= DURATION_TIER_1_MS) {
      durationReduction = 10;
    }

    // ── C) Amount Consistency Check ────────────────────────────────────
    let consistencyReduction = 0;
    if (pair.amounts.length >= 2) {
      const mean =
        pair.amounts.reduce((s, a) => s + a, 0) / pair.amounts.length;

      if (mean > 0) {
        // Standard deviation
        const variance =
          pair.amounts.reduce((s, a) => s + (a - mean) ** 2, 0) /
          pair.amounts.length;
        const stdDev = Math.sqrt(variance);

        // Coefficient of variation
        const cv = stdDev / mean;

        if (cv < CV_THRESHOLD) {
          // More consistent → more reduction (max 15 pts)
          // cv = 0 → 15,  cv = 0.20 → 0
          consistencyReduction = Math.round(15 * (1 - cv / CV_THRESHOLD));
        }
      }
    }

    // ── D) Monthly Periodicity Detection ───────────────────────────────
    let periodicityReduction = 0;
    if (pair.timestamps.length >= 3) {
      // Compute inter-transaction gaps
      const gaps: number[] = [];
      for (let i = 1; i < pair.timestamps.length; i++) {
        gaps.push(pair.timestamps[i] - pair.timestamps[i - 1]);
      }

      const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length;

      if (avgGap > 0) {
        // Count gaps within ±25 % of the average
        const lo = avgGap * (1 - PERIODICITY_TOLERANCE);
        const hi = avgGap * (1 + PERIODICITY_TOLERANCE);
        const matchCount = gaps.filter((g) => g >= lo && g <= hi).length;
        const matchRatio = matchCount / gaps.length;

        if (matchRatio >= PERIODICITY_MATCH_RATIO) {
          // Scale: 70 % match → 10 pts, 100 % match → 20 pts
          periodicityReduction = Math.round(
            10 + ((matchRatio - PERIODICITY_MATCH_RATIO) / (1 - PERIODICITY_MATCH_RATIO)) * 10,
          );
        }
      }
    }

    // Apply best-of reductions to both sender and receiver
    for (const accountId of [pair.sender, pair.receiver]) {
      const r = ensureReduction(accountId);
      r.recurring = Math.max(r.recurring, recurringReduction);
      r.duration = Math.max(r.duration, durationReduction);
      r.consistency = Math.max(r.consistency, consistencyReduction);
      r.periodicity = Math.max(r.periodicity, periodicityReduction);
    }
  }

  // ── Step 4: Apply capped reductions to account scores ────────────────────

  for (const account of accounts) {
    // Never adjust accounts that are part of detected fraud cycles
    if (cycleMembers.has(account.account_id)) continue;

    // Only adjust accounts that currently have a positive score
    if (account.suspicion_score <= 0) continue;

    const r = accountReductions.get(account.account_id);
    if (!r) continue;

    // Sum individual reductions, cap at MAX_TOTAL_REDUCTION
    const totalReduction = Math.min(
      MAX_TOTAL_REDUCTION,
      r.recurring + r.duration + r.consistency + r.periodicity,
    );

    if (totalReduction <= 0) continue;

    // Apply reduction — floor at 0
    const oldScore = account.suspicion_score;
    account.suspicion_score = Math.max(0, oldScore - totalReduction);

    // Update metadata so the adjustment is visible in the output
    account.triggered_algorithms.push('relationship_intelligence');

    // Build a human-readable breakdown
    const parts: string[] = [];
    if (r.recurring > 0) parts.push(`recurring_pair(-${r.recurring})`);
    if (r.duration > 0) parts.push(`long_relationship(-${r.duration})`);
    if (r.consistency > 0) parts.push(`amount_consistency(-${r.consistency})`);
    if (r.periodicity > 0) parts.push(`monthly_periodicity(-${r.periodicity})`);

    const detail = parts.join(', ');
    const note =
      ` | Relationship Intelligence: score reduced by ${totalReduction}` +
      ` (${oldScore}→${account.suspicion_score}) [${detail}]`;

    account.explanation += note;

    // If score dropped to 0, the account is no longer suspicious
    account.is_suspicious = account.suspicion_score > 0;
  }

  return accounts;
}
