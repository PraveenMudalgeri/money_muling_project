// RIFT 2026 - Complete Detection Engine
// Implements: Cycle Detection, Fan-in/Fan-out, Shell Chains, Suspicion Scoring
// All algorithms documented with time complexity

import {
  RawTransaction,
  AccountNode,
  FraudRing,
  AnalysisResult,
  HackathonOutput,
  CytoscapeGraphData,
  FanInTransaction,
  ShellChainPath,
  DetectionMode,
  PatternScores,
} from './types';
import { adjustScoresUsingRelationshipIntelligence } from './relationship-intelligence';
import { validateTemporalCycles } from './temporal-cycle-validation';
import { analyzeRingLeadership } from './centrality-analysis';
import { detectMultiStageFlows } from './multi-stage-flow-analysis';
import { validateFanInTwoPhase } from './fan-in-validation';

// ─── ADJACENCY LIST GRAPH ────────────────────────────────────────────────────
// Using adjacency list for O(V+E) traversal, optimal for sparse financial graphs

type AdjList = Map<string, Map<string, RawTransaction[]>>;

function buildAdjacencyList(transactions: RawTransaction[]): AdjList {
  const graph: AdjList = new Map();
  for (const tx of transactions) {
    if (!graph.has(tx.sender_id)) graph.set(tx.sender_id, new Map());
    if (!graph.has(tx.receiver_id)) graph.set(tx.receiver_id, new Map());
    const neighbors = graph.get(tx.sender_id)!;
    if (!neighbors.has(tx.receiver_id)) neighbors.set(tx.receiver_id, []);
    neighbors.get(tx.receiver_id)!.push(tx);
  }
  return graph;
}

// ─── 1. CYCLE DETECTION ──────────────────────────────────────────────────────
// Uses DFS-based approach similar to Johnson's algorithm
// Finds simple cycles of length 3-5
// Time complexity: O(V + E) per DFS, bounded by max cycle length
// Total: O((V+E) * V) worst case, but pruned heavily by length limit

function detectCycles(
  graph: AdjList,
  allNodes: string[]
): { cycles: string[][]; ringMap: Map<string, string[]> } {
  const cycles: string[][] = [];
  const foundCycleSet = new Set<string>();

  for (const startNode of allNodes) {
    // DFS with depth limit of 5
    const stack: { node: string; path: string[] }[] = [
      { node: startNode, path: [startNode] },
    ];

    while (stack.length > 0) {
      const { node, path } = stack.pop()!;

      if (path.length > 5) continue; // Max cycle length 5

      const neighbors = graph.get(node);
      if (!neighbors) continue;

      for (const [neighbor] of neighbors) {
        if (neighbor === startNode && path.length >= 3) {
          // Found a cycle of length 3-5
          const cycle = [...path];
          const key = [...cycle].sort().join(',');
          if (!foundCycleSet.has(key)) {
            foundCycleSet.add(key);
            cycles.push(cycle);
          }
        } else if (!path.includes(neighbor) && path.length < 5) {
          stack.push({ node: neighbor, path: [...path, neighbor] });
        }
      }
    }
  }

  // Assign ring IDs and build ring membership map
  const ringMap = new Map<string, string[]>();
  cycles.forEach((cycle, idx) => {
    const ringId = `RING_${String(idx + 1).padStart(3, '0')}`;
    for (const node of cycle) {
      if (!ringMap.has(node)) ringMap.set(node, []);
      ringMap.get(node)!.push(ringId);
    }
  });

  return { cycles, ringMap };
}

// ─── 2. FAN-IN DETECTION (Smurfing) ─────────────────────────────────────────
// Sliding 72-hour window: >=10 unique senders to same receiver
// Time complexity: O(T log T) for sort + O(T) for sliding window = O(T log T)
// where T = number of transactions for a given receiver

function detectFanIn(
  transactions: RawTransaction[],
  allNodes: string[]
): Map<string, { senders: Set<string>; windowStart: string; windowEnd: string }> {
  const fanInMap = new Map<string, { senders: Set<string>; windowStart: string; windowEnd: string }>();
  const window72h = 72 * 60 * 60 * 1000;

  // Group transactions by receiver
  const byReceiver = new Map<string, RawTransaction[]>();
  for (const tx of transactions) {
    if (!byReceiver.has(tx.receiver_id)) byReceiver.set(tx.receiver_id, []);
    byReceiver.get(tx.receiver_id)!.push(tx);
  }

  // For each receiver, use sliding window
  for (const [receiver, txs] of byReceiver) {
    const sorted = txs.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      const rightTime = new Date(sorted[right].timestamp).getTime();

      // Slide left pointer to maintain 72h window
      while (
        left < right &&
        rightTime - new Date(sorted[left].timestamp).getTime() > window72h
      ) {
        left++;
      }

      // Count unique senders in window
      const sendersInWindow = new Set<string>();
      for (let i = left; i <= right; i++) {
        sendersInWindow.add(sorted[i].sender_id);
      }

      if (sendersInWindow.size >= 10) {
        fanInMap.set(receiver, {
          senders: sendersInWindow,
          windowStart: sorted[left].timestamp,
          windowEnd: sorted[right].timestamp,
        });
        break; // Found fan-in for this receiver
      }
    }
  }

  return fanInMap;
}

// ─── 3. FAN-OUT DETECTION ────────────────────────────────────────────────────
// Sliding 72-hour window: >=10 unique receivers from same sender
// Time complexity: O(T log T) per sender group

function detectFanOut(
  transactions: RawTransaction[],
  allNodes: string[]
): Map<string, { receivers: Set<string>; windowStart: string; windowEnd: string }> {
  const fanOutMap = new Map<string, { receivers: Set<string>; windowStart: string; windowEnd: string }>();
  const window72h = 72 * 60 * 60 * 1000;

  // Group transactions by sender
  const bySender = new Map<string, RawTransaction[]>();
  for (const tx of transactions) {
    if (!bySender.has(tx.sender_id)) bySender.set(tx.sender_id, []);
    bySender.get(tx.sender_id)!.push(tx);
  }

  for (const [sender, txs] of bySender) {
    const sorted = txs.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      const rightTime = new Date(sorted[right].timestamp).getTime();

      while (
        left < right &&
        rightTime - new Date(sorted[left].timestamp).getTime() > window72h
      ) {
        left++;
      }

      const receiversInWindow = new Set<string>();
      for (let i = left; i <= right; i++) {
        receiversInWindow.add(sorted[i].receiver_id);
      }

      if (receiversInWindow.size >= 10) {
        fanOutMap.set(sender, {
          receivers: receiversInWindow,
          windowStart: sorted[left].timestamp,
          windowEnd: sorted[right].timestamp,
        });
        break;
      }
    }
  }

  return fanOutMap;
}

// ─── 4. SHELL CHAIN DETECTION ────────────────────────────────────────────────
// BFS-based: path length >= 3 hops, intermediate nodes have <= 3 total transactions
// Time complexity: O(V + E) BFS from each low-activity node

function detectShellChains(
  graph: AdjList,
  accountMap: Map<string, AccountNode>,
  transactions: RawTransaction[]
): { chains: string[][]; shellNodes: Set<string> } {
  const chains: string[][] = [];
  const shellNodes = new Set<string>();

  // Identify potential shell accounts (low transaction count)
  const lowActivityNodes = new Set<string>();
  for (const [id, account] of accountMap) {
    if (account.total_transactions <= 3) {
      lowActivityNodes.add(id);
    }
  }

  // BFS from each node, looking for paths through shell accounts
  for (const startNode of accountMap.keys()) {
    const visited = new Set<string>([startNode]);
    const queue: { node: string; path: string[] }[] = [
      { node: startNode, path: [startNode] },
    ];

    while (queue.length > 0) {
      const { node, path } = queue.shift()!;

      if (path.length > 6) continue; // Limit chain length

      const neighbors = graph.get(node);
      if (!neighbors) continue;

      for (const [neighbor] of neighbors) {
        if (visited.has(neighbor)) continue;
        visited.add(neighbor);

        const newPath = [...path, neighbor];

        // Check if this forms a shell chain (>=3 hops with shell intermediaries)
        if (newPath.length >= 4) {
          // path length 4 = 3 hops
          const intermediates = newPath.slice(1, -1);
          const allShell = intermediates.every((n) => lowActivityNodes.has(n));

          if (allShell && intermediates.length >= 1) {
            chains.push(newPath);
            intermediates.forEach((n) => shellNodes.add(n));
          }
        }

        // Continue BFS if next node is low-activity
        if (lowActivityNodes.has(neighbor) && newPath.length < 6) {
          queue.push({ node: neighbor, path: newPath });
        }
      }
    }
  }

  return { chains, shellNodes };
}

// ─── 5. SUSPICION SCORING ENGINE ─────────────────────────────────────────────
// Weighted: Cycle=+40, Fan-in=+30, Fan-out=+30, Shell chain=+35, High velocity=+15
// Cap at 100. False positive reduction for high-degree legitimate accounts.

function calculateSuspicionScores(
  accountMap: Map<string, AccountNode>,
  ringMap: Map<string, string[]>,
  fanInMap: Map<string, { senders: Set<string> }>,
  fanOutMap: Map<string, { receivers: Set<string> }>,
  shellNodes: Set<string>,
  transactions: RawTransaction[]
): void {
  for (const [id, account] of accountMap) {
    const scores: PatternScores = { fan_in: 0, fan_out: 0, cycle: 0, shell: 0, velocity: 0 };
    const patterns: string[] = [];
    const algorithms: string[] = [];
    const explanations: string[] = [];

    // Cycle participation: +40
    if (ringMap.has(id)) {
      scores.cycle += 40;
      patterns.push('cycle');
      algorithms.push('DFS Cycle Detection (Johnson variant)');
      explanations.push(
        `Part of ${ringMap.get(id)!.length} fraud ring(s): ${ringMap.get(id)!.join(', ')}`
      );
      account.ring_ids = ringMap.get(id)!;
    }

    // Fan-in: +30
    if (fanInMap.has(id)) {
      scores.fan_in += 30;
      patterns.push('fan_in');
      algorithms.push('72h Sliding Window Fan-In');
      explanations.push(
        `Received from ${fanInMap.get(id)!.senders.size} unique senders within 72h`
      );
    }

    // Fan-out: +30
    if (fanOutMap.has(id)) {
      scores.fan_out += 30;
      patterns.push('fan_out');
      algorithms.push('72h Sliding Window Fan-Out');
      explanations.push(
        `Sent to ${fanOutMap.get(id)!.receivers.size} unique receivers within 72h`
      );
    }

    // Shell chain: +35
    if (shellNodes.has(id)) {
      scores.shell += 35;
      patterns.push('shell_chain');
      algorithms.push('BFS Shell Chain Detection');
      explanations.push(
        `Intermediate node in shell chain with only ${account.total_transactions} total transactions`
      );
    }

    // High velocity: +15
    const accountTxs = transactions.filter(
      (tx) => tx.sender_id === id || tx.receiver_id === id
    );
    if (accountTxs.length > 0) {
      const timestamps = accountTxs.map((tx) => new Date(tx.timestamp).getTime());
      const timeSpan = Math.max(...timestamps) - Math.min(...timestamps);
      const days = Math.max(timeSpan / (1000 * 60 * 60 * 24), 1);
      const txPerDay = accountTxs.length / days;
      if (txPerDay > 15) {
        scores.velocity += 15;
        patterns.push('high_velocity');
        algorithms.push('Transaction Velocity Analysis');
        explanations.push(
          `High velocity: ${txPerDay.toFixed(1)} transactions/day`
        );
      }
    }

    // Compute total from individual pattern scores
    let score = scores.fan_in + scores.fan_out + scores.cycle + scores.shell + scores.velocity;

    // FALSE POSITIVE REDUCTION
    // If degree > 100, no cycles, consistent intervals -> reduce by 30
    const totalDegree = account.in_degree + account.out_degree;
    if (totalDegree > 100 && !ringMap.has(id)) {
      // Check consistent intervals
      if (accountTxs.length > 10) {
        const sorted = accountTxs
          .map((tx) => new Date(tx.timestamp).getTime())
          .sort((a, b) => a - b);
        const intervals: number[] = [];
        for (let i = 1; i < sorted.length; i++) {
          intervals.push(sorted[i] - sorted[i - 1]);
        }
        const avgInterval =
          intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const consistent = intervals.filter(
          (i) => Math.abs(i - avgInterval) / avgInterval < 0.3
        );
        if (consistent.length / intervals.length > 0.6) {
          score = Math.max(0, score - 30);
          algorithms.push('False Positive Dampening');
          explanations.push(
            `Score reduced by 30: High-degree node (${totalDegree}) with consistent transaction intervals (likely merchant)`
          );
        }
      }
    }

    // Cap at 100
    score = Math.min(score, 100);

    account.pattern_scores = scores;
    account.suspicion_score = score;
    account.detected_patterns = patterns;
    account.triggered_algorithms = algorithms;
    account.explanation = explanations.join('. ');
    account.is_suspicious = score > 0;
  }
}

// ─── 7. INTERCONNECTED MULE COMMUNITY DETECTION ─────────────────────────────
// Network-level money laundering detection via connected components on the
// suspicious subgraph.  Validates communities using multi-signal criteria
// (at least 2 INDEPENDENT fraud evidences) and promotes them into unified
// laundering rings.  Overlapping pattern-level rings within the same connected
// component are merged under a single community ring ID.
// Time complexity: O(V + E) over the suspicious subgraph (BFS)

interface CommunityResult {
  rings: FraudRing[];
  /** Account ID → community ring IDs (for updating account metadata) */
  membershipMap: Map<string, string[]>;
  /** Pattern-level ring IDs that were subsumed by each community ring */
  mergedRingMap: Map<string, string[]>;
}

function detectMuleCommunities(
  graph: AdjList,
  accountMap: Map<string, AccountNode>,
  cycles: string[][],
  fanInMap: Map<string, { senders: Set<string> }>,
  fanOutMap: Map<string, { receivers: Set<string> }>,
  shellChains: string[][],
  patternRings: FraudRing[],
): CommunityResult {
  // ── Step 1: Build suspicious subgraph ─────────────────────────────────
  // Nodes: accounts with suspicion_score > 0
  // Edges: directed edges where BOTH endpoints are suspicious

  const suspiciousIds = new Set<string>();
  for (const [id, account] of accountMap) {
    if (account.suspicion_score > 0) suspiciousIds.add(id);
  }

  // Undirected adjacency for the suspicious subgraph (for BFS)
  const suspAdj = new Map<string, Set<string>>();

  for (const nodeId of suspiciousIds) {
    if (!suspAdj.has(nodeId)) suspAdj.set(nodeId, new Set());
    const neighbors = graph.get(nodeId);
    if (!neighbors) continue;
    for (const [neighbor] of neighbors) {
      if (!suspiciousIds.has(neighbor)) continue;
      // Add undirected edge
      if (!suspAdj.has(neighbor)) suspAdj.set(neighbor, new Set());
      suspAdj.get(nodeId)!.add(neighbor);
      suspAdj.get(neighbor)!.add(nodeId);
    }
  }

  // ── Step 2: Find connected components via BFS ────────────────────────
  const visited = new Set<string>();
  const components: string[][] = [];

  for (const nodeId of suspiciousIds) {
    if (visited.has(nodeId)) continue;

    const component: string[] = [];
    const queue: string[] = [nodeId];
    visited.add(nodeId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      component.push(current);
      const adj = suspAdj.get(current);
      if (!adj) continue;
      for (const neighbor of adj) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }

    // Only consider components with ≥ 2 members
    if (component.length >= 2) components.push(component);
  }

  // ── Pre-compute pattern membership sets for fast lookup ──────────────
  const cycleNodes = new Set<string>();
  for (const cycle of cycles) {
    for (const n of cycle) cycleNodes.add(n);
  }
  const fanInNodes = new Set<string>();
  for (const [id] of fanInMap) fanInNodes.add(id);
  const fanOutNodes = new Set<string>();
  for (const [id] of fanOutMap) fanOutNodes.add(id);
  const shellNodeSet = new Set<string>();
  for (const chain of shellChains) {
    for (const n of chain) shellNodeSet.add(n);
  }

  // ── Pre-compute: which pattern-level ring IDs each account belongs to ─
  // Used later to merge overlapping rings under one community ring
  const accountToPatternRings = new Map<string, Set<string>>();
  for (const ring of patternRings) {
    for (const memberId of ring.members) {
      if (!accountToPatternRings.has(memberId)) {
        accountToPatternRings.set(memberId, new Set());
      }
      accountToPatternRings.get(memberId)!.add(ring.ring_id);
    }
  }

  // ── Step 3 & 4: Validate components and build community rings ────────
  const communityRings: FraudRing[] = [];
  const membershipMap = new Map<string, string[]>();
  const mergedRingMap = new Map<string, string[]>();
  let commIdx = 0;

  for (const component of components) {
    const compSet = new Set(component);

    // Count directed edges within this component
    let internalEdges = 0;
    for (const nodeId of component) {
      const neighbors = graph.get(nodeId);
      if (!neighbors) continue;
      for (const [neighbor] of neighbors) {
        if (compSet.has(neighbor)) internalEdges++;
      }
    }

    // ── Independent fraud evidence validation ──────────────────────────
    // Each evidence type is counted as ONE independent signal regardless
    // of how many nodes satisfy it.  A component is valid only when at
    // least TWO distinct evidence categories are present.

    const evidences: string[] = [];

    // Evidence 1: Contains ≥ 1 cycle ring member
    const cycleCount = component.filter(n => cycleNodes.has(n)).length;
    if (cycleCount >= 1) evidences.push('cycle');

    // Evidence 2: Contains ≥ 1 fan-in pattern
    const fanInCount = component.filter(n => fanInNodes.has(n)).length;
    if (fanInCount >= 1) evidences.push('fan_in');

    // Evidence 3: Contains ≥ 1 fan-out pattern
    const fanOutCount = component.filter(n => fanOutNodes.has(n)).length;
    if (fanOutCount >= 1) evidences.push('fan_out');

    // Evidence 4: Contains ≥ 1 shell chain node
    const shellChainCount = component.filter(n => shellNodeSet.has(n)).length;
    if (shellChainCount >= 1) evidences.push('shell_chain');

    // Evidence 5: Contains ≥ 1 bridge node (connected to ≥ 2 suspicious neighbors)
    const bridgeCount = component.filter(n => {
      const adj = suspAdj.get(n);
      return adj !== undefined && adj.size >= 2;
    }).length;
    if (bridgeCount >= 1) evidences.push('bridge');

    // Evidence 6: Edge density ≥ 1 (directed edges >= nodes)
    if (internalEdges >= component.length) evidences.push('density');

    // ── Require at least 2 INDEPENDENT evidence categories ─────────────
    if (evidences.length < 2) continue;

    commIdx++;
    const ringId = `RING_COMM_${String(commIdx).padStart(3, '0')}`;

    // ── Merge overlapping pattern-level rings ──────────────────────────
    // Collect ALL pattern-level ring IDs whose members fall into this
    // connected component.  They are subsumed under the community ring.
    const subsumedRingIds = new Set<string>();
    for (const memberId of component) {
      const pRings = accountToPatternRings.get(memberId);
      if (pRings) {
        for (const pRingId of pRings) subsumedRingIds.add(pRingId);
      }
    }
    mergedRingMap.set(ringId, Array.from(subsumedRingIds));

    // ── Step 5: Compute community risk score ───────────────────────────
    const fanPatternCount = fanInCount + fanOutCount;
    const maxScore = Math.max(
      ...component.map(id => accountMap.get(id)?.suspicion_score ?? 0)
    );
    const riskScore = Math.min(
      100,
      maxScore
        + 10 * cycleCount
        + 8 * fanPatternCount
        + 6 * shellChainCount,
    );

    // Total value of internal transactions
    let totalValue = 0;
    for (const nodeId of component) {
      const neighbors = graph.get(nodeId);
      if (!neighbors) continue;
      for (const [neighbor, txs] of neighbors) {
        if (compSet.has(neighbor)) {
          for (const tx of txs) totalValue += tx.amount;
        }
      }
    }

    const explanationParts: string[] = [
      `Interconnected mule community of ${component.length} suspicious accounts`,
      `${internalEdges} internal edges`,
      `Evidence: ${evidences.join(', ')}`,
    ];
    if (cycleCount > 0) explanationParts.push(`${cycleCount} cycle member(s)`);
    if (fanInCount > 0) explanationParts.push(`${fanInCount} fan-in node(s)`);
    if (fanOutCount > 0) explanationParts.push(`${fanOutCount} fan-out node(s)`);
    if (shellChainCount > 0) explanationParts.push(`${shellChainCount} shell chain node(s)`);
    if (bridgeCount > 0) explanationParts.push(`${bridgeCount} bridge node(s)`);
    if (subsumedRingIds.size > 0) {
      explanationParts.push(
        `Merges pattern-level rings: ${Array.from(subsumedRingIds).join(', ')}`
      );
    }
    explanationParts.push(`Total internal value: $${Math.round(totalValue).toLocaleString()}`);

    communityRings.push({
      ring_id: ringId,
      pattern_type: 'community',
      members: component,
      member_count: component.length,
      risk_score: Math.round(riskScore),
      total_value: Math.round(totalValue * 100) / 100,
      explanation: explanationParts.join('. ') + '.',
    });

    // Record membership for account updates
    for (const memberId of component) {
      if (!membershipMap.has(memberId)) membershipMap.set(memberId, []);
      membershipMap.get(memberId)!.push(ringId);
    }
  }

  return { rings: communityRings, membershipMap, mergedRingMap };
}

// ─── BUILD FRAUD RINGS ───────────────────────────────────────────────────────

function buildFraudRings(
  cycles: string[][],
  fanInMap: Map<string, { senders: Set<string> }>,
  fanOutMap: Map<string, { receivers: Set<string> }>,
  shellChains: string[][],
  accountMap: Map<string, AccountNode>,
  transactions: RawTransaction[]
): FraudRing[] {
  const rings: FraudRing[] = [];
  let ringCounter = 0;

  // Cycle rings
  for (const cycle of cycles) {
    ringCounter++;
    const ringId = `RING_${String(ringCounter).padStart(3, '0')}`;
    const txsInCycle: RawTransaction[] = [];
    for (let i = 0; i < cycle.length; i++) {
      const from = cycle[i];
      const to = cycle[(i + 1) % cycle.length];
      const matching = transactions.filter(
        (tx) => tx.sender_id === from && tx.receiver_id === to
      );
      txsInCycle.push(...matching);
    }
    const totalValue = txsInCycle.reduce((sum, tx) => sum + tx.amount, 0);
    const avgScore =
      cycle.reduce(
        (sum, id) => sum + (accountMap.get(id)?.suspicion_score || 0),
        0
      ) / cycle.length;

    rings.push({
      ring_id: ringId,
      pattern_type: 'cycle',
      members: cycle,
      member_count: cycle.length,
      risk_score: Math.round(avgScore),
      total_value: totalValue,
      explanation: `Cycle of ${cycle.length} accounts: ${cycle.join(' -> ')} -> ${cycle[0]}. Total value: $${totalValue.toLocaleString()}.`,
    });
  }

  // Fan-in rings
  for (const [receiver, data] of fanInMap) {
    ringCounter++;
    const ringId = `RING_${String(ringCounter).padStart(3, '0')}`;
    const members = [receiver, ...data.senders];
    const avgScore =
      members.reduce(
        (sum, id) => sum + (accountMap.get(id)?.suspicion_score || 0),
        0
      ) / members.length;

    rings.push({
      ring_id: ringId,
      pattern_type: 'fan_in',
      members,
      member_count: members.length,
      risk_score: Math.round(avgScore),
      total_value: 0,
      explanation: `Fan-in: ${data.senders.size} unique senders to ${receiver} within 72h.`,
    });
  }

  // Fan-out rings
  for (const [sender, data] of fanOutMap) {
    ringCounter++;
    const ringId = `RING_${String(ringCounter).padStart(3, '0')}`;
    const members = [sender, ...data.receivers];
    const avgScore =
      members.reduce(
        (sum, id) => sum + (accountMap.get(id)?.suspicion_score || 0),
        0
      ) / members.length;

    rings.push({
      ring_id: ringId,
      pattern_type: 'fan_out',
      members,
      member_count: members.length,
      risk_score: Math.round(avgScore),
      total_value: 0,
      explanation: `Fan-out: ${sender} sent to ${data.receivers.size} unique receivers within 72h.`,
    });
  }

  // Shell chain rings (deduplicate by unique sets of nodes)
  const seenShellSets = new Set<string>();
  for (const chain of shellChains) {
    const key = [...chain].sort().join(',');
    if (seenShellSets.has(key)) continue;
    seenShellSets.add(key);

    ringCounter++;
    const ringId = `RING_${String(ringCounter).padStart(3, '0')}`;
    const avgScore =
      chain.reduce(
        (sum, id) => sum + (accountMap.get(id)?.suspicion_score || 0),
        0
      ) / chain.length;

    rings.push({
      ring_id: ringId,
      pattern_type: 'shell_chain',
      members: chain,
      member_count: chain.length,
      risk_score: Math.round(avgScore),
      total_value: 0,
      explanation: `Shell chain: ${chain.join(' -> ')}. Intermediate nodes have <= 3 total transactions.`,
    });
  }

  // Sort by risk_score descending
  return rings.sort((a, b) => b.risk_score - a.risk_score);
}

// ─── BUILD CYTOSCAPE GRAPH DATA ──────────────────────────────────────────────

function buildCytoscapeData(
  accountMap: Map<string, AccountNode>,
  transactions: RawTransaction[],
  fanInMap: Map<string, { senders: Set<string>; windowStart: string; windowEnd: string }>,
  fanOutMap: Map<string, { receivers: Set<string>; windowStart: string; windowEnd: string }>,
  shellChains: string[][],
  cycles: string[][],
  ringMap: Map<string, string[]>
): CytoscapeGraphData {
  // Build per-node fan-in transactions (latest 10)
  const nodeFanInTxs = new Map<string, FanInTransaction[]>();
  for (const [receiver, data] of fanInMap) {
    const relevant = transactions
      .filter(tx => tx.receiver_id === receiver && data.senders.has(tx.sender_id))
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 10)
      .map(tx => ({
        sender_id: tx.sender_id,
        receiver_id: tx.receiver_id,
        amount: tx.amount,
        timestamp: tx.timestamp,
      }));
    nodeFanInTxs.set(receiver, relevant);
  }

  // Build per-node shell chain paths
  const nodeShellPaths = new Map<string, ShellChainPath[]>();
  for (const chain of shellChains) {
    const hops: ShellChainPath['hops'] = [];
    for (let i = 0; i < chain.length - 1; i++) {
      const hop = transactions.find(
        tx => tx.sender_id === chain[i] && tx.receiver_id === chain[i + 1]
      );
      hops.push({
        from: chain[i],
        to: chain[i + 1],
        amount: hop?.amount ?? 0,
        timestamp: hop?.timestamp ?? '',
      });
    }
    const shellPath: ShellChainPath = { path: chain, hops };
    for (const nodeId of chain) {
      if (!nodeShellPaths.has(nodeId)) nodeShellPaths.set(nodeId, []);
      nodeShellPaths.get(nodeId)!.push(shellPath);
    }
  }

  // Build pattern membership for edges
  const cycleEdges = new Set<string>();
  for (const cycle of cycles) {
    for (let i = 0; i < cycle.length; i++) {
      cycleEdges.add(`${cycle[i]}->${cycle[(i + 1) % cycle.length]}`);
    }
  }
  const fanInEdges = new Set<string>();
  for (const [receiver, data] of fanInMap) {
    for (const sender of data.senders) {
      fanInEdges.add(`${sender}->${receiver}`);
    }
  }
  const fanOutEdges = new Set<string>();
  for (const [sender, data] of fanOutMap) {
    for (const receiver of data.receivers) {
      fanOutEdges.add(`${sender}->${receiver}`);
    }
  }
  const shellEdges = new Set<string>();
  for (const chain of shellChains) {
    for (let i = 0; i < chain.length - 1; i++) {
      shellEdges.add(`${chain[i]}->${chain[i + 1]}`);
    }
  }

  const nodes = Array.from(accountMap.values()).map((account) => ({
    data: {
      id: account.account_id,
      label: account.account_id,
      suspicion_score: account.suspicion_score,
      is_suspicious: account.is_suspicious,
      detected_patterns: account.detected_patterns,
      ring_ids: account.ring_ids,
      in_degree: account.in_degree,
      out_degree: account.out_degree,
      total_amount_sent: account.total_amount_sent,
      total_amount_received: account.total_amount_received,
      total_transactions: account.total_transactions,
      explanation: account.explanation,
      fan_in_transactions: nodeFanInTxs.get(account.account_id) || [],
      shell_chain_paths: nodeShellPaths.get(account.account_id) || [],
    },
  }));

  // Aggregate edges with pattern types and latest timestamp
  const edgeMap = new Map<
    string,
    { amount: number; count: number; source: string; target: string; latestTs: string; patternTypes: Set<string> }
  >();
  for (const tx of transactions) {
    const key = `${tx.sender_id}->${tx.receiver_id}`;
    if (!edgeMap.has(key)) {
      edgeMap.set(key, {
        amount: 0,
        count: 0,
        source: tx.sender_id,
        target: tx.receiver_id,
        latestTs: tx.timestamp,
        patternTypes: new Set(),
      });
    }
    const edge = edgeMap.get(key)!;
    edge.amount += tx.amount;
    edge.count++;
    if (tx.timestamp > edge.latestTs) edge.latestTs = tx.timestamp;
  }

  // Assign pattern types to edges
  for (const [key, edge] of edgeMap) {
    if (cycleEdges.has(key)) edge.patternTypes.add('cycle');
    if (fanInEdges.has(key)) edge.patternTypes.add('fan_in');
    if (fanOutEdges.has(key)) edge.patternTypes.add('fan_out');
    if (shellEdges.has(key)) edge.patternTypes.add('shell_chain');
  }

  const edges = Array.from(edgeMap.entries()).map(([key, data]) => ({
    data: {
      id: key,
      source: data.source,
      target: data.target,
      amount: Math.round(data.amount * 100) / 100,
      transaction_count: data.count,
      label: `$${data.amount.toLocaleString()} (${data.count}x)`,
      timestamp: data.latestTs,
      pattern_types: Array.from(data.patternTypes),
    },
  }));

  return { nodes, edges };
}

// ─── MAIN ANALYSIS FUNCTION ──────────────────────────────────────────────────

export function analyzeTransactions(
  transactions: RawTransaction[],
  mode: DetectionMode = 'all'
): AnalysisResult {
  const startTime = performance.now();

  // Build adjacency list - O(T)
  const graph = buildAdjacencyList(transactions);
  const allNodes = Array.from(graph.keys());

  // Build account map - O(T)
  const accountMap = new Map<string, AccountNode>();
  for (const nodeId of allNodes) {
    accountMap.set(nodeId, {
      account_id: nodeId,
      total_transactions: 0,
      in_degree: 0,
      out_degree: 0,
      total_amount_sent: 0,
      total_amount_received: 0,
      suspicion_score: 0,
      pattern_scores: { fan_in: 0, fan_out: 0, cycle: 0, shell: 0, velocity: 0 },
      detected_patterns: [],
      ring_ids: [],
      triggered_algorithms: [],
      explanation: '',
      is_suspicious: false,
    });
  }

  // Compute per-node metrics - O(T)
  for (const tx of transactions) {
    const sender = accountMap.get(tx.sender_id)!;
    sender.total_transactions++;
    sender.total_amount_sent += tx.amount;

    const receiver = accountMap.get(tx.receiver_id)!;
    receiver.total_transactions++;
    receiver.total_amount_received += tx.amount;
  }

  // Compute degrees - O(V + E)
  for (const [nodeId, neighbors] of graph) {
    const account = accountMap.get(nodeId)!;
    account.out_degree = neighbors.size;
  }
  for (const [, neighbors] of graph) {
    for (const [target] of neighbors) {
      const account = accountMap.get(target)!;
      account.in_degree++;
    }
  }

  // Run detection algorithms — skip expensive ones when mode targets a single pattern
  const runCycles   = mode === 'all' || mode === 'cycles';
  const runFanIn    = mode === 'all' || mode === 'fan-in';
  const runFanOut   = mode === 'all' || mode === 'fan-out';
  const runShell    = mode === 'all' || mode === 'shell';

  const { cycles, ringMap } = runCycles
    ? detectCycles(graph, allNodes)
    : { cycles: [] as string[][], ringMap: new Map<string, string[]>() };

  const fanInMap = runFanIn
    ? detectFanIn(transactions, allNodes)
    : new Map<string, { senders: Set<string>; windowStart: string; windowEnd: string }>();

  const fanOutMap = runFanOut
    ? detectFanOut(transactions, allNodes)
    : new Map<string, { receivers: Set<string>; windowStart: string; windowEnd: string }>();

  const { chains: shellChains, shellNodes } = runShell
    ? detectShellChains(graph, accountMap, transactions)
    : { chains: [] as string[][], shellNodes: new Set<string>() };

  // Calculate suspicion scores
  calculateSuspicionScores(
    accountMap,
    ringMap,
    fanInMap,
    fanOutMap,
    shellNodes,
    transactions
  );

  // Build fraud rings
  const fraudRings = buildFraudRings(
    cycles,
    fanInMap,
    fanOutMap,
    shellChains,
    accountMap,
    transactions
  );

  // Update ring_ids on accounts from fraudRings
  for (const ring of fraudRings) {
    for (const memberId of ring.members) {
      const account = accountMap.get(memberId);
      if (account && !account.ring_ids.includes(ring.ring_id)) {
        account.ring_ids.push(ring.ring_id);
      }
    }
  }

  // ── Relationship Intelligence Layer ──────────────────────────────────────
  // Final adjustment: reduce false positives for legitimate recurring
  // relationships (rent, payroll, subscriptions).  Runs AFTER all pattern
  // detection and scoring.  Never modifies accounts in fraud cycles.
  const cycleMembers = new Set<string>();
  for (const cycle of cycles) {
    for (const nodeId of cycle) {
      cycleMembers.add(nodeId);
    }
  }
  adjustScoresUsingRelationshipIntelligence(
    Array.from(accountMap.values()),
    transactions,
    cycleMembers,
  );

  // ── Temporal Cycle Validation ──────────────────────────────────────────
  // Verify chronological ordering and amount continuity for cycle-type
  // rings.  Invalid cycles are removed and member scores adjusted.
  validateTemporalCycles(
    Array.from(accountMap.values()),
    fraudRings,
    cycles,
    transactions,
  );

  // ── Ring Leadership Detection (Betweenness Centrality) ─────────────────
  // Assigns ORCHESTRATOR / INTERMEDIARY / PERIPHERAL roles within each
  // remaining fraud ring.  Orchestrators receive a +10 score boost.
  analyzeRingLeadership(
    Array.from(accountMap.values()),
    fraudRings,
    transactions,
  );

  // ── Multi-Stage Laundering Flow Detection ──────────────────────────────
  // Flags accounts that span ≥2 distinct pattern types with +20 boost.
  detectMultiStageFlows(
    Array.from(accountMap.values()),
    fraudRings,
    transactions,
  );

  // ── Algorithm 7: Interconnected Mule Community Detection ───────────────
  // Runs after all scoring so it can inspect final suspicion_score.
  // Detects coordinated laundering networks via connected components on the
  // suspicious subgraph.  Validates with ≥ 2 independent evidence categories.
  // Merges overlapping pattern-level rings under a single community ring ID.
  const { rings: communityRings, membershipMap: communityMembership, mergedRingMap } =
    detectMuleCommunities(
      graph,
      accountMap,
      cycles,
      fanInMap,
      fanOutMap,
      shellChains,
      fraudRings,
    );

  // Append community rings to the existing fraud rings list
  fraudRings.push(...communityRings);

  // Update account metadata with community ring IDs and algorithm tag.
  // Replace subsumed pattern-level ring IDs with the community ring ID
  // so accounts show a single unified community membership.
  for (const [accountId, commRingIds] of communityMembership) {
    const account = accountMap.get(accountId);
    if (!account) continue;

    // Determine which pattern-level ring IDs this community subsumes
    const allSubsumed = new Set<string>();
    for (const crid of commRingIds) {
      const subsumed = mergedRingMap.get(crid);
      if (subsumed) {
        for (const rid of subsumed) allSubsumed.add(rid);
      }
    }

    // Replace subsumed pattern-level ring IDs with community ring IDs
    account.ring_ids = account.ring_ids.filter(rid => !allSubsumed.has(rid));
    for (const rid of commRingIds) {
      if (!account.ring_ids.includes(rid)) account.ring_ids.push(rid);
    }

    if (!account.detected_patterns.includes('community')) {
      account.detected_patterns.push('community');
    }
    if (!account.triggered_algorithms.includes('Mule Community Detection (BFS Components)')) {
      account.triggered_algorithms.push('Mule Community Detection (BFS Components)');
    }
    account.explanation += ` | Community member: ${commRingIds.join(', ')}`;
  }

  // Re-sort fraud rings by risk_score descending after adding community rings
  fraudRings.sort((a, b) => b.risk_score - a.risk_score);

  // ── Two-Phase Fan-In Validation ──────────────────────────────────────────────────────
  // Phase 1: Identify aggregation candidates (fan-in without fraud flag).
  // Phase 2: Upgrade to confirmed_money_laundering only if corroborated by
  //   shell chain involvement, cycle participation, rapid outflow, or role
  //   conflict.  Does not modify existing scores or detection outputs.
  validateFanInTwoPhase(
    Array.from(accountMap.values()),
    transactions,
    graph,
    cycles,
    shellChains,
    fanOutMap,
  );

  // Build Cytoscape data with detection results
  const graphData = buildCytoscapeData(
    accountMap,
    transactions,
    fanInMap,
    fanOutMap,
    shellChains,
    cycles,
    ringMap
  );

  const endTime = performance.now();
  const processingTime =
    Math.round(((endTime - startTime) / 1000) * 1000) / 1000;

  // Sort accounts by suspicion_score descending
  const accounts = Array.from(accountMap.values()).sort(
    (a, b) => b.suspicion_score - a.suspicion_score
  );

  // Build strict hackathon JSON output
  const suspiciousAccounts = accounts
    .filter((a) => a.suspicion_score > 0)
    .map((a) => ({
      account_id: a.account_id,
      suspicion_score: a.suspicion_score,
      detected_patterns: a.detected_patterns,
      ring_id: a.ring_ids[0] || '',
      triggered_algorithms: a.triggered_algorithms,
      explanation: a.explanation,
    }));

  const hackathonOutput: HackathonOutput = {
    suspicious_accounts: suspiciousAccounts,
    fraud_rings: fraudRings.map((r) => ({
      ring_id: r.ring_id,
      pattern_type: r.pattern_type,
      member_accounts: r.members,
      member_count: r.member_count,
      risk_score: r.risk_score,
    })),
    summary: {
      total_accounts_analyzed: accounts.length,
      total_transactions: transactions.length,
      suspicious_accounts_flagged: suspiciousAccounts.length,
      fraud_rings_detected: fraudRings.length,
      processing_time_seconds: processingTime,
    },
  };

  return {
    accounts,
    transactions,
    fraudRings,
    summary: hackathonOutput.summary,
    hackathonOutput,
    graphData,
  };
}
