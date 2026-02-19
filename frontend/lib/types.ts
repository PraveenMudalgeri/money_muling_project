// RIFT 2026 Hackathon - Money Muling Detection Engine Types
// Strict compliance with required CSV structure and JSON output format

// Detection mode — controls which algorithms the backend runs
export type DetectionMode = 'all' | 'fan-in' | 'fan-out' | 'cycles' | 'shell';

// Per-pattern score breakdown
export interface PatternScores {
  fan_in: number;
  fan_out: number;
  cycle: number;
  shell: number;
  velocity: number;
}

export interface RawTransaction {
  transaction_id: string;
  sender_id: string;
  receiver_id: string;
  amount: number;
  timestamp: string; // YYYY-MM-DD HH:MM:SS
}

export interface AccountNode {
  account_id: string;
  total_transactions: number;
  in_degree: number;
  out_degree: number;
  total_amount_sent: number;
  total_amount_received: number;
  suspicion_score: number;
  pattern_scores: PatternScores;
  detected_patterns: string[];
  ring_ids: string[];
  triggered_algorithms: string[];
  explanation: string;
  is_suspicious: boolean;
}

export interface FraudRing {
  ring_id: string;
  pattern_type: 'cycle' | 'fan_in' | 'fan_out' | 'shell_chain';
  members: string[];
  member_count: number;
  risk_score: number;
  total_value: number;
  explanation: string;
}

// Strict JSON output format per hackathon spec
export interface HackathonOutput {
  suspicious_accounts: SuspiciousAccount[];
  fraud_rings: FraudRingOutput[];
  summary: SummaryOutput;
}

export interface SuspiciousAccount {
  account_id: string;
  suspicion_score: number; // 0-100
  detected_patterns: string[];
  ring_ids: string[];
  triggered_algorithms: string[];
  explanation: string;
}

export interface FraudRingOutput {
  ring_id: string;
  pattern_type: string;
  members: string[];
  member_count: number;
  risk_score: number;
}

export interface SummaryOutput {
  total_accounts: number;
  total_transactions: number;
  total_suspicious_accounts: number;
  total_fraud_rings: number;
  processing_time_seconds: number;
}

// Internal analysis result
export interface AnalysisResult {
  accounts: AccountNode[];
  transactions: RawTransaction[];
  fraudRings: FraudRing[];
  summary: SummaryOutput;
  hackathonOutput: HackathonOutput;
  graphData: CytoscapeGraphData;
}

// Cytoscape graph data
export interface CytoscapeGraphData {
  nodes: CytoscapeNode[];
  edges: CytoscapeEdge[];
}

export interface CytoscapeNode {
  data: {
    id: string;
    label: string;
    suspicion_score: number;
    is_suspicious: boolean;
    detected_patterns: string[];
    ring_ids: string[];
    in_degree: number;
    out_degree: number;
    total_amount_sent: number;
    total_amount_received: number;
    total_transactions: number;
    explanation: string;
    fan_in_transactions: FanInTransaction[];
    shell_chain_paths: ShellChainPath[];
  };
}

export interface CytoscapeEdge {
  data: {
    id: string;
    source: string;
    target: string;
    amount: number;
    transaction_count: number;
    label: string;
    timestamp?: string;
    pattern_types: string[];
  };
}

export interface FanInTransaction {
  sender_id: string;
  receiver_id: string;
  amount: number;
  timestamp: string;
}

export interface ShellChainPath {
  path: string[];
  hops: { from: string; to: string; amount: number; timestamp: string }[];
}
