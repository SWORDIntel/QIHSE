export interface QihseNode {
  id: string;
  name: string;
  cluster: string;
  clusterType: string;
  host: string;
  port: number;
  role: string;
  status: string;
  architecture: string;
  isaCapabilities: string[];
  shardSlots: string;
  pingMs: number;
  memoryBytes: number;
  qps: number;
  networkTier: string;
}

export interface TelemetryFrame {
  timestamp: number;
  qps: number;
  latencyP50Us: number;
  latencyP95Us: number;
  latencyP99Us: number;
  activeVectors: number;
  totalOperations: number;
  nodes: QihseNode[];
  activeSlots: number;
  clusterState: string;
}

export interface SlotRange {
  start: number;
  end: number;
  masterNodeId: string;
}

export interface VectorSearchResult {
  id: number;
  distance: number;
  latencyUs: number;
  precisionUsed: string;
  hardwareAccelerated: boolean;
  acceleratorUsed: string;
}
