/**
 * Centralized demo data for all dashboard pages.
 * When demo mode is ON, components use these static datasets instead of Supabase queries.
 * When demo mode is OFF, all demo data is discarded and components fetch real data.
 */

const now = new Date();
const ago = (minutes: number) => new Date(now.getTime() - minutes * 60000).toISOString();

// ─── Incidents ──────────────────────────────────────────────
export const demoScoredIncidents = [
  { id: 'demo-si-1', source_ip: '10.0.1.45', total_score: 92, alert_count: 8, attack_types: ['Port Scan', 'Exploit'], severity: 'critical', first_alert_at: ago(120), last_alert_at: ago(5), status: 'open', alert_ids: ['a1', 'a2', 'a3'], sequence_pattern: 'recon_to_exploit', created_at: ago(120), updated_at: ago(5) },
  { id: 'demo-si-2', source_ip: '192.168.2.100', total_score: 74, alert_count: 5, attack_types: ['DDoS'], severity: 'high', first_alert_at: ago(90), last_alert_at: ago(15), status: 'open', alert_ids: ['a4', 'a5'], sequence_pattern: null, created_at: ago(90), updated_at: ago(15) },
  { id: 'demo-si-3', source_ip: '172.16.0.22', total_score: 55, alert_count: 3, attack_types: ['Malware', 'Beaconing'], severity: 'medium', first_alert_at: ago(200), last_alert_at: ago(60), status: 'investigating', alert_ids: ['a6'], sequence_pattern: 'install_to_c2', created_at: ago(200), updated_at: ago(60) },
  { id: 'demo-si-4', source_ip: '10.0.3.88', total_score: 38, alert_count: 2, attack_types: ['Port Scan'], severity: 'low', first_alert_at: ago(300), last_alert_at: ago(180), status: 'open', alert_ids: ['a7'], sequence_pattern: null, created_at: ago(300), updated_at: ago(180) },
];

export const demoIncidentLogs = [
  { id: 'demo-il-1', incident_type: 'Port Scan + Exploit Attempt', severity: 'critical', source_ip: '10.0.1.45', destination_ip: '10.0.1.1', source_port: 54321, destination_port: 443, protocol: 'TCP', status: 'investigating', created_at: ago(120), details: { threat_score: 92 }, raw_data: null, assigned_to: 'analyst-1', resolution: null, resolved_at: null, rule_id: null, signature_id: null },
  { id: 'demo-il-2', incident_type: 'DDoS Attack', severity: 'high', source_ip: '192.168.2.100', destination_ip: '10.0.1.1', source_port: 80, destination_port: 80, protocol: 'UDP', status: 'pending', created_at: ago(90), details: { threat_score: 74 }, raw_data: null, assigned_to: null, resolution: null, resolved_at: null, rule_id: null, signature_id: null },
  { id: 'demo-il-3', incident_type: 'Malware C2 Communication', severity: 'medium', source_ip: '172.16.0.22', destination_ip: '203.0.113.50', source_port: 49200, destination_port: 8443, protocol: 'TCP', status: 'resolved', created_at: ago(200), details: { threat_score: 55, anomaly_score: 0.8 }, raw_data: null, assigned_to: 'analyst-2', resolution: 'Blocked C2 domain', resolved_at: ago(30), rule_id: null, signature_id: null },
];

export const demoResponseActions = [
  { id: 'demo-ra-1', action_type: 'block_ip', target_ip: '10.0.1.45', target_host: null, incident_id: 'demo-il-1', scored_incident_id: null, status: 'completed', triggered_by: 'dashboard', parameters: {}, result: { success: true }, created_at: ago(100), completed_at: ago(99) },
  { id: 'demo-ra-2', action_type: 'rate_limit', target_ip: '192.168.2.100', target_host: null, incident_id: null, scored_incident_id: 'demo-si-2', status: 'executing', triggered_by: 'automated', parameters: { rate: 100 }, result: null, created_at: ago(10), completed_at: null },
];

// ─── Assets ─────────────────────────────────────────────────
export const demoAssets = [
  { id: 'demo-a-1', ip_address: '10.0.1.1', hostname: 'gateway-01', device_type: 'firewall', os: 'PAN-OS 11.1', owner: 'NetOps', department: 'Infrastructure', criticality: 'critical', is_active: true, last_seen: ago(2), first_seen: ago(43200), mac_address: 'AA:BB:CC:DD:EE:01', open_ports: [443, 22, 8443], services: ['HTTPS', 'SSH', 'Management'], notes: 'Primary perimeter firewall' },
  { id: 'demo-a-2', ip_address: '10.0.1.10', hostname: 'web-prod-01', device_type: 'linux_server', os: 'Ubuntu 22.04 LTS', owner: 'DevOps', department: 'Engineering', criticality: 'high', is_active: true, last_seen: ago(1), first_seen: ago(20160), mac_address: 'AA:BB:CC:DD:EE:02', open_ports: [80, 443, 22], services: ['Nginx', 'SSH'], notes: null },
  { id: 'demo-a-3', ip_address: '10.0.1.20', hostname: 'db-primary', device_type: 'database_server', os: 'Ubuntu 20.04', owner: 'DBA Team', department: 'Engineering', criticality: 'critical', is_active: true, last_seen: ago(3), first_seen: ago(30000), mac_address: 'AA:BB:CC:DD:EE:03', open_ports: [5432, 22], services: ['PostgreSQL', 'SSH'], notes: 'Primary database' },
  { id: 'demo-a-4', ip_address: '10.0.2.50', hostname: 'ws-jdoe', device_type: 'windows_workstation', os: 'Windows 11 Pro', owner: 'John Doe', department: 'Finance', criticality: 'medium', is_active: true, last_seen: ago(30), first_seen: ago(10000), mac_address: 'AA:BB:CC:DD:EE:04', open_ports: [3389, 445], services: ['RDP', 'SMB'], notes: null },
  { id: 'demo-a-5', ip_address: '10.0.2.51', hostname: 'ws-asmith', device_type: 'linux_endpoint', os: 'Fedora 39', owner: 'Alice Smith', department: 'Engineering', criticality: 'medium', is_active: true, last_seen: ago(10), first_seen: ago(5000), mac_address: 'AA:BB:CC:DD:EE:05', open_ports: [22], services: ['SSH'], notes: null },
  { id: 'demo-a-6', ip_address: '10.0.3.1', hostname: 'switch-core-01', device_type: 'switch', os: 'Cisco IOS 17.x', owner: 'NetOps', department: 'Infrastructure', criticality: 'high', is_active: true, last_seen: ago(5), first_seen: ago(50000), mac_address: 'AA:BB:CC:DD:EE:06', open_ports: [22, 161], services: ['SSH', 'SNMP'], notes: 'Core switch' },
  { id: 'demo-a-7', ip_address: '10.0.4.100', hostname: 'printer-lobby', device_type: 'printer', os: null, owner: 'Facilities', department: 'Operations', criticality: 'low', is_active: false, last_seen: ago(2880), first_seen: ago(40000), mac_address: 'AA:BB:CC:DD:EE:07', open_ports: [9100, 631], services: ['RAW', 'IPP'], notes: 'Offline - maintenance' },
];

// ─── Network Topology ───────────────────────────────────────
export const demoTopologyEdges = [
  { id: 'demo-te-1', source_ip: '10.0.1.1', destination_ip: '10.0.1.10', connection_count: 4520, protocols: ['TCP', 'HTTPS'], bytes_transferred: 2_500_000_000, first_seen: ago(10000), last_seen: ago(1) },
  { id: 'demo-te-2', source_ip: '10.0.1.1', destination_ip: '10.0.1.20', connection_count: 1200, protocols: ['TCP'], bytes_transferred: 800_000_000, first_seen: ago(10000), last_seen: ago(2) },
  { id: 'demo-te-3', source_ip: '10.0.1.10', destination_ip: '10.0.1.20', connection_count: 8900, protocols: ['TCP', 'PostgreSQL'], bytes_transferred: 5_200_000_000, first_seen: ago(10000), last_seen: ago(1) },
  { id: 'demo-te-4', source_ip: '10.0.2.50', destination_ip: '10.0.1.10', connection_count: 320, protocols: ['HTTPS'], bytes_transferred: 150_000_000, first_seen: ago(5000), last_seen: ago(30) },
  { id: 'demo-te-5', source_ip: '10.0.2.51', destination_ip: '10.0.1.10', connection_count: 780, protocols: ['SSH', 'HTTPS'], bytes_transferred: 420_000_000, first_seen: ago(3000), last_seen: ago(10) },
  { id: 'demo-te-6', source_ip: '10.0.2.50', destination_ip: '10.0.3.1', connection_count: 90, protocols: ['SMB'], bytes_transferred: 45_000_000, first_seen: ago(4000), last_seen: ago(60) },
  { id: 'demo-te-7', source_ip: '10.0.1.45', destination_ip: '10.0.1.1', connection_count: 15000, protocols: ['TCP', 'ICMP'], bytes_transferred: 120_000_000, first_seen: ago(120), last_seen: ago(5) },
];

// ─── Attack Timelines ───────────────────────────────────────
export const demoAttackTimelines = [
  {
    id: 'demo-at-1', source_ip: '10.0.1.45', total_events: 6, is_active: true,
    first_event_at: ago(120), last_event_at: ago(5),
    kill_chain_phases: ['reconnaissance', 'delivery', 'exploitation'],
    timeline_events: [
      { timestamp: ago(120), event_type: 'Port Scan', phase: 'reconnaissance', description: 'Sequential port scan on 10.0.1.1 (ports 1-1024)', severity: 'medium', source: 'alert' },
      { timestamp: ago(90), event_type: 'Port Scan', phase: 'reconnaissance', description: 'Service enumeration on 10.0.1.10', severity: 'medium', source: 'alert' },
      { timestamp: ago(60), event_type: 'Exploit', phase: 'exploitation', description: 'CVE-2024-1234 exploit attempt against web-prod-01', severity: 'critical', source: 'alert' },
      { timestamp: ago(45), event_type: 'DoS', phase: 'delivery', description: 'SYN flood targeting 10.0.1.10:443', severity: 'high', source: 'alert' },
      { timestamp: ago(20), event_type: 'Exploit', phase: 'exploitation', description: 'SQL injection attempt on /api/users', severity: 'critical', source: 'incident' },
      { timestamp: ago(5), event_type: 'Port Scan', phase: 'reconnaissance', description: 'Continued scanning of internal subnet', severity: 'low', source: 'alert' },
    ],
  },
  {
    id: 'demo-at-2', source_ip: '172.16.0.22', total_events: 4, is_active: false,
    first_event_at: ago(200), last_event_at: ago(60),
    kill_chain_phases: ['installation', 'command_and_control'],
    timeline_events: [
      { timestamp: ago(200), event_type: 'Malware', phase: 'installation', description: 'Suspicious binary detected on ws-compromised', severity: 'high', source: 'alert' },
      { timestamp: ago(150), event_type: 'Beaconing', phase: 'command_and_control', description: 'Periodic connection to 203.0.113.50 every 60s', severity: 'high', source: 'hunt' },
      { timestamp: ago(100), event_type: 'C2', phase: 'command_and_control', description: 'Encrypted C2 traffic detected', severity: 'critical', source: 'alert' },
      { timestamp: ago(60), event_type: 'Malware', phase: 'installation', description: 'Additional payload downloaded', severity: 'high', source: 'incident' },
    ],
  },
];

// ─── Threat Hunter Results ──────────────────────────────────
export const demoHuntResults = [
  { id: 'demo-hr-1', hunt_type: 'rare_destination', source_ip: '10.0.2.50', target: '198.51.100.77', score: 85, details: { contact_count: 3, total_sources: 1 }, created_at: ago(30) },
  { id: 'demo-hr-2', hunt_type: 'dns_entropy', source_ip: '172.16.0.22', target: 'xk3j9f2m.evil.com', score: 92, details: { entropy: 4.2, length: 22 }, created_at: ago(45) },
  { id: 'demo-hr-3', hunt_type: 'beaconing', source_ip: '172.16.0.22', target: '203.0.113.50', score: 78, details: { mean_interval_sec: 60, jitter_cv: 0.05, connections: 48 }, created_at: ago(60) },
  { id: 'demo-hr-4', hunt_type: 'data_exfil', source_ip: '10.0.2.51', target: '250MB', score: 65, details: { total_bytes: 262144000, z_score: 3.2 }, created_at: ago(15) },
  { id: 'demo-hr-5', hunt_type: 'rare_destination', source_ip: '10.0.1.10', target: '203.0.113.99', score: 45, details: { contact_count: 1, total_sources: 2 }, created_at: ago(90) },
];

// ─── Risk Scores ────────────────────────────────────────────
export const demoRiskScores = [
  { id: 'demo-rs-1', ip_address: '10.0.1.45', hostname: null, alert_score: 65, anomaly_score: 15, reputation_score: 30, asset_multiplier: 1.0, total_risk: 92, risk_level: 'critical', updated_at: ago(5) },
  { id: 'demo-rs-2', ip_address: '192.168.2.100', hostname: null, alert_score: 50, anomaly_score: 10, reputation_score: 20, asset_multiplier: 1.0, total_risk: 74, risk_level: 'high', updated_at: ago(15) },
  { id: 'demo-rs-3', ip_address: '172.16.0.22', hostname: 'ws-compromised', alert_score: 30, anomaly_score: 20, reputation_score: 15, asset_multiplier: 1.0, total_risk: 55, risk_level: 'medium', updated_at: ago(60) },
  { id: 'demo-rs-4', ip_address: '10.0.1.10', hostname: 'web-prod-01', alert_score: 15, anomaly_score: 5, reputation_score: 0, asset_multiplier: 1.5, total_risk: 30, risk_level: 'medium', updated_at: ago(30) },
  { id: 'demo-rs-5', ip_address: '10.0.1.20', hostname: 'db-primary', alert_score: 5, anomaly_score: 0, reputation_score: 0, asset_multiplier: 2.0, total_risk: 10, risk_level: 'low', updated_at: ago(60) },
];

// ─── ML Models ──────────────────────────────────────────────
export const demoMLModels = [
  { id: 'demo-ml-1', name: 'IDS-RandomForest-v3', algorithm: 'random_forest', status: 'trained', is_active: true, version: '3.0.0', model_config: { nEstimators: 100, maxDepth: 15 }, model_artifacts: null, feature_importance: { duration: 0.23, src_bytes: 0.18, dst_bytes: 0.15, protocol_type: 0.12, service: 0.1 }, training_dataset_id: null, created_at: ago(1440), updated_at: ago(60) },
  { id: 'demo-ml-2', name: 'Anomaly-GBDT-v2', algorithm: 'gradient_boosted_dt', status: 'trained', is_active: false, version: '2.1.0', model_config: { nEstimators: 50, learningRate: 0.1 }, model_artifacts: null, feature_importance: { packet_size: 0.25, flow_duration: 0.2, flag_count: 0.18 }, training_dataset_id: null, created_at: ago(4320), updated_at: ago(2880) },
  { id: 'demo-ml-3', name: 'C45-Classifier-v1', algorithm: 'c45_decision_tree', status: 'training', is_active: false, version: '1.0.0', model_config: { maxDepth: 10 }, model_artifacts: null, feature_importance: null, training_dataset_id: null, created_at: ago(10), updated_at: ago(10) },
];

// ─── Model Evaluations ──────────────────────────────────────
export const demoModelEvaluations = [
  { id: 'demo-me-1', model_id: 'demo-ml-1', accuracy: 0.967, precision: 0.952, recall: 0.941, f1_score: 0.946, false_positive_rate: 0.021, detection_rate: 0.941, roc_auc: 0.988, training_time_ms: 3200, testing_time_ms: 45, created_at: ago(1440), evaluation_type: 'cross_validation', dataset_id: null, confusion_matrix: null, class_performance: null },
  { id: 'demo-me-2', model_id: 'demo-ml-2', accuracy: 0.943, precision: 0.931, recall: 0.918, f1_score: 0.924, false_positive_rate: 0.035, detection_rate: 0.918, roc_auc: 0.972, training_time_ms: 8500, testing_time_ms: 120, created_at: ago(4320), evaluation_type: 'cross_validation', dataset_id: null, confusion_matrix: null, class_performance: null },
  { id: 'demo-me-3', model_id: 'demo-ml-1', accuracy: 0.955, precision: 0.940, recall: 0.935, f1_score: 0.937, false_positive_rate: 0.028, detection_rate: 0.935, roc_auc: 0.981, training_time_ms: 3400, testing_time_ms: 50, created_at: ago(720), evaluation_type: 'holdout', dataset_id: null, confusion_matrix: null, class_performance: null },
];

// ─── Predictions (Inference) ────────────────────────────────
export const demoPredictions = [
  { id: 'demo-p-1', model_id: 'demo-ml-1', prediction: 'normal', confidence: 0.96, is_anomaly: false, features: { duration: 0.5, src_bytes: 1024, dst_bytes: 2048, protocol_type: 1, source_ip: '10.0.2.50' }, created_at: ago(1), prediction_time_ms: 2, actual_label: null, feedback_provided: false, network_event_id: null },
  { id: 'demo-p-2', model_id: 'demo-ml-1', prediction: 'port_scan', confidence: 0.89, is_anomaly: true, features: { duration: 0.01, src_bytes: 60, dst_bytes: 0, protocol_type: 0, source_ip: '10.0.1.45' }, created_at: ago(2), prediction_time_ms: 1, actual_label: null, feedback_provided: false, network_event_id: null },
  { id: 'demo-p-3', model_id: 'demo-ml-1', prediction: 'dos', confidence: 0.82, is_anomaly: true, features: { duration: 0.001, src_bytes: 120, dst_bytes: 0, protocol_type: 0, source_ip: '192.168.2.100' }, created_at: ago(3), prediction_time_ms: 1, actual_label: null, feedback_provided: false, network_event_id: null },
  { id: 'demo-p-4', model_id: 'demo-ml-1', prediction: 'normal', confidence: 0.99, is_anomaly: false, features: { duration: 12.5, src_bytes: 50000, dst_bytes: 120000, protocol_type: 1, source_ip: '10.0.2.51' }, created_at: ago(4), prediction_time_ms: 3, actual_label: null, feedback_provided: false, network_event_id: null },
];

// ─── Adaptive Learning Configs ──────────────────────────────
export const demoAdaptiveConfigs = [
  { id: 'demo-ac-1', model_id: 'demo-ml-1', environment_type: 'Cloud', resource_constraints: { memory: 2048, cpu: 80, bandwidth: 1000 }, update_frequency: 3600, batch_size: 100, learning_rate: 0.001, drift_threshold: 0.05, is_active: true, created_at: ago(1440), updated_at: ago(60) },
  { id: 'demo-ac-2', model_id: 'demo-ml-2', environment_type: 'Edge', resource_constraints: { memory: 512, cpu: 40, bandwidth: 100 }, update_frequency: 7200, batch_size: 32, learning_rate: 0.0005, drift_threshold: 0.08, is_active: false, created_at: ago(4320), updated_at: ago(2880) },
];

// ─── Detection Rules ────────────────────────────────────────
export const demoDetectionRules = [
  { id: 'demo-dr-1', name: 'SYN Flood Detection', rule_type: 'rate_limit', severity: 'critical', pattern: 'flags.SYN > 100/s', regex_pattern: null, rate_limit_threshold: 100, rate_limit_window_seconds: 1, yara_rule: null, description: 'Detects SYN flood attacks', mitre_attack_id: 'T1499', enabled: true, triggered_count: 47, false_positive_rate: 0.02, last_triggered: ago(5), cve_ids: [], created_at: ago(30000), updated_at: ago(5) },
  { id: 'demo-dr-2', name: 'Port Scan Signature', rule_type: 'signature', severity: 'medium', pattern: 'unique_dst_ports > 50 in 60s', regex_pattern: null, rate_limit_threshold: null, rate_limit_window_seconds: null, yara_rule: null, description: 'Horizontal port scan detection', mitre_attack_id: 'T1046', enabled: true, triggered_count: 123, false_positive_rate: 0.05, last_triggered: ago(15), cve_ids: [], created_at: ago(30000), updated_at: ago(15) },
  { id: 'demo-dr-3', name: 'SQL Injection Pattern', rule_type: 'regex', severity: 'high', pattern: 'payload contains SQL keywords', regex_pattern: '(?i)(union\\s+select|drop\\s+table|;\\s*delete)', rate_limit_threshold: null, rate_limit_window_seconds: null, yara_rule: null, description: 'Detects common SQL injection patterns', mitre_attack_id: 'T1190', enabled: true, triggered_count: 12, false_positive_rate: 0.08, last_triggered: ago(60), cve_ids: ['CVE-2024-1234'], created_at: ago(20000), updated_at: ago(60) },
  { id: 'demo-dr-4', name: 'DNS Tunneling', rule_type: 'anomaly', severity: 'high', pattern: 'dns_query_entropy > 4.0', regex_pattern: null, rate_limit_threshold: null, rate_limit_window_seconds: null, yara_rule: null, description: 'Detects DNS tunneling via high entropy domains', mitre_attack_id: 'T1071.004', enabled: true, triggered_count: 5, false_positive_rate: 0.12, last_triggered: ago(180), cve_ids: [], created_at: ago(15000), updated_at: ago(180) },
  { id: 'demo-dr-5', name: 'Brute Force SSH', rule_type: 'rate_limit', severity: 'medium', pattern: 'ssh_failed_auth > 10/min', regex_pattern: null, rate_limit_threshold: 10, rate_limit_window_seconds: 60, yara_rule: null, description: 'Detects SSH brute force attempts', mitre_attack_id: 'T1110', enabled: false, triggered_count: 89, false_positive_rate: 0.15, last_triggered: ago(500), cve_ids: [], created_at: ago(25000), updated_at: ago(500) },
];

// ─── Malware Signatures ─────────────────────────────────────
export const demoMalwareSignatures = [
  { id: 'demo-ms-1', hash_md5: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', hash_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', hash_sha1: null, malware_family: 'Emotet', malware_type: 'trojan', threat_level: 'critical', description: 'Emotet banking trojan variant', first_seen: ago(10000), last_seen: ago(30), detection_count: 15, is_active: true, yara_rule: null, ioc_indicators: ['evil-domain.com', '198.51.100.10'], created_at: ago(10000) },
  { id: 'demo-ms-2', hash_md5: 'f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6', hash_sha256: null, hash_sha1: null, malware_family: 'WannaCry', malware_type: 'ransomware', threat_level: 'critical', description: 'WannaCry ransomware', first_seen: ago(50000), last_seen: ago(5000), detection_count: 3, is_active: true, yara_rule: null, ioc_indicators: ['wannacry-kill-switch.com'], created_at: ago(50000) },
  { id: 'demo-ms-3', hash_md5: null, hash_sha256: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd', hash_sha1: null, malware_family: 'Cobalt Strike', malware_type: 'backdoor', threat_level: 'high', description: 'Cobalt Strike beacon payload', first_seen: ago(2000), last_seen: ago(100), detection_count: 8, is_active: true, yara_rule: 'rule cobalt_beacon { strings: $a = "beacon" condition: $a }', ioc_indicators: ['203.0.113.50'], created_at: ago(2000) },
];

// ─── IP Reputation ──────────────────────────────────────────
export const demoIPReputations = [
  { id: 'demo-ip-1', ip_address: '198.51.100.10', reputation_score: 92, threat_types: ['malware', 'botnet'], country_code: 'RU', asn: 'AS12345', asn_org: 'Evil Corp Hosting', is_tor_exit: false, is_vpn: false, is_proxy: false, is_datacenter: true, abuse_reports: 145, last_reported: ago(60), first_seen: ago(10000), last_checked: ago(10), source: 'abuseipdb' },
  { id: 'demo-ip-2', ip_address: '203.0.113.50', reputation_score: 85, threat_types: ['c2', 'malware'], country_code: 'CN', asn: 'AS67890', asn_org: 'Shady VPS Ltd', is_tor_exit: false, is_vpn: true, is_proxy: false, is_datacenter: true, abuse_reports: 67, last_reported: ago(120), first_seen: ago(5000), last_checked: ago(30), source: 'abuseipdb' },
  { id: 'demo-ip-3', ip_address: '192.168.2.100', reputation_score: 35, threat_types: ['ddos'], country_code: 'US', asn: null, asn_org: null, is_tor_exit: false, is_vpn: false, is_proxy: false, is_datacenter: false, abuse_reports: 3, last_reported: ago(90), first_seen: ago(500), last_checked: ago(15), source: 'heuristic' },
  { id: 'demo-ip-4', ip_address: '45.33.32.156', reputation_score: 15, threat_types: [], country_code: 'US', asn: 'AS63949', asn_org: 'Linode', is_tor_exit: false, is_vpn: false, is_proxy: false, is_datacenter: true, abuse_reports: 0, last_reported: null, first_seen: ago(20000), last_checked: ago(60), source: 'heuristic' },
];

// ─── Threat Feeds ───────────────────────────────────────────
export const demoThreatFeeds = [
  { id: 'demo-tf-1', name: 'AbuseIPDB Blocklist', feed_type: 'ip_blocklist', url: 'https://api.abuseipdb.com/api/v2/blacklist', is_active: true, api_key_required: true, update_frequency_hours: 6, entries_count: 12500, last_updated: ago(120), created_at: ago(50000), updated_at: ago(120) },
  { id: 'demo-tf-2', name: 'Emerging Threats Open', feed_type: 'signature', url: 'https://rules.emergingthreats.net/open/suricata/rules/', is_active: true, api_key_required: false, update_frequency_hours: 24, entries_count: 34000, last_updated: ago(480), created_at: ago(50000), updated_at: ago(480) },
  { id: 'demo-tf-3', name: 'MISP Community Feed', feed_type: 'ioc', url: null, is_active: false, api_key_required: true, update_frequency_hours: 12, entries_count: 0, last_updated: null, created_at: ago(30000), updated_at: ago(30000) },
];

// ─── Retention Policies ─────────────────────────────────────
export const demoRetentionPolicies = [
  { id: 'demo-rp-1', table_name: 'network_traffic', retention_days: 30, archive_before_delete: true, is_active: true, last_cleanup_at: ago(1440), rows_deleted: 12450, created_at: ago(50000) },
  { id: 'demo-rp-2', table_name: 'system_metrics_log', retention_days: 14, archive_before_delete: false, is_active: true, last_cleanup_at: ago(1440), rows_deleted: 8900, created_at: ago(50000) },
  { id: 'demo-rp-3', table_name: 'live_alerts', retention_days: 90, archive_before_delete: true, is_active: true, last_cleanup_at: ago(4320), rows_deleted: 3200, created_at: ago(30000) },
  { id: 'demo-rp-4', table_name: 'predictions', retention_days: 7, archive_before_delete: false, is_active: false, last_cleanup_at: null, rows_deleted: 0, created_at: ago(10000) },
];

// ─── Notification Configs ───────────────────────────────────
export const demoNotificationConfigs = [
  { id: 'demo-nc-1', config_type: 'email', target: 'soc-team@company.com', severity_threshold: 'high', is_active: true, last_sent_at: ago(30), created_at: ago(50000) },
  { id: 'demo-nc-2', config_type: 'webhook', target: 'https://hooks.slack.com/services/DEMO/WEBHOOK', severity_threshold: 'critical', is_active: true, last_sent_at: ago(120), created_at: ago(40000) },
  { id: 'demo-nc-3', config_type: 'email', target: 'ciso@company.com', severity_threshold: 'critical', is_active: false, last_sent_at: null, created_at: ago(20000) },
];

// ─── Correlation Groups (for CorrelationEngine) ─────────────
export const demoCorrelationGroups = [
  {
    id: 'demo-cg-1', sourceIP: '10.0.1.45', compositeScore: 88, isMultiStage: true,
    escalated: false, persisted: false, sequencePattern: 'recon_to_exploit',
    firstSeen: ago(120), lastSeen: ago(5),
    phases: ['reconnaissance', 'delivery', 'exploitation'],
    events: [
      { id: 'e1', timestamp: ago(120), sourceIP: '10.0.1.45', attackType: 'Port Scan', severity: 'medium', threatScore: 40 },
      { id: 'e2', timestamp: ago(90), sourceIP: '10.0.1.45', attackType: 'Port Scan', severity: 'medium', threatScore: 45 },
      { id: 'e3', timestamp: ago(60), sourceIP: '10.0.1.45', destinationIP: '10.0.1.10', attackType: 'Exploit', severity: 'critical', threatScore: 90 },
      { id: 'e4', timestamp: ago(45), sourceIP: '10.0.1.45', destinationIP: '10.0.1.10', attackType: 'DoS', severity: 'high', threatScore: 75 },
    ],
  },
  {
    id: 'demo-cg-2', sourceIP: '172.16.0.22', compositeScore: 72, isMultiStage: true,
    escalated: true, persisted: true, sequencePattern: 'install_to_c2',
    firstSeen: ago(200), lastSeen: ago(60),
    phases: ['installation', 'command_and_control'],
    events: [
      { id: 'e5', timestamp: ago(200), sourceIP: '172.16.0.22', attackType: 'Malware', severity: 'high', threatScore: 70 },
      { id: 'e6', timestamp: ago(150), sourceIP: '172.16.0.22', destinationIP: '203.0.113.50', attackType: 'Beaconing', severity: 'high', threatScore: 65 },
      { id: 'e7', timestamp: ago(100), sourceIP: '172.16.0.22', destinationIP: '203.0.113.50', attackType: 'C2', severity: 'critical', threatScore: 85 },
    ],
  },
];
