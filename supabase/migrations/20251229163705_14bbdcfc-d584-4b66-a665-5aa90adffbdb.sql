-- Create malware_signatures table for hash-based detection
CREATE TABLE public.malware_signatures (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  hash_md5 TEXT,
  hash_sha256 TEXT,
  hash_sha1 TEXT,
  malware_family TEXT NOT NULL,
  malware_type TEXT NOT NULL,
  threat_level TEXT NOT NULL DEFAULT 'medium',
  description TEXT,
  first_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
  detection_count INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT true,
  yara_rule TEXT,
  ioc_indicators JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create ip_reputation table for threat intelligence
CREATE TABLE public.ip_reputation (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  ip_address TEXT NOT NULL UNIQUE,
  reputation_score INTEGER NOT NULL DEFAULT 0,
  threat_types JSONB DEFAULT '[]'::jsonb,
  country_code TEXT,
  asn TEXT,
  asn_org TEXT,
  is_tor_exit BOOLEAN DEFAULT false,
  is_vpn BOOLEAN DEFAULT false,
  is_proxy BOOLEAN DEFAULT false,
  is_datacenter BOOLEAN DEFAULT false,
  abuse_reports INTEGER DEFAULT 0,
  last_reported TIMESTAMP WITH TIME ZONE,
  first_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
  last_checked TIMESTAMP WITH TIME ZONE DEFAULT now(),
  source TEXT NOT NULL DEFAULT 'manual',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create detection_rules table for enhanced rule management
CREATE TABLE public.detection_rules (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  rule_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  pattern TEXT NOT NULL,
  regex_pattern TEXT,
  rate_limit_threshold INTEGER,
  rate_limit_window_seconds INTEGER,
  yara_rule TEXT,
  description TEXT,
  enabled BOOLEAN DEFAULT true,
  triggered_count INTEGER DEFAULT 0,
  last_triggered TIMESTAMP WITH TIME ZONE,
  mitre_attack_id TEXT,
  cve_ids JSONB DEFAULT '[]'::jsonb,
  false_positive_rate NUMERIC DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create threat_feeds table for external threat intelligence sources
CREATE TABLE public.threat_feeds (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  feed_type TEXT NOT NULL,
  url TEXT,
  api_key_required BOOLEAN DEFAULT false,
  update_frequency_hours INTEGER DEFAULT 24,
  last_updated TIMESTAMP WITH TIME ZONE,
  entries_count INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create incident_logs table for tracking detections
CREATE TABLE public.incident_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  source_ip TEXT,
  destination_ip TEXT,
  source_port INTEGER,
  destination_port INTEGER,
  protocol TEXT,
  rule_id UUID REFERENCES public.detection_rules(id),
  signature_id UUID REFERENCES public.malware_signatures(id),
  details JSONB DEFAULT '{}'::jsonb,
  raw_data JSONB,
  status TEXT DEFAULT 'open',
  assigned_to TEXT,
  resolution TEXT,
  resolved_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.malware_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ip_reputation ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_logs ENABLE ROW LEVEL SECURITY;

-- RLS policies for malware_signatures
CREATE POLICY "Enable read access for all users" ON public.malware_signatures FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.malware_signatures FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.malware_signatures FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.malware_signatures FOR DELETE USING (true);

-- RLS policies for ip_reputation
CREATE POLICY "Enable read access for all users" ON public.ip_reputation FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.ip_reputation FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.ip_reputation FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.ip_reputation FOR DELETE USING (true);

-- RLS policies for detection_rules
CREATE POLICY "Enable read access for all users" ON public.detection_rules FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.detection_rules FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.detection_rules FOR UPDATE USING (true);
CREATE POLICY "Enable delete access for all users" ON public.detection_rules FOR DELETE USING (true);

-- RLS policies for threat_feeds
CREATE POLICY "Enable read access for all users" ON public.threat_feeds FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.threat_feeds FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.threat_feeds FOR UPDATE USING (true);

-- RLS policies for incident_logs
CREATE POLICY "Enable read access for all users" ON public.incident_logs FOR SELECT USING (true);
CREATE POLICY "Enable insert access for all users" ON public.incident_logs FOR INSERT WITH CHECK (true);
CREATE POLICY "Enable update access for all users" ON public.incident_logs FOR UPDATE USING (true);

-- Create indexes for better performance
CREATE INDEX idx_malware_signatures_hash_md5 ON public.malware_signatures(hash_md5);
CREATE INDEX idx_malware_signatures_hash_sha256 ON public.malware_signatures(hash_sha256);
CREATE INDEX idx_malware_signatures_family ON public.malware_signatures(malware_family);
CREATE INDEX idx_ip_reputation_ip ON public.ip_reputation(ip_address);
CREATE INDEX idx_ip_reputation_score ON public.ip_reputation(reputation_score);
CREATE INDEX idx_detection_rules_type ON public.detection_rules(rule_type);
CREATE INDEX idx_detection_rules_enabled ON public.detection_rules(enabled);
CREATE INDEX idx_incident_logs_status ON public.incident_logs(status);
CREATE INDEX idx_incident_logs_severity ON public.incident_logs(severity);
CREATE INDEX idx_incident_logs_created_at ON public.incident_logs(created_at);

-- Triggers for updated_at
CREATE TRIGGER update_malware_signatures_updated_at
  BEFORE UPDATE ON public.malware_signatures
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_ip_reputation_updated_at
  BEFORE UPDATE ON public.ip_reputation
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_detection_rules_updated_at
  BEFORE UPDATE ON public.detection_rules
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_threat_feeds_updated_at
  BEFORE UPDATE ON public.threat_feeds
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Insert default malware signatures for common threats
INSERT INTO public.malware_signatures (hash_md5, malware_family, malware_type, threat_level, description) VALUES
('44d88612fea8a8f36de82e1278abb02f', 'EICAR', 'test', 'low', 'EICAR Anti-Malware Test File'),
('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'WannaCry', 'ransomware', 'critical', 'WannaCry Ransomware'),
('84c82835a5d21bbcf75a61706d8ab549', 'Emotet', 'trojan', 'high', 'Emotet Banking Trojan'),
('7b3baa6e4c5f6f2a3c5a5e8f9c1d2b3a', 'Mirai', 'botnet', 'high', 'Mirai IoT Botnet'),
('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'Cobalt Strike', 'rat', 'critical', 'Cobalt Strike Beacon');

-- Insert default detection rules
INSERT INTO public.detection_rules (name, rule_type, severity, pattern, regex_pattern, description, rate_limit_threshold, rate_limit_window_seconds, mitre_attack_id) VALUES
('Port Scan Detection', 'behavioral', 'medium', 'PORT_SCAN', '.*', 'Detects port scanning activity', 100, 60, 'T1046'),
('Brute Force SSH', 'signature', 'high', 'SSH_BRUTE_FORCE', 'Failed password.*sshd', 'Multiple failed SSH login attempts', 5, 300, 'T1110'),
('SQL Injection Attempt', 'signature', 'high', 'SQL_INJECTION', '(union|select|insert|update|delete|drop).*--', 'Potential SQL injection attack', NULL, NULL, 'T1190'),
('DDoS Attack Pattern', 'anomaly', 'critical', 'DDOS_ATTACK', '.*', 'Distributed denial of service attack', 1000, 10, 'T1498'),
('Malware C2 Communication', 'behavioral', 'critical', 'C2_BEACON', '.*', 'Command and control beacon detected', 10, 3600, 'T1071'),
('Data Exfiltration', 'anomaly', 'critical', 'DATA_EXFIL', '.*', 'Large outbound data transfer detected', NULL, NULL, 'T1041'),
('Privilege Escalation', 'behavioral', 'high', 'PRIV_ESC', '(sudo|su|chmod|chown).*', 'Potential privilege escalation attempt', NULL, NULL, 'T1068'),
('Lateral Movement', 'behavioral', 'high', 'LATERAL_MOVE', '.*', 'Internal network lateral movement detected', NULL, NULL, 'T1021');

-- Insert sample malicious IPs for testing
INSERT INTO public.ip_reputation (ip_address, reputation_score, threat_types, country_code, is_tor_exit, abuse_reports, source) VALUES
('185.220.101.1', 95, '["tor_exit", "scanner"]', 'DE', true, 150, 'threat_feed'),
('45.33.32.156', 80, '["bruteforce", "scanner"]', 'US', false, 89, 'abuseipdb'),
('193.142.146.35', 100, '["ransomware_c2", "botnet"]', 'RU', false, 500, 'threat_feed'),
('91.240.118.172', 75, '["spam", "phishing"]', 'NL', false, 45, 'manual'),
('89.248.167.131', 90, '["scanner", "exploit"]', 'NL', false, 200, 'threat_feed');

-- Insert default threat feeds
INSERT INTO public.threat_feeds (name, feed_type, url, update_frequency_hours, is_active) VALUES
('AbuseIPDB', 'ip_reputation', 'https://api.abuseipdb.com/api/v2', 24, true),
('Emerging Threats', 'signatures', 'https://rules.emergingthreats.net', 12, true),
('AlienVault OTX', 'ioc', 'https://otx.alienvault.com/api/v1', 6, true),
('VirusTotal', 'hash', 'https://www.virustotal.com/api/v3', 1, true),
('Spamhaus', 'ip_blocklist', 'https://www.spamhaus.org', 24, true);