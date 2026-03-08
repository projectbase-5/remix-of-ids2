import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

export interface MalwareSignature {
  id: string;
  hash_md5: string | null;
  hash_sha256: string | null;
  hash_sha1: string | null;
  malware_family: string;
  malware_type: string;
  threat_level: string;
  description: string | null;
  first_seen: string | null;
  last_seen: string | null;
  detection_count: number;
  is_active: boolean;
  yara_rule: string | null;
  ioc_indicators: string[];
  created_at: string;
}

export interface IPReputation {
  id: string;
  ip_address: string;
  reputation_score: number;
  threat_types: string[];
  country_code: string | null;
  asn: string | null;
  asn_org: string | null;
  is_tor_exit: boolean;
  is_vpn: boolean;
  is_proxy: boolean;
  is_datacenter: boolean;
  abuse_reports: number;
  last_reported: string | null;
  first_seen: string | null;
  last_checked: string | null;
  source: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  rule_type: string;
  severity: string;
  pattern: string;
  regex_pattern: string | null;
  rate_limit_threshold: number | null;
  rate_limit_window_seconds: number | null;
  yara_rule: string | null;
  description: string | null;
  enabled: boolean;
  triggered_count: number;
  last_triggered: string | null;
  mitre_attack_id: string | null;
  cve_ids: string[];
  false_positive_rate: number;
}

export interface ThreatFeed {
  id: string;
  name: string;
  feed_type: string;
  url: string | null;
  api_key_required: boolean;
  update_frequency_hours: number;
  last_updated: string | null;
  entries_count: number;
  is_active: boolean;
}

export interface IncidentLog {
  id: string;
  incident_type: string;
  severity: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  rule_id: string | null;
  signature_id: string | null;
  details: Record<string, unknown>;
  status: string;
  created_at: string;
}

export function useThreatIntelligence() {
  const [signatures, setSignatures] = useState<MalwareSignature[]>([]);
  const [ipReputations, setIPReputations] = useState<IPReputation[]>([]);
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>([]);
  const [threatFeeds, setThreatFeeds] = useState<ThreatFeed[]>([]);
  const [incidentLogs, setIncidentLogs] = useState<IncidentLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [signaturesRes, ipRes, rulesRes, feedsRes, incidentsRes] = await Promise.all([
        supabase.from('malware_signatures').select('*').order('created_at', { ascending: false }),
        supabase.from('ip_reputation').select('*').order('reputation_score', { ascending: false }),
        supabase.from('detection_rules').select('*').order('created_at', { ascending: false }),
        supabase.from('threat_feeds').select('*').order('name'),
        supabase.from('incident_logs').select('*').order('created_at', { ascending: false }).limit(100)
      ]);

      if (signaturesRes.data) setSignatures(signaturesRes.data as unknown as MalwareSignature[]);
      if (ipRes.data) setIPReputations(ipRes.data as unknown as IPReputation[]);
      if (rulesRes.data) setDetectionRules(rulesRes.data as unknown as DetectionRule[]);
      if (feedsRes.data) setThreatFeeds(feedsRes.data as unknown as ThreatFeed[]);
      if (incidentsRes.data) setIncidentLogs(incidentsRes.data as unknown as IncidentLog[]);
    } catch (error) {
      console.error('Error loading threat intelligence data:', error);
      toast.error('Failed to load threat intelligence data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const checkIPReputation = useCallback(async (ipAddress: string) => {
    setChecking(true);
    try {
      const { data, error } = await supabase.functions.invoke('check-ip-reputation', {
        body: { ip_address: ipAddress }
      });

      if (error) throw error;

      const sourceLabel = data.source === 'abuseipdb' ? ' (AbuseIPDB)' : data.source === 'heuristic' ? ' (Heuristic)' : '';
      toast.success(`IP ${ipAddress} checked - Score: ${data.reputation_score}/100${sourceLabel}`);
      await loadData();
      return data;
    } catch (error) {
      console.error('Error checking IP reputation:', error);
      toast.error('Failed to check IP reputation');
      return null;
    } finally {
      setChecking(false);
    }
  }, [loadData]);

  const enrichAlert = useCallback(async (sourceIp: string, destinationIp?: string) => {
    setChecking(true);
    try {
      const { data, error } = await supabase.functions.invoke('enrich-alert', {
        body: { source_ip: sourceIp, destination_ip: destinationIp }
      });

      if (error) throw error;

      toast.success('Alert enriched with threat intelligence');
      return data;
    } catch (error) {
      console.error('Error enriching alert:', error);
      toast.error('Failed to enrich alert');
      return null;
    } finally {
      setChecking(false);
    }
  }, []);

  const scanFileHash = useCallback(async (hash: string) => {
    setChecking(true);
    try {
      const { data, error } = await supabase.functions.invoke('scan-file-hash', {
        body: { hash }
      });

      if (error) throw error;

      if (data.is_malicious) {
        toast.error(`Malware detected: ${data.malware_family} (${data.malware_type})`);
      } else {
        toast.success('Hash is clean - no malware detected');
      }
      return data;
    } catch (error) {
      console.error('Error scanning file hash:', error);
      toast.error('Failed to scan file hash');
      return null;
    } finally {
      setChecking(false);
    }
  }, []);

  const addMalwareSignature = useCallback(async (signature: {
    hash_md5?: string;
    hash_sha256?: string;
    malware_family: string;
    malware_type: string;
    threat_level: string;
    description?: string;
  }) => {
    try {
      const { error } = await supabase.from('malware_signatures').insert([signature]);
      if (error) throw error;
      toast.success('Malware signature added');
      await loadData();
    } catch (error) {
      console.error('Error adding signature:', error);
      toast.error('Failed to add signature');
    }
  }, [loadData]);

  const addIPReputation = useCallback(async (ip: {
    ip_address: string;
    reputation_score?: number;
    threat_types?: string[];
    country_code?: string;
  }) => {
    try {
      const { error } = await supabase.from('ip_reputation').insert([ip]);
      if (error) throw error;
      toast.success('IP reputation entry added');
      await loadData();
    } catch (error) {
      console.error('Error adding IP reputation:', error);
      toast.error('Failed to add IP reputation');
    }
  }, [loadData]);

  const addDetectionRule = useCallback(async (rule: {
    name: string;
    rule_type: string;
    severity: string;
    pattern: string;
    regex_pattern?: string | null;
    rate_limit_threshold?: number | null;
    rate_limit_window_seconds?: number | null;
    yara_rule?: string | null;
    description?: string | null;
    mitre_attack_id?: string | null;
    enabled?: boolean;
  }) => {
    try {
      const { error } = await supabase.from('detection_rules').insert([rule]);
      if (error) throw error;
      toast.success('Detection rule added');
      await loadData();
    } catch (error) {
      console.error('Error adding detection rule:', error);
      toast.error('Failed to add detection rule');
    }
  }, [loadData]);

  const updateDetectionRule = useCallback(async (id: string, updates: Partial<DetectionRule>) => {
    try {
      const { error } = await supabase.from('detection_rules').update(updates).eq('id', id);
      if (error) throw error;
      toast.success('Detection rule updated');
      await loadData();
    } catch (error) {
      console.error('Error updating detection rule:', error);
      toast.error('Failed to update detection rule');
    }
  }, [loadData]);

  const deleteDetectionRule = useCallback(async (id: string) => {
    try {
      const { error } = await supabase.from('detection_rules').delete().eq('id', id);
      if (error) throw error;
      toast.success('Detection rule deleted');
      await loadData();
    } catch (error) {
      console.error('Error deleting detection rule:', error);
      toast.error('Failed to delete detection rule');
    }
  }, [loadData]);

  const deleteMalwareSignature = useCallback(async (id: string) => {
    try {
      const { error } = await supabase.from('malware_signatures').delete().eq('id', id);
      if (error) throw error;
      toast.success('Malware signature deleted');
      await loadData();
    } catch (error) {
      console.error('Error deleting signature:', error);
      toast.error('Failed to delete signature');
    }
  }, [loadData]);

  const deleteIPReputation = useCallback(async (id: string) => {
    try {
      const { error } = await supabase.from('ip_reputation').delete().eq('id', id);
      if (error) throw error;
      toast.success('IP reputation entry deleted');
      await loadData();
    } catch (error) {
      console.error('Error deleting IP reputation:', error);
      toast.error('Failed to delete IP reputation');
    }
  }, [loadData]);

  const logIncident = useCallback(async (incident: {
    incident_type: string;
    severity: string;
    source_ip?: string;
    destination_ip?: string;
    details?: Record<string, unknown>;
  }) => {
    try {
      const { error } = await supabase.from('incident_logs').insert([{
        ...incident,
        details: incident.details as unknown as undefined
      }]);
      if (error) throw error;
      await loadData();
    } catch (error) {
      console.error('Error logging incident:', error);
    }
  }, [loadData]);

  return {
    signatures,
    ipReputations,
    detectionRules,
    threatFeeds,
    incidentLogs,
    loading,
    checking,
    checkIPReputation,
    enrichAlert,
    scanFileHash,
    addMalwareSignature,
    addIPReputation,
    addDetectionRule,
    updateDetectionRule,
    deleteDetectionRule,
    deleteMalwareSignature,
    deleteIPReputation,
    logIncident,
    refresh: loadData
  };
}
