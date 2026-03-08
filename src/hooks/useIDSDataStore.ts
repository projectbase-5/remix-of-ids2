/**
 * useIDSDataStore — Central state manager for the IDS Dashboard
 * ==============================================================
 * This hook owns ALL runtime state for the dashboard: network events,
 * threat detections, security alerts, system metrics, and traffic chart data.
 *
 * Two operating modes:
 *   - Demo mode (default) — generates synthetic metrics locally.
 *   - Live mode — polls Supabase tables every 2 seconds for real data.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useMetricsCalculator } from './useMetricsCalculator';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';

export interface NetworkEvent {
  id: string;
  timestamp: string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  port: number;
  packetSize: number;
  flags: string[];
  payload?: string;
}

export interface ThreatDetection {
  id: string;
  timestamp: string;
  ruleId: string;
  ruleName: string;
  severity: "low" | "medium" | "high";
  confidence: number;
  sourceIP: string;
  targetIP: string;
  attackType: string;
  description: string;
  evidence: NetworkEvent[];
  threatScore: number;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  type: "DoS" | "DDoS" | "Port Scan" | "Brute Force" | "Malware" | "Anomaly";
  severity: "low" | "medium" | "high";
  sourceIP: string;
  targetIP: string;
  description: string;
  status: "active" | "investigating" | "resolved";
  threatId?: string;
}

export interface SystemMetrics {
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkHealth: number;
  detectionEngineStatus: "online" | "offline" | "maintenance";
  packetsProcessed: number;
  threatsBlocked: number;
  eventsPerSecond: number;
  activeConnections: number;
}

export interface TrafficData {
  time: string;
  inbound: number;
  outbound: number;
  threats: number;
  events: number;
}

export const useIDSDataStore = () => {
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [threats, setThreats] = useState<ThreatDetection[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>({
    cpuUsage: 25,
    memoryUsage: 35,
    diskUsage: 78,
    networkHealth: 98,
    detectionEngineStatus: "online",
    packetsProcessed: 0,
    threatsBlocked: 0,
    eventsPerSecond: 0,
    activeConnections: 1247,
  });
  const [trafficData, setTrafficData] = useState<TrafficData[]>([]);
  
  const { calculateMetrics } = useMetricsCalculator();

  // ---------------------------------------------------------------------------
  // addNetworkEvent — append a packet and recalculate derived metrics / chart
  // ---------------------------------------------------------------------------
  const addNetworkEvent = useCallback((event: NetworkEvent) => {
    setNetworkEvents(prev => {
      // Keep at most 100 events in memory (sliding window)
      const updated = [event, ...prev.slice(0, 99)];
      
      const metrics = calculateMetrics(updated, threats);
      
      setSystemMetrics(prev => ({
        ...prev,
        packetsProcessed: prev.packetsProcessed + 1,
        eventsPerSecond: metrics.eventsPerSecond,
        cpuUsage: metrics.cpuUsage,
        memoryUsage: metrics.memoryUsage,
        networkHealth: metrics.networkHealth,
      }));

      // Aggregate into 1-second time slots for the traffic chart
      const now = new Date();
      const time = now.toLocaleTimeString();
      
      setTrafficData(prev => {
        const latest = prev[prev.length - 1];
        if (latest && latest.time === time) {
          return prev.map((item, index) => 
            index === prev.length - 1 
              ? {
                  ...item,
                  inbound: metrics.inboundTraffic,
                  outbound: metrics.outboundTraffic,
                  events: item.events + 1,
                }
              : item
          );
        } else {
          const newSlot: TrafficData = {
            time,
            inbound: metrics.inboundTraffic,
            outbound: metrics.outboundTraffic,
            threats: 0,
            events: 1,
          };
          return [...prev.slice(-19), newSlot];
        }
      });
      
      return updated;
    });
  }, [calculateMetrics, threats]);

  // ---------------------------------------------------------------------------
  // addThreat — record a detection and auto-create a matching SecurityAlert
  // ---------------------------------------------------------------------------
  const addThreat = useCallback((threat: ThreatDetection) => {
    setThreats(prev => {
      const updated = [threat, ...prev.slice(0, 49)];
      
      const metrics = calculateMetrics(networkEvents, updated);
      
      setSystemMetrics(prev => ({
        ...prev,
        threatsBlocked: prev.threatsBlocked + 1,
        cpuUsage: metrics.cpuUsage,
        networkHealth: metrics.networkHealth,
      }));

      setTrafficData(prev => 
        prev.map((item, index) => 
          index === prev.length - 1 
            ? { ...item, threats: item.threats + 1 }
            : item
        )
      );
      
      return updated;
    });
    
    const alert: SecurityAlert = {
      id: `alert-${threat.id}`,
      timestamp: threat.timestamp,
      type: threat.attackType as SecurityAlert['type'],
      severity: threat.severity,
      sourceIP: threat.sourceIP,
      targetIP: threat.targetIP,
      description: threat.description,
      status: "active",
      threatId: threat.id,
    };
    
    setAlerts(prev => [alert, ...prev.slice(0, 49)]);
  }, [calculateMetrics, networkEvents]);

  // ---------------------------------------------------------------------------
  // updateAlertStatus — mark an alert as investigating / resolved
  // ---------------------------------------------------------------------------
  const updateAlertStatus = useCallback((alertId: string, status: SecurityAlert['status']) => {
    setAlerts(prev => prev.map(alert => 
      alert.id === alertId ? { ...alert, status } : alert
    ));
  }, []);

  // Initialize traffic chart with empty time slots
  useEffect(() => {
    const initialData: TrafficData[] = [];
    for (let i = 19; i >= 0; i--) {
      const time = new Date(Date.now() - i * 2000);
      initialData.push({
        time: time.toLocaleTimeString(),
        inbound: 0,
        outbound: 0,
        threats: 0,
        events: 0,
      });
    }
    setTrafficData(initialData);
  }, []);

  // ==========================================================================
  // LIVE MODE — Poll `network_traffic` and `system_metrics_log` every 2 s
  // ==========================================================================
  // `lastFetchRef` stores the `created_at` of the most recent packet we've
  // seen so we only fetch new rows on each poll cycle.
  const lastFetchRef = useRef<string>(new Date().toISOString());

  useEffect(() => {
    if (isDemoMode || !isMonitoring) return;

    const pollLiveData = async () => {
      try {
        // Fetch packets inserted since our last poll timestamp
        const { data: packets } = await supabase
          .from('network_traffic')
          .select('*')
          .gt('created_at', lastFetchRef.current)
          .order('created_at', { ascending: true })
          .limit(50);

        if (packets && packets.length > 0) {
          // Advance the cursor so the next poll only gets newer rows
          lastFetchRef.current = packets[packets.length - 1].created_at;
          packets.forEach((p) => {
            const event: NetworkEvent = {
              id: p.id,
              timestamp: p.created_at,
              sourceIP: p.source_ip,
              destinationIP: p.destination_ip,
              protocol: p.protocol,
              port: p.port || 0,
              packetSize: p.packet_size || 0,
              flags: Array.isArray(p.flags) ? (p.flags as string[]) : [],
              payload: p.payload_preview || undefined,
            };
            addNetworkEvent(event);
          });
        }

        // Grab the single most recent system metrics row (sent by the agent)
        const { data: metrics } = await supabase
          .from('system_metrics_log')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(1);

        if (metrics && metrics.length > 0) {
          const m = metrics[0];
          setSystemMetrics((prev) => ({
            ...prev,
            cpuUsage: Number(m.cpu_usage),
            memoryUsage: Number(m.memory_usage),
            diskUsage: Number(m.disk_usage),
            networkHealth: Number(m.network_health),
            activeConnections: m.active_connections || prev.activeConnections,
          }));
        }
      } catch (err) {
        console.error('Live polling error:', err);
      }
    };

    const interval = setInterval(pollLiveData, 2000);
    return () => clearInterval(interval);
  }, [isDemoMode, isMonitoring, addNetworkEvent]);

  // ==========================================================================
  // LIVE MODE — Poll `live_alerts` every 2 s
  // ==========================================================================
  // `seenAlertIdsRef` prevents the same alert row from being processed twice
  // (guards against overlapping poll windows or duplicate reads).
  const lastAlertFetchRef = useRef<string>(new Date().toISOString());
  const seenAlertIdsRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (isDemoMode || !isMonitoring) return;

    const pollAlerts = async () => {
      try {
        const { data: rows } = await supabase
          .from('live_alerts')
          .select('*')
          .gt('created_at', lastAlertFetchRef.current)
          .order('created_at', { ascending: true })
          .limit(50);

        if (rows && rows.length > 0) {
          lastAlertFetchRef.current = rows[rows.length - 1].created_at!;

          for (const row of rows) {
            // Skip already-processed alerts (deduplication)
            if (seenAlertIdsRef.current.has(row.id)) continue;
            seenAlertIdsRef.current.add(row.id);

            // Convert DB row → SecurityAlert for the UI
            const alert: SecurityAlert = {
              id: row.id,
              timestamp: row.created_at || new Date().toISOString(),
              type: row.alert_type as SecurityAlert['type'],
              severity: (row.severity || 'medium') as SecurityAlert['severity'],
              sourceIP: row.source_ip,
              targetIP: row.destination_ip || '0.0.0.0',
              description: row.description,
              status: (row.status || 'active') as SecurityAlert['status'],
            };

            setAlerts(prev => [alert, ...prev.slice(0, 49)]);

            // Also create a ThreatDetection so it appears in the threats panel
            const threat: ThreatDetection = {
              id: `threat-${row.id}`,
              timestamp: row.created_at || new Date().toISOString(),
              ruleId: row.detection_module,
              ruleName: row.alert_type,
              severity: (row.severity || 'medium') as ThreatDetection['severity'],
              confidence: row.severity === 'high' ? 0.95 : 0.75,
              sourceIP: row.source_ip,
              targetIP: row.destination_ip || '0.0.0.0',
              attackType: row.alert_type,
              description: row.description,
              evidence: [],
              threatScore: row.severity === 'high' ? 90 : 60,
            };

            setThreats(prev => [threat, ...prev.slice(0, 49)]);

            // Show a destructive toast for high-severity alerts so the
            // operator is immediately notified of critical attacks.
            if (row.severity === 'high') {
              toast({
                variant: 'destructive',
                title: `🚨 ${row.alert_type} Detected`,
                description: `Source: ${row.source_ip} — ${row.description}`,
              });
            }
          }
        }
      } catch (err) {
        console.error('Alert polling error:', err);
      }
    };

    const interval = setInterval(pollAlerts, 2000);
    return () => clearInterval(interval);
  }, [isDemoMode, isMonitoring]);

  // Demo mode only: simulate slow-moving system metrics
  useEffect(() => {
    if (!isMonitoring || !isDemoMode) return;

    const interval = setInterval(() => {
      setSystemMetrics(prev => ({
        ...prev,
        diskUsage: Math.max(75, Math.min(85, prev.diskUsage + (Math.random() - 0.5))),
        activeConnections: Math.max(1000, Math.min(2000, prev.activeConnections + Math.floor((Math.random() - 0.5) * 20))),
      }));
    }, 1000);

    return () => clearInterval(interval);
  }, [isMonitoring, isDemoMode]);

  // ==========================================================================
  // DEMO MODE — Global synthetic event & threat generation
  // ==========================================================================
  useEffect(() => {
    if (!isMonitoring || !isDemoMode) return;

    const protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"];
    const commonPorts = [80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995];
    const suspiciousPorts = [1433, 3389, 5432, 6379, 27017];

    const generateNetworkEvent = (): NetworkEvent => {
      const isSuspicious = Math.random() > 0.85;
      const port = isSuspicious
        ? suspiciousPorts[Math.floor(Math.random() * suspiciousPorts.length)]
        : commonPorts[Math.floor(Math.random() * commonPorts.length)];

      return {
        id: `event-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        sourceIP: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        destinationIP: `192.168.1.${Math.floor(Math.random() * 255)}`,
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        port,
        packetSize: Math.floor(Math.random() * 1500) + 64,
        flags: isSuspicious ? ["SYN", "FIN"] : ["ACK"],
        payload: isSuspicious ? "SELECT * FROM users WHERE 1=1" : undefined,
      };
    };

    const processEvent = (event: NetworkEvent) => {
      // Simplified inline rule matching for demo
      const rules = [
        { pattern: "port_scan", check: () => event.port > 1000 && event.flags.includes("SYN") && Math.random() > 0.9, confidence: 85, attackType: "Port Scan", severity: "medium" as const },
        { pattern: "ddos", check: () => event.packetSize > 1200 && Math.random() > 0.95, confidence: 92, attackType: "DDoS", severity: "high" as const },
        { pattern: "brute_force", check: () => (event.port === 22 || event.port === 3389) && Math.random() > 0.93, confidence: 88, attackType: "Brute Force", severity: "high" as const },
        { pattern: "sql_injection", check: () => !!event.payload?.includes("SELECT"), confidence: 95, attackType: "SQL Injection", severity: "high" as const },
        { pattern: "anomaly", check: () => (event.packetSize < 100 || event.packetSize > 1400) && Math.random() > 0.92, confidence: 75, attackType: "Anomaly", severity: "low" as const },
      ];

      for (const rule of rules) {
        if (rule.check()) {
          const baseScore = rule.severity === "high" ? 75 : rule.severity === "medium" ? 50 : 25;
          const threatScore = Math.min(100, Math.round(baseScore * (rule.confidence / 100) + (rule.attackType.includes("DDoS") || rule.attackType.includes("SQL") ? 15 : 0)));

          addThreat({
            id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date().toISOString(),
            ruleId: `demo-${rule.pattern}`,
            ruleName: rule.attackType,
            severity: rule.severity,
            confidence: rule.confidence,
            sourceIP: event.sourceIP,
            targetIP: event.destinationIP,
            attackType: rule.attackType,
            description: `${rule.attackType} detected from ${event.sourceIP} targeting ${event.destinationIP}`,
            evidence: [event],
            threatScore,
          });
          break; // one threat per event max
        }
      }
    };

    const interval = setInterval(() => {
      const event = generateNetworkEvent();
      addNetworkEvent(event);
      processEvent(event);
    }, 300);

    return () => clearInterval(interval);
  }, [isMonitoring, isDemoMode, addNetworkEvent, addThreat]);

  // ---------------------------------------------------------------------------
  // toggleDemoMode — clear all accumulated data when switching modes so stale
  // demo data doesn't bleed into live mode and vice-versa.
  // ---------------------------------------------------------------------------
  const toggleDemoMode = useCallback((enabled: boolean) => {
    setIsDemoMode(enabled);
    if (!enabled) {
      setNetworkEvents([]);
      setThreats([]);
      setAlerts([]);
      setSystemMetrics(prev => ({
        ...prev,
        packetsProcessed: 0,
        threatsBlocked: 0,
        eventsPerSecond: 0,
        cpuUsage: 15,
        memoryUsage: 25,
      }));
    }
  }, []);

  return {
    networkEvents,
    threats,
    alerts,
    systemMetrics,
    trafficData,
    isMonitoring,
    isDemoMode,
    addNetworkEvent,
    addThreat,
    updateAlertStatus,
    setIsMonitoring,
    toggleDemoMode,
  };
};
