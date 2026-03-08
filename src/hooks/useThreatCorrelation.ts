import { useState, useCallback, useRef } from 'react';

export interface CorrelationEvent {
  id: string;
  timestamp: string;
  sourceIP?: string;
  destinationIP?: string;
  attackType: string;
  severity: string;
  threatScore: number;
  details?: Record<string, unknown>;
}

export interface KillChainPhase {
  phase: string;
  label: string;
  order: number;
}

export const KILL_CHAIN_PHASES: KillChainPhase[] = [
  { phase: 'reconnaissance', label: 'Recon', order: 0 },
  { phase: 'weaponization', label: 'Weaponize', order: 1 },
  { phase: 'delivery', label: 'Deliver', order: 2 },
  { phase: 'exploitation', label: 'Exploit', order: 3 },
  { phase: 'installation', label: 'Install', order: 4 },
  { phase: 'command_control', label: 'C2', order: 5 },
  { phase: 'exfiltration', label: 'Exfil', order: 6 },
];

const ATTACK_TO_PHASE: Record<string, string> = {
  'port_scan': 'reconnaissance', 'probe': 'reconnaissance', 'scan': 'reconnaissance', 'suspicious': 'reconnaissance',
  'phishing': 'delivery', 'malware_indicator': 'delivery', 'suspicious_file': 'delivery',
  'exploit': 'exploitation', 'attack': 'exploitation', 'potential_threat': 'exploitation', 'sql_injection': 'exploitation',
  'malware_detected': 'installation', 'quarantine_file': 'installation', 'trojan': 'installation',
  'c2_beacon': 'command_control', 'backdoor': 'command_control', 'reverse_shell': 'command_control',
  'data_exfiltration': 'exfiltration', 'dns_tunnel': 'exfiltration',
};

export interface CorrelationGroup {
  id: string;
  sourceIP: string;
  events: CorrelationEvent[];
  phases: string[];
  compositeScore: number;
  isMultiStage: boolean;
  firstSeen: string;
  lastSeen: string;
  escalated: boolean;
}

export function useThreatCorrelation(windowMinutes: number = 15) {
  const [groups, setGroups] = useState<CorrelationGroup[]>([]);
  const eventsRef = useRef<CorrelationEvent[]>([]);

  const getPhase = (attackType: string): string => {
    const lower = attackType.toLowerCase();
    for (const [key, phase] of Object.entries(ATTACK_TO_PHASE)) {
      if (lower.includes(key)) return phase;
    }
    return 'exploitation'; // default
  };

  const correlateEvents = useCallback(() => {
    const now = Date.now();
    const windowMs = windowMinutes * 60 * 1000;
    
    // Prune old events
    eventsRef.current = eventsRef.current.filter(e => now - new Date(e.timestamp).getTime() < windowMs);

    // Group by source IP
    const ipGroups = new Map<string, CorrelationEvent[]>();
    for (const event of eventsRef.current) {
      const ip = event.sourceIP || 'unknown';
      if (!ipGroups.has(ip)) ipGroups.set(ip, []);
      ipGroups.get(ip)!.push(event);
    }

    const newGroups: CorrelationGroup[] = [];
    for (const [ip, events] of ipGroups) {
      if (events.length < 2) continue;

      const sorted = events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      const phases = [...new Set(sorted.map(e => getPhase(e.attackType)))];
      const phaseOrders = phases.map(p => KILL_CHAIN_PHASES.find(k => k.phase === p)?.order ?? 3);
      const isMultiStage = phases.length >= 2 && Math.max(...phaseOrders) - Math.min(...phaseOrders) >= 1;

      const avgScore = events.reduce((s, e) => s + e.threatScore, 0) / events.length;
      const compositeScore = Math.min(100, Math.round(avgScore * (isMultiStage ? 1.5 : 1) + phases.length * 5));

      newGroups.push({
        id: `corr-${ip}-${Date.now()}`,
        sourceIP: ip,
        events: sorted,
        phases,
        compositeScore,
        isMultiStage,
        firstSeen: sorted[0].timestamp,
        lastSeen: sorted[sorted.length - 1].timestamp,
        escalated: isMultiStage && compositeScore >= 70,
      });
    }

    setGroups(newGroups.sort((a, b) => b.compositeScore - a.compositeScore));
    return newGroups;
  }, [windowMinutes]);

  const addEvent = useCallback((event: CorrelationEvent) => {
    eventsRef.current.push(event);
    return correlateEvents();
  }, [correlateEvents]);

  const clearEvents = useCallback(() => {
    eventsRef.current = [];
    setGroups([]);
  }, []);

  return { groups, addEvent, correlateEvents, clearEvents };
}
