import { useState, useCallback, useRef } from 'react';
import { supabase } from '@/integrations/supabase/client';

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

// Named attack chain patterns with phase sequences
export const ATTACK_SEQUENCES = {
  RECON_TO_EXFIL: ['reconnaissance', 'exploitation', 'command_control', 'exfiltration'],
  DELIVERY_CHAIN: ['delivery', 'exploitation', 'installation'],
  LATERAL_MOVE: ['exploitation', 'installation', 'command_control'],
  FULL_INTRUSION: ['reconnaissance', 'delivery', 'exploitation', 'installation', 'command_control'],
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
  sequencePattern?: string;
  persisted?: boolean;
}

interface CorrelationOptions {
  windowMinutes?: number;
  persistGroups?: boolean;
}

export function useThreatCorrelation(options: CorrelationOptions | number = 15) {
  // Handle backwards compatibility with number arg
  const config = typeof options === 'number' 
    ? { windowMinutes: options, persistGroups: false }
    : { windowMinutes: options.windowMinutes ?? 15, persistGroups: options.persistGroups ?? false };

  const [groups, setGroups] = useState<CorrelationGroup[]>([]);
  const [historicalGroups, setHistoricalGroups] = useState<CorrelationGroup[]>([]);
  const eventsRef = useRef<CorrelationEvent[]>([]);

  const getPhase = (attackType: string): string => {
    const lower = attackType.toLowerCase();
    for (const [key, phase] of Object.entries(ATTACK_TO_PHASE)) {
      if (lower.includes(key)) return phase;
    }
    return 'exploitation'; // default
  };

  // Detect if phases follow a known attack sequence
  const detectSequencePattern = (phases: string[]): string | undefined => {
    const phaseOrders = phases.map(p => KILL_CHAIN_PHASES.find(k => k.phase === p)?.order ?? 3);
    
    // Check if phases are in ascending order (temporal progression)
    const isAscending = phaseOrders.every((val, i, arr) => i === 0 || val >= arr[i - 1]);
    if (!isAscending || phases.length < 2) return undefined;

    for (const [name, sequence] of Object.entries(ATTACK_SEQUENCES)) {
      const matchCount = sequence.filter(s => phases.includes(s)).length;
      const sequenceRatio = matchCount / sequence.length;
      
      // If 60%+ of the sequence matches and phases are in order
      if (sequenceRatio >= 0.6) {
        return name;
      }
    }
    return undefined;
  };

  // Calculate weighted composite score
  const calculateCompositeScore = (
    events: CorrelationEvent[],
    phases: string[],
    isMultiStage: boolean,
    sequencePattern?: string
  ): number => {
    // Base: weighted average of threat scores
    const weights = events.map(e => {
      const recency = 1 - (Date.now() - new Date(e.timestamp).getTime()) / (config.windowMinutes * 60 * 1000);
      return Math.max(0.3, recency); // Minimum weight 0.3 for older events
    });
    const totalWeight = weights.reduce((a, b) => a + b, 0);
    const baseScore = events.reduce((sum, e, i) => sum + e.threatScore * weights[i], 0) / totalWeight;

    // Phase progression bonus: +5 per unique phase
    const phaseBonus = phases.length * 5;

    // Multi-stage multiplier
    const multiStageMultiplier = isMultiStage ? 1.3 : 1.0;

    // Sequence pattern bonus
    let sequenceBonus = 0;
    if (sequencePattern) {
      const matchedSequence = ATTACK_SEQUENCES[sequencePattern as keyof typeof ATTACK_SEQUENCES];
      if (matchedSequence) {
        sequenceBonus = matchedSequence.length >= 4 ? 40 : 20;
      }
    }

    return Math.min(100, Math.round(baseScore * multiStageMultiplier + phaseBonus + sequenceBonus));
  };

  const correlateEvents = useCallback(() => {
    const now = Date.now();
    const windowMs = config.windowMinutes * 60 * 1000;
    
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
      
      // Sort phases by kill chain order for sequence detection
      const sortedPhases = phases.sort((a, b) => {
        const orderA = KILL_CHAIN_PHASES.find(k => k.phase === a)?.order ?? 3;
        const orderB = KILL_CHAIN_PHASES.find(k => k.phase === b)?.order ?? 3;
        return orderA - orderB;
      });

      const phaseOrders = sortedPhases.map(p => KILL_CHAIN_PHASES.find(k => k.phase === p)?.order ?? 3);
      const isMultiStage = sortedPhases.length >= 2 && Math.max(...phaseOrders) - Math.min(...phaseOrders) >= 1;
      
      const sequencePattern = detectSequencePattern(sortedPhases);
      const compositeScore = calculateCompositeScore(events, sortedPhases, isMultiStage, sequencePattern);

      newGroups.push({
        id: `corr-${ip}-${Date.now()}`,
        sourceIP: ip,
        events: sorted,
        phases: sortedPhases,
        compositeScore,
        isMultiStage,
        firstSeen: sorted[0].timestamp,
        lastSeen: sorted[sorted.length - 1].timestamp,
        escalated: isMultiStage && compositeScore >= 70,
        sequencePattern,
      });
    }

    const sortedGroups = newGroups.sort((a, b) => b.compositeScore - a.compositeScore);
    setGroups(sortedGroups);

    // Persist high-scoring groups if enabled
    if (config.persistGroups) {
      persistHighScoringGroups(sortedGroups.filter(g => g.compositeScore >= 60));
    }

    return sortedGroups;
  }, [config.windowMinutes, config.persistGroups]);

  const persistHighScoringGroups = async (groupsToPersist: CorrelationGroup[]) => {
    for (const group of groupsToPersist) {
      try {
        // Upsert correlation group
        const { data: insertedGroup, error: groupError } = await supabase
          .from('correlation_groups')
          .upsert({
            source_ip: group.sourceIP,
            composite_score: group.compositeScore,
            phases: group.phases,
            is_multi_stage: group.isMultiStage,
            escalated: group.escalated,
            first_seen: group.firstSeen,
            last_seen: group.lastSeen,
            sequence_pattern: group.sequencePattern || null,
          }, {
            onConflict: 'source_ip',
          })
          .select('id')
          .single();

        if (groupError) {
          console.error('Failed to persist correlation group:', groupError);
          continue;
        }

        // Insert correlation events
        const eventInserts = group.events.map(e => ({
          group_id: insertedGroup.id,
          event_type: 'incident_log' as const,
          event_id: e.id,
          timestamp: e.timestamp,
          attack_type: e.attackType,
          phase: getPhase(e.attackType),
          threat_score: e.threatScore,
        }));

        const { error: eventsError } = await supabase
          .from('correlation_events')
          .insert(eventInserts);

        if (eventsError) {
          console.error('Failed to persist correlation events:', eventsError);
        }
      } catch (err) {
        console.error('Persistence error:', err);
      }
    }
  };

  const addEvent = useCallback((event: CorrelationEvent) => {
    eventsRef.current.push(event);
    return correlateEvents();
  }, [correlateEvents]);

  const addEvents = useCallback((newEvents: CorrelationEvent[]) => {
    eventsRef.current.push(...newEvents);
    return correlateEvents();
  }, [correlateEvents]);

  const clearEvents = useCallback(() => {
    eventsRef.current = [];
    setGroups([]);
  }, []);

  // Fetch historical groups from database
  const fetchHistoricalGroups = useCallback(async (hoursBack: number = 24) => {
    const since = new Date(Date.now() - hoursBack * 60 * 60 * 1000).toISOString();
    
    const { data, error } = await supabase
      .from('correlation_groups')
      .select(`
        *,
        correlation_events (*)
      `)
      .gte('created_at', since)
      .order('composite_score', { ascending: false })
      .limit(100);

    if (error) {
      console.error('Failed to fetch historical groups:', error);
      return [];
    }

    const mapped: CorrelationGroup[] = (data || []).map(g => ({
      id: g.id,
      sourceIP: g.source_ip,
      events: (g.correlation_events || []).map((e: any) => ({
        id: e.event_id,
        timestamp: e.timestamp,
        attackType: e.attack_type,
        severity: e.threat_score >= 80 ? 'critical' : e.threat_score >= 60 ? 'high' : 'medium',
        threatScore: e.threat_score,
      })),
      phases: g.phases as string[],
      compositeScore: g.composite_score,
      isMultiStage: g.is_multi_stage,
      firstSeen: g.first_seen,
      lastSeen: g.last_seen,
      escalated: g.escalated,
      sequencePattern: g.sequence_pattern || undefined,
      persisted: true,
    }));

    setHistoricalGroups(mapped);
    return mapped;
  }, []);

  // Escalate a group to incident_logs
  const escalateToIncident = useCallback(async (group: CorrelationGroup) => {
    const { error } = await supabase
      .from('incident_logs')
      .insert({
        incident_type: 'multi_stage_attack',
        severity: group.compositeScore >= 80 ? 'critical' : 'high',
        source_ip: group.sourceIP,
        status: 'open',
        details: {
          correlation_id: group.id,
          phases: group.phases,
          sequence_pattern: group.sequencePattern,
          composite_score: group.compositeScore,
          event_count: group.events.length,
          first_seen: group.firstSeen,
          last_seen: group.lastSeen,
        },
      });

    if (error) {
      console.error('Failed to escalate to incident:', error);
      return false;
    }
    return true;
  }, []);

  return { 
    groups, 
    historicalGroups,
    addEvent, 
    addEvents,
    correlateEvents, 
    clearEvents,
    fetchHistoricalGroups,
    escalateToIncident,
  };
}
