import { useEffect, useCallback, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { GitBranch, AlertTriangle, Shield, Trash2, History, ArrowRight, ExternalLink } from 'lucide-react';
import { useThreatCorrelation, KILL_CHAIN_PHASES, ATTACK_SEQUENCES, type CorrelationGroup } from '@/hooks/useThreatCorrelation';
import { useCorrelationAggregator, type AggregatedEvent } from '@/hooks/useCorrelationAggregator';
import { supabase } from '@/integrations/supabase/client';
import { useRealtimeSubscription } from '@/hooks/useRealtimeSubscription';
import { toast } from 'sonner';

const CorrelationEngine = ({ isDemoMode }: { isDemoMode?: boolean }) => {
  const [historicalMode, setHistoricalMode] = useState(false);
  const [windowMinutes, setWindowMinutes] = useState('15');
  const [demoGroups, setDemoGroups] = useState<CorrelationGroup[]>([]);
  
  const { 
    groups, 
    historicalGroups,
    addEvent, 
    addEvents,
    clearEvents,
    fetchHistoricalGroups,
    escalateToIncident,
  } = useThreatCorrelation({ 
    windowMinutes: parseInt(windowMinutes), 
    persistGroups: true 
  });

  const { fetchAllEvents } = useCorrelationAggregator({
    windowMinutes: parseInt(windowMinutes),
    includePredictions: true,
  });

  // Fetch and correlate events from all sources
  useEffect(() => {
    if (isDemoMode) {
      import('@/lib/demoData').then(({ demoCorrelationGroups }) => {
        setDemoGroups(demoCorrelationGroups as unknown as CorrelationGroup[]);
      });
      return;
    }
    const loadEvents = async () => {
      const events = await fetchAllEvents(parseInt(windowMinutes));
      if (events.length > 0) {
        addEvents(events);
      }
    };
    loadEvents();
  }, [isDemoMode, windowMinutes, fetchAllEvents, addEvents]);

  // Historical mode
  useEffect(() => {
    if (historicalMode) {
      fetchHistoricalGroups(24);
    }
  }, [historicalMode, fetchHistoricalGroups]);

  // Realtime subscription for new incidents
  const handleNewIncident = useCallback((payload: any) => {
    const incident = payload.new;
    if (incident) {
      addEvent({
        id: incident.id,
        timestamp: incident.created_at,
        sourceIP: incident.source_ip || undefined,
        destinationIP: incident.destination_ip || undefined,
        attackType: incident.incident_type,
        severity: incident.severity,
        threatScore: (incident.details as any)?.threat_score || 50,
      });
    }
  }, [addEvent]);
  useRealtimeSubscription('incident_logs', ['INSERT'], handleNewIncident);

  // Realtime subscription for new alerts
  const handleNewAlert = useCallback((payload: any) => {
    const alert = payload.new;
    if (alert) {
      addEvent({
        id: alert.id,
        timestamp: alert.created_at,
        sourceIP: alert.source_ip || undefined,
        destinationIP: alert.destination_ip || undefined,
        attackType: alert.alert_type,
        severity: alert.severity,
        threatScore: (alert.metadata as any)?.threat_score || 50,
      });
    }
  }, [addEvent]);
  useRealtimeSubscription('live_alerts', ['INSERT'], handleNewAlert);

  const handleEscalate = async (group: CorrelationGroup) => {
    const success = await escalateToIncident(group);
    if (success) {
      toast.success(`Escalated attack chain from ${group.sourceIP} to incidents`);
    } else {
      toast.error('Failed to escalate to incident');
    }
  };

  const severityColor = (score: number) =>
    score >= 80 ? 'text-destructive' : score >= 60 ? 'text-yellow-500' : score >= 40 ? 'text-orange-400' : 'text-muted-foreground';

  const SequenceBadge = ({ pattern }: { pattern?: string }) => {
    if (!pattern) return null;
    const sequence = ATTACK_SEQUENCES[pattern as keyof typeof ATTACK_SEQUENCES];
    if (!sequence) return null;

    const labels = sequence.map(p => KILL_CHAIN_PHASES.find(k => k.phase === p)?.label || p);
    
    return (
      <Badge variant="outline" className="text-xs bg-destructive/10 border-destructive/30">
        {labels.map((l, i) => (
          <span key={i} className="flex items-center">
            {l}
            {i < labels.length - 1 && <ArrowRight className="h-3 w-3 mx-0.5" />}
          </span>
        ))}
      </Badge>
    );
  };

  const EventSourceBadge = ({ source }: { source?: string }) => {
    if (!source) return null;
    const colors: Record<string, string> = {
      'incident_log': 'bg-blue-500/20 text-blue-400',
      'live_alert': 'bg-orange-500/20 text-orange-400',
      'prediction': 'bg-purple-500/20 text-purple-400',
    };
    return (
      <span className={`text-[10px] px-1.5 py-0.5 rounded ${colors[source] || ''}`}>
        {source.replace('_', ' ')}
      </span>
    );
  };

  const GroupCard = ({ group }: { group: CorrelationGroup }) => (
    <Card className={group.escalated ? 'border-destructive' : ''}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            {group.escalated && <AlertTriangle className="h-4 w-4 text-destructive" />}
            <span className="font-mono">{group.sourceIP}</span>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant={group.isMultiStage ? 'destructive' : 'secondary'}>
              {group.isMultiStage ? 'Multi-Stage' : 'Single Phase'}
            </Badge>
            <span className={`text-lg font-bold ${severityColor(group.compositeScore)}`}>{group.compositeScore}</span>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <CardDescription>
            {group.events.length} events · {new Date(group.firstSeen).toLocaleTimeString()} – {new Date(group.lastSeen).toLocaleTimeString()}
          </CardDescription>
          <SequenceBadge pattern={group.sequencePattern} />
          {group.persisted && <Badge variant="outline" className="text-xs">Persisted</Badge>}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Kill chain progress */}
        <div className="flex gap-1">
          {KILL_CHAIN_PHASES.map(phase => {
            const active = group.phases.includes(phase.phase);
            return (
              <div key={phase.phase} className="flex-1 text-center">
                <div className={`text-[10px] mb-1 ${active ? 'font-bold text-foreground' : 'text-muted-foreground'}`}>{phase.label}</div>
                <div className={`h-2 rounded-full ${active ? 'bg-destructive' : 'bg-muted'}`} />
              </div>
            );
          })}
        </div>

        {/* Event list */}
        <div className="space-y-1 max-h-40 overflow-y-auto">
          {group.events.slice(0, 10).map(e => (
            <div key={e.id} className="flex items-center justify-between text-xs px-2 py-1 rounded bg-muted/50">
              <div className="flex items-center gap-2">
                <span>{e.attackType}</span>
                <EventSourceBadge source={(e as any).eventSource} />
              </div>
              <span className="text-muted-foreground">{new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
          ))}
          {group.events.length > 10 && <div className="text-xs text-muted-foreground text-center">+{group.events.length - 10} more</div>}
        </div>

        {/* Actions */}
        {!group.persisted && group.isMultiStage && (
          <Button 
            variant="outline" 
            size="sm" 
            className="w-full"
            onClick={() => handleEscalate(group)}
          >
            <ExternalLink className="h-4 w-4 mr-1" />
            Escalate to Incident
          </Button>
        )}
      </CardContent>
    </Card>
  );

  const displayGroups = isDemoMode ? demoGroups : (historicalMode ? historicalGroups : groups);
  const multiStage = displayGroups.filter(g => g.isMultiStage);

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center space-x-2">
            <Switch
              id="historical-mode"
              checked={historicalMode}
              onCheckedChange={setHistoricalMode}
            />
            <Label htmlFor="historical-mode" className="flex items-center gap-1">
              <History className="h-4 w-4" />
              Historical Mode
            </Label>
          </div>
          
          <Select value={windowMinutes} onValueChange={setWindowMinutes}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="15">15 min</SelectItem>
              <SelectItem value="60">1 hour</SelectItem>
              <SelectItem value="360">6 hours</SelectItem>
              <SelectItem value="1440">24 hours</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Button variant="outline" size="sm" onClick={clearEvents}>
          <Trash2 className="h-4 w-4 mr-1" />Clear
        </Button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6 text-center">
            <div className="text-3xl font-bold">{displayGroups.length}</div>
            <div className="text-xs text-muted-foreground">Correlation Groups</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6 text-center">
            <div className="text-3xl font-bold text-destructive">{multiStage.length}</div>
            <div className="text-xs text-muted-foreground">Multi-Stage Attacks</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6 text-center">
            <div className="text-3xl font-bold">{displayGroups.filter(g => g.escalated).length}</div>
            <div className="text-xs text-muted-foreground">Escalated</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6 text-center">
            <div className="text-3xl font-bold">{displayGroups.reduce((s, g) => s + g.events.length, 0)}</div>
            <div className="text-xs text-muted-foreground">Total Correlated Events</div>
          </CardContent>
        </Card>
      </div>

      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <GitBranch className="h-5 w-5" />
          {historicalMode ? 'Historical Attack Chains' : 'Live Attack Chains'}
        </h2>
      </div>

      {displayGroups.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
            {historicalMode 
              ? 'No historical attack chains found in the last 24 hours'
              : `No correlated attack chains detected in the last ${windowMinutes} minutes`}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {displayGroups.map(g => <GroupCard key={g.id} group={g} />)}
        </div>
      )}
    </div>
  );
};

export default CorrelationEngine;
