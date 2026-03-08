import { useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { GitBranch, AlertTriangle, Shield, Trash2 } from 'lucide-react';
import { useThreatCorrelation, KILL_CHAIN_PHASES, type CorrelationGroup } from '@/hooks/useThreatCorrelation';
import { supabase } from '@/integrations/supabase/client';
import { useRealtimeSubscription } from '@/hooks/useRealtimeSubscription';

const CorrelationEngine = () => {
  const { groups, addEvent, clearEvents } = useThreatCorrelation(15);

  // Poll incident_logs to feed correlation engine
  useEffect(() => {
    const fetchRecent = async () => {
      const since = new Date(Date.now() - 15 * 60 * 1000).toISOString();
      const { data } = await supabase
        .from('incident_logs')
        .select('*')
        .gte('created_at', since)
        .order('created_at', { ascending: false })
        .limit(200);
      if (data) {
        data.forEach(incident => {
          addEvent({
            id: incident.id,
            timestamp: incident.created_at,
            sourceIP: incident.source_ip || undefined,
            destinationIP: incident.destination_ip || undefined,
            attackType: incident.incident_type,
            severity: incident.severity,
            threatScore: (incident.details as any)?.threat_score || 50,
          });
        });
      }
    };
    fetchRecent();
    // No more polling - realtime handles new events
  }, [addEvent]);

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

  const severityColor = (score: number) =>
    score >= 80 ? 'text-destructive' : score >= 60 ? 'text-yellow-500' : score >= 40 ? 'text-orange-400' : 'text-muted-foreground';

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
        <CardDescription>{group.events.length} events · {new Date(group.firstSeen).toLocaleTimeString()} – {new Date(group.lastSeen).toLocaleTimeString()}</CardDescription>
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
              <span>{e.attackType}</span>
              <span className="text-muted-foreground">{new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
          ))}
          {group.events.length > 10 && <div className="text-xs text-muted-foreground text-center">+{group.events.length - 10} more</div>}
        </div>
      </CardContent>
    </Card>
  );

  const multiStage = groups.filter(g => g.isMultiStage);
  const singlePhase = groups.filter(g => !g.isMultiStage);

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{groups.length}</div><div className="text-xs text-muted-foreground">Correlation Groups</div></CardContent></Card>
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold text-destructive">{multiStage.length}</div><div className="text-xs text-muted-foreground">Multi-Stage Attacks</div></CardContent></Card>
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{groups.filter(g => g.escalated).length}</div><div className="text-xs text-muted-foreground">Escalated</div></CardContent></Card>
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{groups.reduce((s, g) => s + g.events.length, 0)}</div><div className="text-xs text-muted-foreground">Total Correlated Events</div></CardContent></Card>
      </div>

      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold flex items-center gap-2"><GitBranch className="h-5 w-5" />Attack Chains</h2>
        <Button variant="outline" size="sm" onClick={clearEvents}><Trash2 className="h-4 w-4 mr-1" />Clear</Button>
      </div>

      {groups.length === 0 ? (
        <Card><CardContent className="py-12 text-center text-muted-foreground"><Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />No correlated attack chains detected in the last 15 minutes</CardContent></Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {groups.map(g => <GroupCard key={g.id} group={g} />)}
        </div>
      )}
    </div>
  );
};

export default CorrelationEngine;
