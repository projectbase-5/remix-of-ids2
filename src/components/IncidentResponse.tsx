import { useState, useCallback, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Textarea } from '@/components/ui/textarea';
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from '@/components/ui/select';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { useRealtimeSubscription } from '@/hooks/useRealtimeSubscription';
import RoleGate from '@/components/RoleGate';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  User, 
  FileText,
  MessageSquare,
  Target,
  Activity,
  ArrowRight,
  Pause,
  Play,
  RotateCcw,
  Flame,
  ChevronDown,
  ChevronRight,
  Search,
  Zap,
  Ban,
  Wifi,
  WifiOff,
  Bell,
  Gauge,
  Microscope,
  History,
} from 'lucide-react';
import { IncidentLog } from '@/hooks/useThreatIntelligence';

interface IncidentTimeline {
  id: string;
  timestamp: string;
  action: string;
  user: string;
  details?: string;
}

interface IncidentDetails extends IncidentLog {
  timeline: IncidentTimeline[];
  notes: string;
  assignee?: string;
  resolution?: string;
  impactScore: number;
  containmentStatus: 'not_started' | 'in_progress' | 'contained' | 'eradicated' | 'recovered';
}

interface ScoredIncident {
  id: string;
  source_ip: string;
  total_score: number;
  alert_count: number;
  attack_types: string[];
  severity: string;
  first_alert_at: string;
  last_alert_at: string;
  status: string;
  alert_ids: string[];
  sequence_pattern: string | null;
  created_at: string;
  updated_at: string;
}

const PLAYBOOKS = [
  {
    id: 'pb-malware',
    name: 'Malware Incident',
    description: 'Steps to contain and remediate malware infection',
    steps: [
      { order: 1, action: 'Isolate affected host', automated: true },
      { order: 2, action: 'Collect memory dump', automated: false },
      { order: 3, action: 'Identify malware family', automated: true },
      { order: 4, action: 'Block IOCs', automated: true },
      { order: 5, action: 'Scan for lateral movement', automated: true },
      { order: 6, action: 'Remediate affected systems', automated: false },
      { order: 7, action: 'Verify eradication', automated: false },
      { order: 8, action: 'Document lessons learned', automated: false },
    ],
  },
  {
    id: 'pb-phishing',
    name: 'Phishing Attack',
    description: 'Response procedure for phishing incidents',
    steps: [
      { order: 1, action: 'Identify affected users', automated: true },
      { order: 2, action: 'Block malicious URLs/domains', automated: true },
      { order: 3, action: 'Reset compromised credentials', automated: false },
      { order: 4, action: 'Scan mailboxes for similar emails', automated: true },
      { order: 5, action: 'Notify affected users', automated: true },
      { order: 6, action: 'Report to threat intel team', automated: false },
    ],
  },
  {
    id: 'pb-ddos',
    name: 'DDoS Attack',
    description: 'Mitigation steps for DDoS attacks',
    steps: [
      { order: 1, action: 'Activate DDoS mitigation', automated: true },
      { order: 2, action: 'Rate limit suspicious IPs', automated: true },
      { order: 3, action: 'Enable CDN caching', automated: true },
      { order: 4, action: 'Notify ISP/upstream provider', automated: false },
      { order: 5, action: 'Monitor attack traffic', automated: true },
      { order: 6, action: 'Document attack vectors', automated: false },
    ],
  },
  {
    id: 'pb-data-breach',
    name: 'Data Breach',
    description: 'Critical response for data breach incidents',
    steps: [
      { order: 1, action: 'Contain breach source', automated: true },
      { order: 2, action: 'Assess scope of exposure', automated: false },
      { order: 3, action: 'Preserve evidence', automated: true },
      { order: 4, action: 'Notify legal/compliance', automated: true },
      { order: 5, action: 'Prepare customer notification', automated: false },
      { order: 6, action: 'Engage forensics team', automated: false },
      { order: 7, action: 'File regulatory reports', automated: false },
      { order: 8, action: 'Implement additional controls', automated: false },
    ],
  },
];

export default function IncidentResponse({ isDemoMode }: { isDemoMode?: boolean }) {
  const [incidents, setIncidents] = useState<IncidentDetails[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [activePlaybook, setActivePlaybook] = useState<typeof PLAYBOOKS[0] | null>(null);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const [newNote, setNewNote] = useState('');
  const [activeTab, setActiveTab] = useState('incidents');

  // Priority Queue state
  const [scoredIncidents, setScoredIncidents] = useState<ScoredIncident[]>([]);
  const [scoredLoading, setScoredLoading] = useState(false);
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);
  const [linkedAlerts, setLinkedAlerts] = useState<Record<string, any[]>>({});

  // Response Actions state
  const [responseActions, setResponseActions] = useState<any[]>([]);
  const [responseLoading, setResponseLoading] = useState(false);
  const [executingAction, setExecutingAction] = useState<string | null>(null);

  const loadIncidents = useCallback(async () => {
    if (isDemoMode) return;
    setLoading(true);
    try {
      const { data, error } = await supabase
        .from('incident_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(100);

      if (error) throw error;

      const enhancedIncidents: IncidentDetails[] = (data || []).map((incident) => ({
        ...incident,
        details: (typeof incident.details === 'object' && incident.details !== null && !Array.isArray(incident.details)) 
          ? incident.details as Record<string, unknown> 
          : {},
        timeline: [
          {
            id: `tl-${incident.id}-1`,
            timestamp: incident.created_at,
            action: 'Incident created',
            user: 'System',
          },
        ],
        notes: '',
        impactScore: calculateImpactScore(incident.severity),
        containmentStatus: incident.status === 'resolved' ? 'recovered' : 'not_started',
      }));

      setIncidents(enhancedIncidents);
    } catch (error) {
      console.error('Error loading incidents:', error);
      toast.error('Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, [isDemoMode]);

  const loadScoredIncidents = useCallback(async () => {
    if (isDemoMode) return;
    setScoredLoading(true);
    try {
      const { data, error } = await supabase
        .from('scored_incidents')
        .select('*')
        .order('total_score', { ascending: false })
        .limit(50);

      if (error) throw error;

      setScoredIncidents((data || []).map((d) => ({
        ...d,
        attack_types: Array.isArray(d.attack_types) ? d.attack_types as string[] : [],
        alert_ids: Array.isArray(d.alert_ids) ? d.alert_ids as string[] : [],
      })));
    } catch (error) {
      console.error('Error loading scored incidents:', error);
    } finally {
      setScoredLoading(false);
    }
  }, [isDemoMode]);

  const loadResponseActions = useCallback(async () => {
    if (isDemoMode) return;
    setResponseLoading(true);
    try {
      const { data, error } = await supabase
        .from('response_actions')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (error) throw error;
      setResponseActions(data || []);
    } catch (error) {
      console.error('Error loading response actions:', error);
    } finally {
      setResponseLoading(false);
    }
  }, [isDemoMode]);

  useEffect(() => {
    if (isDemoMode) {
      import('@/lib/demoData').then(({ demoIncidentLogs, demoScoredIncidents, demoResponseActions }) => {
        const enhancedIncidents: IncidentDetails[] = demoIncidentLogs.map((incident: any) => ({
          ...incident,
          timeline: [{ id: `tl-${incident.id}-1`, timestamp: incident.created_at, action: 'Incident created', user: 'System' }],
          notes: '',
          impactScore: calculateImpactScore(incident.severity),
          containmentStatus: incident.status === 'resolved' ? 'recovered' as const : 'not_started' as const,
        }));
        setIncidents(enhancedIncidents);
        setScoredIncidents(demoScoredIncidents as ScoredIncident[]);
        setResponseActions(demoResponseActions);
        setLoading(false);
        setScoredLoading(false);
        setResponseLoading(false);
      });
      return;
    }
    loadIncidents();
    loadScoredIncidents();
    loadResponseActions();
  }, [isDemoMode, loadIncidents, loadScoredIncidents, loadResponseActions]);

  useRealtimeSubscription('incident_logs', ['INSERT', 'UPDATE'], useCallback(() => {
    loadIncidents();
  }, [loadIncidents]));

  useRealtimeSubscription('scored_incidents', ['INSERT', 'UPDATE'], useCallback(() => {
    loadScoredIncidents();
  }, [loadScoredIncidents]));

  useRealtimeSubscription('response_actions', ['INSERT', 'UPDATE'], useCallback(() => {
    loadResponseActions();
  }, [loadResponseActions]));

  const calculateImpactScore = (severity: string): number => {
    switch (severity.toLowerCase()) {
      case 'critical': return 95;
      case 'high': return 75;
      case 'medium': return 50;
      case 'low': return 25;
      default: return 30;
    }
  };

  const updateIncidentStatus = async (incidentId: string, status: string) => {
    try {
      const { error } = await supabase
        .from('incident_logs')
        .update({ status })
        .eq('id', incidentId);

      if (error) throw error;

      setIncidents(prev => prev.map(inc => 
        inc.id === incidentId ? { ...inc, status } : inc
      ));

      if (selectedIncident?.id === incidentId) {
        setSelectedIncident(prev => prev ? { ...prev, status } : null);
      }

      toast.success(`Incident status updated to ${status}`);
    } catch (error) {
      console.error('Error updating incident:', error);
      toast.error('Failed to update incident');
    }
  };

  const addTimelineEntry = (action: string) => {
    if (!selectedIncident) return;

    const entry: IncidentTimeline = {
      id: `tl-${Date.now()}`,
      timestamp: new Date().toISOString(),
      action,
      user: 'Security Analyst',
    };

    setSelectedIncident(prev => prev ? {
      ...prev,
      timeline: [...prev.timeline, entry],
    } : null);

    setIncidents(prev => prev.map(inc =>
      inc.id === selectedIncident.id
        ? { ...inc, timeline: [...inc.timeline, entry] }
        : inc
    ));
  };

  const executePlaybookStep = async (stepOrder: number, action: string, automated: boolean) => {
    addTimelineEntry(`Executing: ${action}`);
    await new Promise(resolve => setTimeout(resolve, automated ? 500 : 1000));
    setCompletedSteps(prev => [...prev, stepOrder]);
    addTimelineEntry(`Completed: ${action}`);
    toast.success(`Step ${stepOrder} completed: ${action}`);
  };

  const startPlaybook = (playbook: typeof PLAYBOOKS[0]) => {
    setActivePlaybook(playbook);
    setCompletedSteps([]);
    addTimelineEntry(`Started playbook: ${playbook.name}`);
    toast.info(`Starting playbook: ${playbook.name}`);
  };

  const addNote = () => {
    if (!newNote.trim() || !selectedIncident) return;
    addTimelineEntry(`Note added: ${newNote}`);
    setSelectedIncident(prev => prev ? {
      ...prev,
      notes: prev.notes + (prev.notes ? '\n' : '') + `[${new Date().toLocaleString()}] ${newNote}`,
    } : null);
    setNewNote('');
    toast.success('Note added');
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'resolved': return 'bg-green-500 text-white';
      case 'pending': return 'bg-yellow-500 text-yellow-50';
      case 'investigating': return 'bg-blue-500 text-white';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-destructive text-destructive-foreground';
      case 'high': return 'bg-red-500 text-white';
      case 'medium': return 'bg-yellow-500 text-yellow-50';
      case 'low': return 'bg-green-500 text-white';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getContainmentProgress = (status: IncidentDetails['containmentStatus']): number => {
    switch (status) {
      case 'not_started': return 0;
      case 'in_progress': return 25;
      case 'contained': return 50;
      case 'eradicated': return 75;
      case 'recovered': return 100;
      default: return 0;
    }
  };

  const getScoreBadgeColor = (score: number) => {
    if (score >= 100) return 'bg-destructive text-destructive-foreground';
    if (score >= 60) return 'bg-red-500 text-white';
    if (score >= 30) return 'bg-yellow-500 text-yellow-50';
    return 'bg-muted text-muted-foreground';
  };

  const triggerScoring = async () => {
    try {
      toast.info('Running incident scoring...');
      const { data, error } = await supabase.functions.invoke('score-incidents', {
        body: { window_minutes: 60 },
      });
      if (error) throw error;
      toast.success(`Scored ${data?.scored || 0} incidents from ${data?.total_alerts_processed || 0} alerts`);
      loadScoredIncidents();
    } catch (err) {
      console.error('Scoring error:', err);
      toast.error('Failed to run scoring');
    }
  };

  const investigateScoredIncident = async (scored: ScoredIncident) => {
    try {
      // Create a formal incident_log entry
      const { error } = await supabase.from('incident_logs').insert({
        incident_type: scored.attack_types.join(' + ') || 'Aggregated Incident',
        severity: scored.severity,
        source_ip: scored.source_ip,
        status: 'investigating',
        details: {
          scored_incident_id: scored.id,
          total_score: scored.total_score,
          attack_types: scored.attack_types,
          alert_count: scored.alert_count,
          sequence_pattern: scored.sequence_pattern,
        },
      });

      if (error) throw error;

      // Update scored incident status
      await supabase
        .from('scored_incidents')
        .update({ status: 'investigating' })
        .eq('id', scored.id);

      toast.success('Promoted to formal incident for investigation');
      loadIncidents();
      loadScoredIncidents();
    } catch (err) {
      console.error('Error promoting incident:', err);
      toast.error('Failed to promote incident');
    }
  };

  const loadLinkedAlerts = async (scoredId: string, alertIds: string[]) => {
    if (linkedAlerts[scoredId]) {
      setExpandedIncidentId(expandedIncidentId === scoredId ? null : scoredId);
      return;
    }

    if (alertIds.length === 0) {
      setLinkedAlerts(prev => ({ ...prev, [scoredId]: [] }));
      setExpandedIncidentId(scoredId);
      return;
    }

    try {
      const { data } = await supabase
        .from('live_alerts')
        .select('id, alert_type, severity, source_ip, destination_ip, description, created_at')
        .in('id', alertIds.slice(0, 20));

      setLinkedAlerts(prev => ({ ...prev, [scoredId]: data || [] }));
      setExpandedIncidentId(scoredId);
    } catch {
      setExpandedIncidentId(scoredId);
    }
  };

  const executeResponseAction = async (
    actionType: string,
    targetIp: string,
    incidentId?: string,
    scoredIncidentId?: string,
    parameters?: Record<string, unknown>,
  ) => {
    setExecutingAction(actionType);
    try {
      const { data, error } = await supabase.functions.invoke('execute-response', {
        body: {
          action_type: actionType,
          target_ip: targetIp,
          incident_id: incidentId || null,
          scored_incident_id: scoredIncidentId || null,
          parameters: parameters || {},
          triggered_by: 'dashboard',
        },
      });
      if (error) throw error;
      toast.success(`${actionType.replace(/_/g, ' ')} executed for ${targetIp}`);
      loadResponseActions();
    } catch (err) {
      console.error('Response action error:', err);
      toast.error(`Failed to execute ${actionType}`);
    } finally {
      setExecutingAction(null);
    }
  };

  const ACTION_BUTTONS = [
    { type: 'block_ip', label: 'Block IP', icon: Ban, variant: 'destructive' as const },
    { type: 'rate_limit', label: 'Rate Limit', icon: Gauge, variant: 'outline' as const },
    { type: 'isolate_host', label: 'Isolate Host', icon: WifiOff, variant: 'destructive' as const },
    { type: 'send_notification', label: 'Notify SOC', icon: Bell, variant: 'outline' as const },
    { type: 'capture_forensics', label: 'Capture Forensics', icon: Microscope, variant: 'outline' as const },
  ];

  const getActionStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500 text-white';
      case 'executing': return 'bg-blue-500 text-white';
      case 'failed': return 'bg-destructive text-destructive-foreground';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Open Incidents</p>
                <p className="text-2xl font-bold text-destructive">
                  {incidents.filter(i => i.status !== 'resolved').length}
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical</p>
                <p className="text-2xl font-bold text-red-500">
                  {incidents.filter(i => i.severity === 'critical').length}
                </p>
              </div>
              <Target className="h-8 w-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Scored Incidents</p>
                <p className="text-2xl font-bold text-primary">
                  {scoredIncidents.filter(s => s.status === 'open').length}
                </p>
              </div>
              <Flame className="h-8 w-8 text-primary" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Resolved Today</p>
                <p className="text-2xl font-bold text-green-500">
                  {incidents.filter(i => 
                    i.status === 'resolved' && 
                    new Date(i.created_at).toDateString() === new Date().toDateString()
                  ).length}
                </p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top-level tabs: Priority Queue vs traditional Incidents */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="priority-queue" className="flex items-center gap-1.5">
            <Flame className="h-4 w-4" />
            Priority Queue
          </TabsTrigger>
          <TabsTrigger value="incidents" className="flex items-center gap-1.5">
            <Shield className="h-4 w-4" />
            Incidents
          </TabsTrigger>
          <TabsTrigger value="response-actions" className="flex items-center gap-1.5">
            <Zap className="h-4 w-4" />
            Response Actions
          </TabsTrigger>
        </TabsList>

        {/* ============== PRIORITY QUEUE TAB ============== */}
        <TabsContent value="priority-queue">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Flame className="h-5 w-5" />
                    Incident Priority Queue
                  </CardTitle>
                  <CardDescription>
                    Alerts aggregated by source IP, scored by severity + diversity + kill chain sequence
                  </CardDescription>
                </div>
                <Button onClick={triggerScoring} size="sm">
                  <Zap className="h-4 w-4 mr-1" />
                  Run Scoring
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {scoredLoading ? (
                <div className="text-center text-muted-foreground py-8">Loading scored incidents...</div>
              ) : scoredIncidents.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">
                  <p>No scored incidents yet.</p>
                  <p className="text-sm mt-1">Click "Run Scoring" to aggregate recent alerts.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {scoredIncidents.map((scored) => (
                    <div key={scored.id} className="border rounded-lg">
                      <div
                        className="p-4 cursor-pointer hover:bg-muted/30 transition-colors"
                        onClick={() => loadLinkedAlerts(scored.id, scored.alert_ids)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {expandedIncidentId === scored.id ? (
                              <ChevronDown className="h-4 w-4 text-muted-foreground" />
                            ) : (
                              <ChevronRight className="h-4 w-4 text-muted-foreground" />
                            )}
                            <Badge className={getScoreBadgeColor(scored.total_score)}>
                              Score: {scored.total_score}
                            </Badge>
                            <Badge className={getSeverityColor(scored.severity)}>
                              {scored.severity}
                            </Badge>
                            <span className="font-mono text-sm">{scored.source_ip}</span>
                            <span className="text-sm text-muted-foreground">
                              {scored.alert_count} alert{scored.alert_count !== 1 ? 's' : ''}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs">
                              {scored.status}
                            </Badge>
                            {scored.status === 'open' && (
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  investigateScoredIncident(scored);
                                }}
                              >
                                <Search className="h-3 w-3 mr-1" />
                                Investigate
                              </Button>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-2 mt-2 ml-7">
                          {scored.attack_types.map((type) => (
                            <Badge key={type} variant="secondary" className="text-xs">
                              {type}
                            </Badge>
                          ))}
                          {scored.sequence_pattern && (
                            <Badge className="bg-primary/20 text-primary text-xs border border-primary/30">
                              ⛓ {scored.sequence_pattern}
                            </Badge>
                          )}
                        </div>

                        <div className="text-xs text-muted-foreground mt-2 ml-7">
                          Window: {new Date(scored.first_alert_at).toLocaleString()} → {new Date(scored.last_alert_at).toLocaleString()}
                        </div>
                      </div>

                      {expandedIncidentId === scored.id && (
                        <div className="border-t px-4 py-3 bg-muted/20">
                          <p className="text-sm font-medium mb-2">Linked Alerts</p>
                          {(linkedAlerts[scored.id] || []).length === 0 ? (
                            <p className="text-xs text-muted-foreground">No linked alerts found</p>
                          ) : (
                            <div className="space-y-1.5 max-h-48 overflow-auto">
                              {(linkedAlerts[scored.id] || []).map((alert: any) => (
                                <div key={alert.id} className="flex items-center gap-2 text-xs p-1.5 bg-background rounded">
                                  <Badge className={getSeverityColor(alert.severity)} >
                                    {alert.severity}
                                  </Badge>
                                  <span className="font-medium">{alert.alert_type}</span>
                                  <span className="text-muted-foreground truncate flex-1">
                                    {alert.description}
                                  </span>
                                  <span className="text-muted-foreground">
                                    {new Date(alert.created_at).toLocaleTimeString()}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ============== TRADITIONAL INCIDENTS TAB ============== */}
        <TabsContent value="incidents">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Incident List */}
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Incidents</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[600px]">
                  <div className="space-y-2">
                    {loading ? (
                      <div className="text-center text-muted-foreground py-4">Loading...</div>
                    ) : incidents.length === 0 ? (
                      <div className="text-center text-muted-foreground py-4">No incidents</div>
                    ) : (
                      incidents.map((incident) => (
                        <div
                          key={incident.id}
                          className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                            selectedIncident?.id === incident.id 
                              ? 'border-primary bg-primary/5' 
                              : 'hover:bg-muted/50'
                          }`}
                          onClick={() => {
                            setSelectedIncident(incident);
                            setActivePlaybook(null);
                            setCompletedSteps([]);
                          }}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <Badge className={getSeverityColor(incident.severity)}>
                              {incident.severity}
                            </Badge>
                            <Badge className={getStatusColor(incident.status)}>
                              {incident.status}
                            </Badge>
                          </div>
                          <div className="font-medium text-sm truncate">
                            {incident.incident_type}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {incident.source_ip && `From: ${incident.source_ip}`}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(incident.created_at).toLocaleString()}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            {/* Incident Details */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <FileText className="h-5 w-5" />
                  <span>Incident Details</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!selectedIncident ? (
                  <div className="text-center text-muted-foreground py-16">
                    Select an incident to view details
                  </div>
                ) : (
                  <Tabs defaultValue="overview" className="space-y-4">
                    <TabsList className="grid w-full grid-cols-4">
                      <TabsTrigger value="overview">Overview</TabsTrigger>
                      <TabsTrigger value="timeline">Timeline</TabsTrigger>
                      <TabsTrigger value="playbook">Playbook</TabsTrigger>
                      <TabsTrigger value="notes">Notes</TabsTrigger>
                    </TabsList>

                    <TabsContent value="overview">
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="text-sm text-muted-foreground">Type</label>
                            <p className="font-medium">{selectedIncident.incident_type}</p>
                          </div>
                          <div>
                            <label className="text-sm text-muted-foreground">Severity</label>
                            <Badge className={getSeverityColor(selectedIncident.severity)}>
                              {selectedIncident.severity}
                            </Badge>
                          </div>
                          <div>
                            <label className="text-sm text-muted-foreground">Source IP</label>
                            <p className="font-mono">{selectedIncident.source_ip || 'N/A'}</p>
                          </div>
                          <div>
                            <label className="text-sm text-muted-foreground">Destination IP</label>
                            <p className="font-mono">{selectedIncident.destination_ip || 'N/A'}</p>
                          </div>
                        </div>

                        <div>
                          <label className="text-sm text-muted-foreground">Impact Score</label>
                          <div className="flex items-center space-x-3 mt-1">
                            <Progress value={selectedIncident.impactScore} className="flex-1" />
                            <span className="font-bold">{selectedIncident.impactScore}%</span>
                          </div>
                        </div>

                        <div>
                          <label className="text-sm text-muted-foreground">Containment Status</label>
                          <div className="flex items-center space-x-3 mt-1">
                            <Progress 
                              value={getContainmentProgress(selectedIncident.containmentStatus)} 
                              className="flex-1" 
                            />
                            <Badge variant="outline">{selectedIncident.containmentStatus}</Badge>
                          </div>
                        </div>

                        <div>
                          <label className="text-sm text-muted-foreground">Update Status</label>
                          <Select
                            value={selectedIncident.status}
                            onValueChange={(value) => updateIncidentStatus(selectedIncident.id, value)}
                          >
                            <SelectTrigger className="mt-1">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="pending">Pending</SelectItem>
                              <SelectItem value="investigating">Investigating</SelectItem>
                              <SelectItem value="contained">Contained</SelectItem>
                              <SelectItem value="resolved">Resolved</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </TabsContent>

                    <TabsContent value="timeline">
                      <ScrollArea className="h-[400px]">
                        <div className="space-y-4">
                          {selectedIncident.timeline.map((entry, index) => (
                            <div key={entry.id} className="flex items-start space-x-3">
                              <div className="flex flex-col items-center">
                                <div className="w-3 h-3 bg-primary rounded-full" />
                                {index < selectedIncident.timeline.length - 1 && (
                                  <div className="w-0.5 h-full bg-border mt-1" />
                                )}
                              </div>
                              <div className="flex-1 pb-4">
                                <div className="flex items-center space-x-2">
                                  <span className="text-sm font-medium">{entry.action}</span>
                                </div>
                                <div className="flex items-center space-x-2 text-xs text-muted-foreground mt-1">
                                  <User className="h-3 w-3" />
                                  <span>{entry.user}</span>
                                  <span>•</span>
                                  <Clock className="h-3 w-3" />
                                  <span>{new Date(entry.timestamp).toLocaleString()}</span>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </TabsContent>

                    <TabsContent value="playbook">
                      {!activePlaybook ? (
                        <div className="grid gap-4 md:grid-cols-2">
                          {PLAYBOOKS.map((playbook) => (
                            <Card key={playbook.id} className="cursor-pointer hover:border-primary transition-colors">
                              <CardHeader className="pb-2">
                                <CardTitle className="text-lg">{playbook.name}</CardTitle>
                                <CardDescription>{playbook.description}</CardDescription>
                              </CardHeader>
                              <CardContent>
                                <div className="text-sm text-muted-foreground mb-3">
                                  {playbook.steps.length} steps
                                </div>
                                <Button onClick={() => startPlaybook(playbook)} className="w-full">
                                  <Play className="h-4 w-4 mr-2" />
                                  Start Playbook
                                </Button>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      ) : (
                        <div className="space-y-4">
                          <div className="flex items-center justify-between">
                            <h4 className="font-medium">{activePlaybook.name}</h4>
                            <Button variant="outline" size="sm" onClick={() => setActivePlaybook(null)}>
                              <RotateCcw className="h-4 w-4 mr-1" />
                              Reset
                            </Button>
                          </div>
                          <Progress 
                            value={(completedSteps.length / activePlaybook.steps.length) * 100} 
                          />
                          <div className="space-y-2">
                            {activePlaybook.steps.map((step) => (
                              <div 
                                key={step.order}
                                className={`p-3 rounded border flex items-center justify-between ${
                                  completedSteps.includes(step.order) ? 'bg-green-50 border-green-200' : ''
                                }`}
                              >
                                <div className="flex items-center space-x-3">
                                  {completedSteps.includes(step.order) ? (
                                    <CheckCircle className="h-5 w-5 text-green-500" />
                                  ) : (
                                    <div className="w-5 h-5 rounded-full border-2 flex items-center justify-center text-xs">
                                      {step.order}
                                    </div>
                                  )}
                                  <span className={completedSteps.includes(step.order) ? 'text-muted-foreground line-through' : ''}>
                                    {step.action}
                                  </span>
                                  <Badge variant={step.automated ? 'default' : 'outline'}>
                                    {step.automated ? 'Auto' : 'Manual'}
                                  </Badge>
                                </div>
                                {!completedSteps.includes(step.order) && (
                                  <Button
                                    size="sm"
                                    onClick={() => executePlaybookStep(step.order, step.action, step.automated)}
                                    disabled={step.order > 1 && !completedSteps.includes(step.order - 1)}
                                  >
                                    <ArrowRight className="h-4 w-4" />
                                  </Button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </TabsContent>

                    <TabsContent value="notes">
                      <div className="space-y-4">
                        <div className="flex space-x-2">
                          <Textarea
                            placeholder="Add investigation notes..."
                            value={newNote}
                            onChange={(e) => setNewNote(e.target.value)}
                            className="flex-1"
                          />
                          <Button onClick={addNote} disabled={!newNote.trim()}>
                            <MessageSquare className="h-4 w-4 mr-1" />
                            Add
                          </Button>
                        </div>
                        {selectedIncident.notes && (
                          <div className="p-4 rounded border bg-muted/50">
                            <pre className="text-sm whitespace-pre-wrap font-sans">
                              {selectedIncident.notes}
                            </pre>
                          </div>
                        )}
                      </div>
                    </TabsContent>
                  </Tabs>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ============== RESPONSE ACTIONS TAB ============== */}
        <TabsContent value="response-actions">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Quick Actions Panel */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Quick Actions
                </CardTitle>
                <CardDescription>
                  Execute response actions against a target IP
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm text-muted-foreground">Target IP</label>
                  <input
                    id="response-target-ip"
                    type="text"
                    placeholder="e.g. 10.0.0.50"
                    className="mt-1 w-full rounded-md border bg-background px-3 py-2 text-sm"
                  />
                </div>
                <div className="space-y-2">
                  {ACTION_BUTTONS.map(({ type, label, icon: Icon, variant }) => (
                    <Button
                      key={type}
                      variant={variant}
                      className="w-full justify-start"
                      disabled={executingAction !== null}
                      onClick={() => {
                        const ipInput = document.getElementById('response-target-ip') as HTMLInputElement;
                        const ip = ipInput?.value?.trim();
                        if (!ip) {
                          toast.error('Enter a target IP address');
                          return;
                        }
                        executeResponseAction(type, ip);
                      }}
                    >
                      <Icon className="h-4 w-4 mr-2" />
                      {executingAction === type ? 'Executing...' : label}
                    </Button>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Audit Log */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <History className="h-5 w-5" />
                      Response Audit Log
                    </CardTitle>
                    <CardDescription>
                      All executed response actions with status and results
                    </CardDescription>
                  </div>
                  <Button variant="outline" size="sm" onClick={loadResponseActions}>
                    <RotateCcw className="h-4 w-4 mr-1" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  {responseLoading ? (
                    <div className="text-center text-muted-foreground py-8">Loading...</div>
                  ) : responseActions.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      No response actions executed yet
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {responseActions.map((action: any) => (
                        <div key={action.id} className="p-3 border rounded-lg">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge className={getActionStatusColor(action.status)}>
                                {action.status}
                              </Badge>
                              <span className="font-medium text-sm">
                                {action.action_type.replace(/_/g, ' ')}
                              </span>
                              {action.target_ip && (
                                <span className="font-mono text-xs text-muted-foreground">
                                  → {action.target_ip}
                                </span>
                              )}
                            </div>
                            <Badge variant="outline" className="text-xs">
                              {action.triggered_by}
                            </Badge>
                          </div>
                          {action.result && (
                            <div className="mt-2 text-xs text-muted-foreground bg-muted/50 rounded p-2">
                              {(action.result as any)?.message || JSON.stringify(action.result)}
                            </div>
                          )}
                          <div className="text-xs text-muted-foreground mt-1">
                            {new Date(action.created_at).toLocaleString()}
                            {action.completed_at && (
                              <span> • Completed: {new Date(action.completed_at).toLocaleString()}</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
