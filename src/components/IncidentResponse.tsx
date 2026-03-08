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
  RotateCcw
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

export default function IncidentResponse() {
  const [incidents, setIncidents] = useState<IncidentDetails[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [activePlaybook, setActivePlaybook] = useState<typeof PLAYBOOKS[0] | null>(null);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const [newNote, setNewNote] = useState('');

  const loadIncidents = useCallback(async () => {
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
  }, []);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  // Realtime subscription for incident changes
  useRealtimeSubscription('incident_logs', ['INSERT', 'UPDATE'], useCallback(() => {
    loadIncidents();
  }, [loadIncidents]));

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
    
    // Simulate step execution
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
                <p className="text-sm text-muted-foreground">Investigating</p>
                <p className="text-2xl font-bold text-blue-500">
                  {incidents.filter(i => i.status === 'investigating').length}
                </p>
              </div>
              <Activity className="h-8 w-8 text-blue-500" />
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
    </div>
  );
}
