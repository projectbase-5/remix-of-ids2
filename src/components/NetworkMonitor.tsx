import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Switch } from '@/components/ui/switch';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { useNetworkMonitor, LogEntry, FileEvent, ResponseAction, ResponseWorkflow, ResponseExecution } from '@/hooks/useNetworkMonitor';
import { useIntegratedDetection, MLDetectionResult, IntegratedDetectionConfig } from '@/hooks/useIntegratedDetection';
import { useMLPipeline } from '@/hooks/useMLPipeline';
import { 
  Activity, 
  Play, 
  Pause, 
  Square, 
  Trash2, 
  Search,
  FileWarning,
  Shield,
  Zap,
  Terminal,
  FolderOpen,
  Settings,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Brain,
  Target,
  TrendingUp
} from 'lucide-react';

const getLevelColor = (level: LogEntry['level']) => {
  switch (level) {
    case 'critical': return 'bg-destructive text-destructive-foreground';
    case 'error': return 'bg-red-500 text-white';
    case 'warning': return 'bg-yellow-500 text-yellow-50';
    case 'info': return 'bg-blue-500 text-white';
    case 'debug': return 'bg-muted text-muted-foreground';
    default: return 'bg-muted text-muted-foreground';
  }
};

const getSourceIcon = (source: LogEntry['source']) => {
  switch (source) {
    case 'firewall': return <Shield className="h-3 w-3" />;
    case 'auth': return <Settings className="h-3 w-3" />;
    case 'file_monitor': return <FolderOpen className="h-3 w-3" />;
    case 'network': return <Activity className="h-3 w-3" />;
    default: return <Terminal className="h-3 w-3" />;
  }
};

const getStatusIcon = (status: ResponseExecution['status']) => {
  switch (status) {
    case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
    case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
    case 'pending': return <Clock className="h-4 w-4 text-yellow-500" />;
    case 'executing': return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />;
    default: return <Clock className="h-4 w-4 text-muted-foreground" />;
  }
};

const getThreatScoreColor = (score: number) => {
  if (score >= 80) return 'text-destructive';
  if (score >= 60) return 'text-orange-500';
  if (score >= 40) return 'text-yellow-500';
  return 'text-green-500';
};

interface NetworkMonitorProps {
  mlPipeline?: ReturnType<typeof useMLPipeline>;
  isDemoMode?: boolean;
}

export default function NetworkMonitor({ mlPipeline, isDemoMode = true }: NetworkMonitorProps) {
  const networkMonitor = useNetworkMonitor(isDemoMode);
  const {
    logs,
    fileEvents,
    responseActions,
    workflows,
    executions,
    isMonitoring,
    isPaused,
    stats,
    startMonitoring,
    stopMonitoring,
    pauseMonitoring,
    resumeMonitoring,
    executeAction,
    toggleAction,
    toggleWorkflow,
    clearLogs,
  } = networkMonitor;

  // ML detection integration
  const defaultMLPipeline = useMLPipeline();
  const activePipeline = mlPipeline || defaultMLPipeline;
  
  const [mlConfig] = useState<IntegratedDetectionConfig>({
    enableMLDetection: true,
    confidenceThreshold: 0.7,
    anomalyThreshold: 0.8,
    autoCreateIncident: true,
    checkIPReputation: true,
    ipReputationThreshold: 50,
  });

  const integratedDetection = useIntegratedDetection(activePipeline, mlConfig);
  const [mlDetections, setMLDetections] = useState<MLDetectionResult[]>([]);
  const [mlStats, setMLStats] = useState({ totalDetections: 0, threatsDetected: 0, anomaliesDetected: 0, highThreatCount: 0, averageThreatScore: 0, modelActive: false });

  // Process logs through ML detection when they come in
  useEffect(() => {
    if (!isMonitoring || isPaused || logs.length === 0) return;

    const latestLog = logs[0];
    integratedDetection.processLogEntry(latestLog).then(result => {
      if (result) {
        setMLDetections(prev => [result, ...prev.slice(0, 199)]);
        setMLStats(integratedDetection.getDetectionStats());
      }
    });
  }, [logs, isMonitoring, isPaused, integratedDetection]);

  // Process file events through ML detection
  useEffect(() => {
    if (!isMonitoring || isPaused || fileEvents.length === 0) return;

    const latestEvent = fileEvents[0];
    integratedDetection.processFileEvent(latestEvent).then(result => {
      if (result) {
        setMLDetections(prev => [result, ...prev.slice(0, 199)]);
        setMLStats(integratedDetection.getDetectionStats());
      }
    });
  }, [fileEvents, isMonitoring, isPaused, integratedDetection]);

  const [logFilter, setLogFilter] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  const filteredLogs = logs.filter(log => {
    const matchesText = logFilter === '' || 
      log.message.toLowerCase().includes(logFilter.toLowerCase()) ||
      log.sourceIP?.toLowerCase().includes(logFilter.toLowerCase());
    const matchesLevel = levelFilter === 'all' || log.level === levelFilter;
    const matchesSource = sourceFilter === 'all' || log.source === sourceFilter;
    return matchesText && matchesLevel && matchesSource;
  });

  const suspiciousFileEvents = fileEvents.filter(f => f.isSuspicious);
  const highThreatDetections = mlDetections.filter(d => d.threatScore >= 70);

  return (
    <div className="space-y-6">
      {/* Status Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Activity className="h-6 w-6 text-primary" />
              <div>
                <CardTitle>Network & File Monitor</CardTitle>
                <CardDescription>
                  Real-time log ingestion, file system monitoring, and automated response
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Badge className={isMonitoring ? (isPaused ? 'bg-yellow-500' : 'bg-green-500 text-green-50') : 'bg-muted'}>
                {isMonitoring ? (isPaused ? 'PAUSED' : 'MONITORING') : 'STOPPED'}
              </Badge>
              {!isMonitoring ? (
                <Button onClick={startMonitoring} className="flex items-center space-x-2">
                  <Play className="h-4 w-4" />
                  <span>Start</span>
                </Button>
              ) : (
                <div className="flex items-center space-x-2">
                  {isPaused ? (
                    <Button onClick={resumeMonitoring} variant="outline" size="sm">
                      <Play className="h-4 w-4 mr-1" />
                      Resume
                    </Button>
                  ) : (
                    <Button onClick={pauseMonitoring} variant="outline" size="sm">
                      <Pause className="h-4 w-4 mr-1" />
                      Pause
                    </Button>
                  )}
                  <Button onClick={stopMonitoring} variant="destructive" size="sm">
                    <Square className="h-4 w-4 mr-1" />
                    Stop
                  </Button>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-7 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.logsIngested.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">Logs Ingested</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.fileEventsProcessed}</div>
              <div className="text-sm text-muted-foreground">File Events</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-destructive">{stats.threatsDetected}</div>
              <div className="text-sm text-muted-foreground">Workflow Triggers</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.actionsExecuted}</div>
              <div className="text-sm text-muted-foreground">Actions Executed</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{stats.logsPerSecond}/s</div>
              <div className="text-sm text-muted-foreground">Ingestion Rate</div>
            </div>
            <div className="text-center border-l border-border pl-4">
              <div className="text-2xl font-bold text-destructive">{mlStats.threatsDetected}</div>
              <div className="text-sm text-muted-foreground">ML Threats</div>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center gap-1">
                <Brain className={`h-4 w-4 ${mlStats.modelActive ? 'text-primary' : 'text-muted-foreground'}`} />
                <span className={`text-2xl font-bold ${mlStats.modelActive ? 'text-primary' : 'text-muted-foreground'}`}>
                  {mlStats.modelActive ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="text-sm text-muted-foreground">ML Engine</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="logs" className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="logs">Log Stream</TabsTrigger>
          <TabsTrigger value="files">File Monitor</TabsTrigger>
          <TabsTrigger value="ml-detections" className="flex items-center gap-1">
            <Brain className="h-3 w-3" />
            ML Detections
            {highThreatDetections.length > 0 && (
              <Badge variant="destructive" className="ml-1 h-5 w-5 p-0 flex items-center justify-center text-xs">
                {highThreatDetections.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="workflows">Workflows</TabsTrigger>
          <TabsTrigger value="actions">Actions</TabsTrigger>
          <TabsTrigger value="executions">Executions</TabsTrigger>
        </TabsList>

        {/* Log Stream Tab */}
        <TabsContent value="logs">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center space-x-2">
                  <Terminal className="h-5 w-5" />
                  <span>Live Log Stream</span>
                </CardTitle>
                <div className="flex items-center space-x-2">
                  <Button onClick={clearLogs} variant="outline" size="sm">
                    <Trash2 className="h-4 w-4 mr-1" />
                    Clear
                  </Button>
                </div>
              </div>
              <div className="flex items-center space-x-2 mt-4">
                <div className="relative flex-1">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Filter logs..."
                    value={logFilter}
                    onChange={(e) => setLogFilter(e.target.value)}
                    className="pl-8"
                  />
                </div>
                <select
                  value={levelFilter}
                  onChange={(e) => setLevelFilter(e.target.value)}
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="all">All Levels</option>
                  <option value="critical">Critical</option>
                  <option value="error">Error</option>
                  <option value="warning">Warning</option>
                  <option value="info">Info</option>
                  <option value="debug">Debug</option>
                </select>
                <select
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="all">All Sources</option>
                  <option value="syslog">Syslog</option>
                  <option value="firewall">Firewall</option>
                  <option value="auth">Auth</option>
                  <option value="network">Network</option>
                  <option value="application">Application</option>
                  <option value="file_monitor">File Monitor</option>
                </select>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-1 font-mono text-sm">
                  {filteredLogs.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      {isMonitoring ? 'Waiting for logs...' : 'Start monitoring to see logs'}
                    </div>
                  ) : (
                    filteredLogs.map((log) => (
                      <div 
                        key={log.id} 
                        className={`flex items-start space-x-2 p-2 rounded ${log.threatIndicator ? 'bg-destructive/10 border border-destructive/20' : 'hover:bg-muted/50'}`}
                      >
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                        <Badge className={`${getLevelColor(log.level)} text-xs shrink-0`}>
                          {log.level.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-xs shrink-0 flex items-center gap-1">
                          {getSourceIcon(log.source)}
                          {log.source}
                        </Badge>
                        {log.sourceIP && (
                          <span className="text-xs text-muted-foreground shrink-0">{log.sourceIP}</span>
                        )}
                        <span className="flex-1 break-all">{log.message}</span>
                        {log.threatIndicator && (
                          <AlertTriangle className="h-4 w-4 text-destructive shrink-0" />
                        )}
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* File Monitor Tab */}
        <TabsContent value="files">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <FolderOpen className="h-5 w-5" />
                <span>File System Monitor</span>
              </CardTitle>
              <CardDescription>
                {suspiciousFileEvents.length} suspicious events detected
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {fileEvents.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      {isMonitoring ? 'Waiting for file events...' : 'Start monitoring to see file events'}
                    </div>
                  ) : (
                    fileEvents.map((event) => (
                      <div 
                        key={event.id} 
                        className={`p-3 rounded border ${event.isSuspicious ? 'border-destructive bg-destructive/5' : 'border-border'}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            {event.isSuspicious ? (
                              <FileWarning className="h-4 w-4 text-destructive" />
                            ) : (
                              <FolderOpen className="h-4 w-4 text-muted-foreground" />
                            )}
                            <Badge variant={event.isSuspicious ? 'destructive' : 'outline'}>
                              {event.eventType}
                            </Badge>
                            <span className="font-mono text-sm">{event.fileName}</span>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div className="mt-2 text-sm text-muted-foreground">
                          <div className="font-mono text-xs break-all">{event.filePath}</div>
                          {event.user && (
                            <span className="mr-3">User: {event.user}</span>
                          )}
                          {event.process && (
                            <span className="mr-3">Process: {event.process}</span>
                          )}
                          {event.fileSize !== undefined && (
                            <span className="mr-3">Size: {(event.fileSize / 1024).toFixed(1)} KB</span>
                          )}
                        </div>
                        {event.isSuspicious && event.suspicionReason && (
                          <div className="mt-2 text-sm text-destructive font-medium">
                            ⚠️ {event.suspicionReason}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ML Detections Tab */}
        <TabsContent value="ml-detections">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center space-x-2">
                    <Brain className="h-5 w-5" />
                    <span>ML-Based Threat Detection</span>
                  </CardTitle>
                  <CardDescription>
                    Real-time machine learning analysis of network events and files
                  </CardDescription>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-sm font-medium">Avg Threat Score</div>
                    <div className={`text-xl font-bold ${getThreatScoreColor(mlStats.averageThreatScore)}`}>
                      {mlStats.averageThreatScore.toFixed(1)}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium">High Threats</div>
                    <div className="text-xl font-bold text-destructive">{mlStats.highThreatCount}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium">Anomalies</div>
                    <div className="text-xl font-bold text-primary">{mlStats.anomaliesDetected}</div>
                  </div>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-3">
                  {mlDetections.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      {isMonitoring ? 'Analyzing events with ML...' : 'Start monitoring to see ML detections'}
                    </div>
                  ) : (
                    mlDetections.map((detection) => (
                      <div 
                        key={detection.id} 
                        className={`p-4 rounded-lg border ${
                          detection.threatScore >= 70 ? 'border-destructive bg-destructive/5' : 
                          detection.threatScore >= 40 ? 'border-yellow-500/50 bg-yellow-500/5' : 
                          'border-border'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className="flex items-center justify-center w-10 h-10 rounded-full bg-muted">
                              {detection.eventType === 'log' ? (
                                <Terminal className="h-5 w-5 text-muted-foreground" />
                              ) : (
                                <FolderOpen className="h-5 w-5 text-muted-foreground" />
                              )}
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <Badge 
                                  variant={detection.prediction === 'normal' ? 'outline' : 'destructive'}
                                  className="capitalize"
                                >
                                  {detection.prediction.replace('_', ' ')}
                                </Badge>
                                {detection.isAnomaly && (
                                  <Badge variant="secondary" className="flex items-center gap-1">
                                    <TrendingUp className="h-3 w-3" />
                                    Anomaly
                                  </Badge>
                                )}
                              </div>
                              <div className="text-xs text-muted-foreground mt-1">
                                Model: {detection.modelName}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-4">
                            <div className="text-right">
                              <div className="text-xs text-muted-foreground">Confidence</div>
                              <div className="flex items-center gap-2">
                                <Progress 
                                  value={detection.confidence * 100} 
                                  className="w-16 h-2" 
                                />
                                <span className="text-sm font-medium">
                                  {(detection.confidence * 100).toFixed(0)}%
                                </span>
                              </div>
                            </div>
                            <div className="text-right">
                              <div className="text-xs text-muted-foreground">Threat Score</div>
                              <div className={`text-lg font-bold ${getThreatScoreColor(detection.threatScore)}`}>
                                {detection.threatScore}
                              </div>
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {new Date(detection.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                        </div>
                        {detection.threatScore >= 50 && (
                          <div className="mt-3 flex items-center gap-2 text-sm">
                            <Target className="h-4 w-4 text-destructive" />
                            <span className="text-muted-foreground">
                              Incident auto-created • Event: {detection.eventId.substring(0, 20)}...
                            </span>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Workflows Tab */}
        <TabsContent value="workflows">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Zap className="h-5 w-5" />
                <span>Response Workflows</span>
              </CardTitle>
              <CardDescription>
                Automated incident response workflows
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {workflows.map((workflow) => (
                  <div key={workflow.id} className="p-4 rounded-lg border">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <Switch
                          checked={workflow.enabled}
                          onCheckedChange={() => toggleWorkflow(workflow.id)}
                        />
                        <div>
                          <h4 className="font-medium">{workflow.name}</h4>
                          <p className="text-sm text-muted-foreground">{workflow.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <Badge variant="outline">Priority: {workflow.priority}</Badge>
                        <div className="text-sm text-muted-foreground">
                          Triggered: {workflow.triggerCount}x
                        </div>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <span className="text-sm text-muted-foreground">Triggers:</span>
                      {workflow.triggers.map((trigger, i) => (
                        <Badge key={i} variant="secondary">{trigger.type}</Badge>
                      ))}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <span className="text-sm text-muted-foreground">Actions:</span>
                      {workflow.actions.map((actionId) => {
                        const action = responseActions.find(a => a.id === actionId);
                        return action ? (
                          <Badge key={actionId} variant="outline">{action.name}</Badge>
                        ) : null;
                      })}
                    </div>
                    {workflow.lastTriggered && (
                      <div className="mt-2 text-xs text-muted-foreground">
                        Last triggered: {new Date(workflow.lastTriggered).toLocaleString()}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Actions Tab */}
        <TabsContent value="actions">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>Response Actions</span>
              </CardTitle>
              <CardDescription>
                Available automated and manual response actions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                {responseActions.map((action) => (
                  <div key={action.id} className="p-4 rounded-lg border">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={action.enabled}
                          onCheckedChange={() => toggleAction(action.id)}
                        />
                        <h4 className="font-medium">{action.name}</h4>
                      </div>
                      <Badge className={
                        action.severity === 'critical' ? 'bg-destructive' :
                        action.severity === 'high' ? 'bg-red-500 text-white' :
                        action.severity === 'medium' ? 'bg-yellow-500' : 'bg-muted'
                      }>
                        {action.severity}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">{action.description}</p>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3 text-sm">
                        <Badge variant={action.automated ? 'default' : 'outline'}>
                          {action.automated ? 'Auto' : 'Manual'}
                        </Badge>
                        <span className="text-muted-foreground">
                          Cooldown: {action.cooldownSeconds}s
                        </span>
                        <span className="text-muted-foreground">
                          Runs: {action.executionCount}
                        </span>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => executeAction(action, 'Manual trigger')}
                        disabled={!action.enabled}
                      >
                        Execute
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Executions Tab */}
        <TabsContent value="executions">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Activity className="h-5 w-5" />
                <span>Execution History</span>
              </CardTitle>
              <CardDescription>
                Recent response action executions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {executions.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      No executions yet
                    </div>
                  ) : (
                    executions.map((exec) => (
                      <div key={exec.id} className="p-3 rounded border">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            {getStatusIcon(exec.status)}
                            <span className="font-medium">{exec.actionName}</span>
                            <Badge variant="outline">{exec.workflowName}</Badge>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(exec.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="mt-2 text-sm text-muted-foreground">
                          Trigger: {exec.triggerEvent}
                        </div>
                        {exec.result && (
                          <div className="mt-1 text-sm text-green-600">{exec.result}</div>
                        )}
                        {exec.error && (
                          <div className="mt-1 text-sm text-destructive">{exec.error}</div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
