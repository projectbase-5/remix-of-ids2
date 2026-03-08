import { useState, useEffect, useCallback, useRef } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

export interface LogEntry {
  id: string;
  timestamp: string;
  source: 'syslog' | 'firewall' | 'auth' | 'network' | 'application' | 'file_monitor';
  level: 'debug' | 'info' | 'warning' | 'error' | 'critical';
  message: string;
  sourceIP?: string;
  destinationIP?: string;
  port?: number;
  protocol?: string;
  details?: Record<string, unknown>;
  parsed: boolean;
  threatIndicator?: boolean;
}

export interface FileEvent {
  id: string;
  timestamp: string;
  eventType: 'created' | 'modified' | 'deleted' | 'accessed' | 'permission_changed';
  filePath: string;
  fileName: string;
  fileSize?: number;
  fileHash?: string;
  user?: string;
  process?: string;
  isSuspicious: boolean;
  suspicionReason?: string;
}

export interface ResponseAction {
  id: string;
  name: string;
  type: 'block_ip' | 'kill_process' | 'quarantine_file' | 'disable_account' | 'isolate_host' | 'notify' | 'custom';
  description: string;
  automated: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cooldownSeconds: number;
  lastExecuted?: string;
  executionCount: number;
  enabled: boolean;
}

export interface ResponseWorkflow {
  id: string;
  name: string;
  description: string;
  triggers: WorkflowTrigger[];
  actions: string[]; // Action IDs
  enabled: boolean;
  priority: number;
  lastTriggered?: string;
  triggerCount: number;
}

export interface WorkflowTrigger {
  type: 'threat_detected' | 'high_severity_alert' | 'ip_reputation' | 'malware_detected' | 'brute_force' | 'data_exfiltration';
  conditions: Record<string, unknown>;
}

export interface ResponseExecution {
  id: string;
  workflowId: string;
  workflowName: string;
  actionId: string;
  actionName: string;
  timestamp: string;
  status: 'pending' | 'executing' | 'success' | 'failed' | 'rolled_back';
  triggerEvent: string;
  result?: string;
  error?: string;
}

const SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.msi', '.scr', '.cmd', '.pif'];
const SUSPICIOUS_PATHS = ['/tmp', '/var/tmp', 'AppData/Local/Temp', 'Downloads', '/dev/shm'];
const CRITICAL_FILES = ['/etc/passwd', '/etc/shadow', '/etc/hosts', 'system32', 'boot.ini'];

export function useNetworkMonitor(isDemoMode: boolean = true) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [workflows, setWorkflows] = useState<ResponseWorkflow[]>([]);
  const [executions, setExecutions] = useState<ResponseExecution[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [stats, setStats] = useState({
    logsIngested: 0,
    fileEventsProcessed: 0,
    threatsDetected: 0,
    actionsExecuted: 0,
    logsPerSecond: 0,
  });
  
  const logCountRef = useRef(0);
  const lastSecondRef = useRef(Date.now());

  // Initialize default response actions
  useEffect(() => {
    const defaultActions: ResponseAction[] = [
      {
        id: 'action-block-ip',
        name: 'Block IP Address',
        type: 'block_ip',
        description: 'Add IP to firewall blocklist',
        automated: true,
        severity: 'high',
        cooldownSeconds: 300,
        executionCount: 0,
        enabled: true,
      },
      {
        id: 'action-quarantine',
        name: 'Quarantine File',
        type: 'quarantine_file',
        description: 'Move suspicious file to quarantine directory',
        automated: true,
        severity: 'critical',
        cooldownSeconds: 60,
        executionCount: 0,
        enabled: true,
      },
      {
        id: 'action-disable-account',
        name: 'Disable User Account',
        type: 'disable_account',
        description: 'Temporarily disable compromised user account',
        automated: false,
        severity: 'critical',
        cooldownSeconds: 600,
        executionCount: 0,
        enabled: true,
      },
      {
        id: 'action-isolate-host',
        name: 'Isolate Host',
        type: 'isolate_host',
        description: 'Isolate compromised host from network',
        automated: false,
        severity: 'critical',
        cooldownSeconds: 900,
        executionCount: 0,
        enabled: true,
      },
      {
        id: 'action-notify-team',
        name: 'Notify Security Team',
        type: 'notify',
        description: 'Send alert to security operations team',
        automated: true,
        severity: 'medium',
        cooldownSeconds: 60,
        executionCount: 0,
        enabled: true,
      },
      {
        id: 'action-kill-process',
        name: 'Terminate Process',
        type: 'kill_process',
        description: 'Kill malicious process by PID',
        automated: true,
        severity: 'high',
        cooldownSeconds: 30,
        executionCount: 0,
        enabled: true,
      },
    ];
    setResponseActions(defaultActions);

    const defaultWorkflows: ResponseWorkflow[] = [
      {
        id: 'workflow-brute-force',
        name: 'Brute Force Response',
        description: 'Automatically block IPs after detected brute force attacks',
        triggers: [{ type: 'brute_force', conditions: { maxAttempts: 5, timeWindowSeconds: 300 } }],
        actions: ['action-block-ip', 'action-notify-team'],
        enabled: true,
        priority: 1,
        triggerCount: 0,
      },
      {
        id: 'workflow-malware',
        name: 'Malware Response',
        description: 'Quarantine detected malware and notify team',
        triggers: [{ type: 'malware_detected', conditions: { minThreatLevel: 'medium' } }],
        actions: ['action-quarantine', 'action-notify-team', 'action-isolate-host'],
        enabled: true,
        priority: 1,
        triggerCount: 0,
      },
      {
        id: 'workflow-data-exfil',
        name: 'Data Exfiltration Response',
        description: 'Block and isolate on detected data exfiltration',
        triggers: [{ type: 'data_exfiltration', conditions: { dataThresholdMB: 100 } }],
        actions: ['action-block-ip', 'action-isolate-host', 'action-notify-team'],
        enabled: true,
        priority: 1,
        triggerCount: 0,
      },
      {
        id: 'workflow-critical-alert',
        name: 'Critical Alert Response',
        description: 'Immediate response to critical severity alerts',
        triggers: [{ type: 'high_severity_alert', conditions: { severity: 'critical' } }],
        actions: ['action-notify-team'],
        enabled: true,
        priority: 0,
        triggerCount: 0,
      },
    ];
    setWorkflows(defaultWorkflows);
  }, []);

  // Generate simulated log entry
  const generateLogEntry = useCallback((): LogEntry => {
    const sources: LogEntry['source'][] = ['syslog', 'firewall', 'auth', 'network', 'application', 'file_monitor'];
    const levels: LogEntry['level'][] = ['debug', 'info', 'warning', 'error', 'critical'];
    
    const source = sources[Math.floor(Math.random() * sources.length)];
    const isSuspicious = Math.random() > 0.85;
    const level = isSuspicious 
      ? levels[Math.floor(Math.random() * 3) + 2] // warning, error, critical
      : levels[Math.floor(Math.random() * 3)]; // debug, info, warning

    const messages: Record<LogEntry['source'], string[]> = {
      syslog: [
        'System startup complete',
        'Service restart requested',
        'Disk usage threshold exceeded',
        'Memory allocation warning',
        'Kernel panic - attempting recovery',
      ],
      firewall: [
        'Connection allowed from trusted network',
        'Blocked connection attempt on port 22',
        'Rate limiting triggered for IP',
        'Suspicious port scan detected',
        'Multiple failed connection attempts blocked',
      ],
      auth: [
        'User login successful',
        'Password changed by administrator',
        'Failed login attempt',
        'Multiple authentication failures detected',
        'Unauthorized sudo command attempt',
      ],
      network: [
        'New connection established',
        'DNS query resolved',
        'High bandwidth utilization detected',
        'Unusual outbound traffic pattern',
        'Potential C2 beacon detected',
      ],
      application: [
        'Application started successfully',
        'Configuration reloaded',
        'Database connection warning',
        'API rate limit exceeded',
        'Unhandled exception logged',
      ],
      file_monitor: [
        'File created in monitored directory',
        'Configuration file modified',
        'Executable dropped in temp directory',
        'Critical system file accessed',
        'Suspicious script execution detected',
      ],
    };

    const sourceIP = isSuspicious
      ? `${Math.floor(Math.random() * 100) + 100}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      : `192.168.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}`;

    return {
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      source,
      level,
      message: messages[source][Math.floor(Math.random() * messages[source].length)],
      sourceIP,
      destinationIP: `10.0.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 255)}`,
      port: [22, 80, 443, 3389, 1433, 5432, 8080][Math.floor(Math.random() * 7)],
      protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
      parsed: true,
      threatIndicator: isSuspicious,
    };
  }, []);

  // Generate simulated file event
  const generateFileEvent = useCallback((): FileEvent => {
    const eventTypes: FileEvent['eventType'][] = ['created', 'modified', 'deleted', 'accessed', 'permission_changed'];
    const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
    
    const paths = [
      '/var/log/syslog',
      '/home/user/documents/report.pdf',
      '/tmp/unknown_binary',
      '/etc/hosts',
      '/usr/local/bin/service.sh',
      'C:\\Users\\Admin\\Downloads\\installer.exe',
      'C:\\Windows\\Temp\\script.ps1',
    ];
    
    const filePath = paths[Math.floor(Math.random() * paths.length)];
    const fileName = filePath.split(/[/\\]/).pop() || 'unknown';
    
    const isSuspicious = 
      SUSPICIOUS_EXTENSIONS.some(ext => fileName.toLowerCase().endsWith(ext)) ||
      SUSPICIOUS_PATHS.some(p => filePath.toLowerCase().includes(p.toLowerCase())) ||
      CRITICAL_FILES.some(f => filePath.toLowerCase().includes(f.toLowerCase()));

    let suspicionReason: string | undefined;
    if (isSuspicious) {
      if (SUSPICIOUS_EXTENSIONS.some(ext => fileName.toLowerCase().endsWith(ext))) {
        suspicionReason = 'Suspicious file extension';
      } else if (CRITICAL_FILES.some(f => filePath.toLowerCase().includes(f.toLowerCase()))) {
        suspicionReason = 'Critical system file modification';
      } else {
        suspicionReason = 'Suspicious location';
      }
    }

    return {
      id: `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      eventType,
      filePath,
      fileName,
      fileSize: Math.floor(Math.random() * 10000000),
      fileHash: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
      user: ['root', 'admin', 'user', 'system'][Math.floor(Math.random() * 4)],
      process: ['sshd', 'bash', 'python3', 'node', 'powershell.exe'][Math.floor(Math.random() * 5)],
      isSuspicious,
      suspicionReason,
    };
  }, []);

  // Execute response action
  const executeAction = useCallback(async (
    action: ResponseAction,
    triggeredBy: string,
    workflowId?: string,
    workflowName?: string
  ): Promise<ResponseExecution> => {
    const execution: ResponseExecution = {
      id: `exec-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      workflowId: workflowId || 'manual',
      workflowName: workflowName || 'Manual Execution',
      actionId: action.id,
      actionName: action.name,
      timestamp: new Date().toISOString(),
      status: 'pending',
      triggerEvent: triggeredBy,
    };

    setExecutions(prev => [execution, ...prev.slice(0, 99)]);

    // Simulate execution
    await new Promise(resolve => setTimeout(resolve, 500));

    const success = Math.random() > 0.1; // 90% success rate
    const updatedExecution: ResponseExecution = {
      ...execution,
      status: success ? 'success' : 'failed',
      result: success ? `${action.name} executed successfully` : undefined,
      error: success ? undefined : 'Execution failed - target unreachable',
    };

    setExecutions(prev => prev.map(e => e.id === execution.id ? updatedExecution : e));
    setResponseActions(prev => prev.map(a => 
      a.id === action.id 
        ? { ...a, executionCount: a.executionCount + 1, lastExecuted: new Date().toISOString() }
        : a
    ));

    setStats(prev => ({ ...prev, actionsExecuted: prev.actionsExecuted + 1 }));

    if (success) {
      toast.success(`Action executed: ${action.name}`);
    } else {
      toast.error(`Action failed: ${action.name}`);
    }

    // Log incident
    try {
      await supabase.from('incident_logs').insert([{
        incident_type: action.type,
        severity: action.severity,
        details: { action: action.name, trigger: triggeredBy, success } as unknown as undefined,
        status: success ? 'resolved' : 'pending',
      }]);
    } catch (error) {
      console.error('Failed to log incident:', error);
    }

    return updatedExecution;
  }, []);

  // Check if workflow should be triggered
  const checkWorkflowTriggers = useCallback((log: LogEntry) => {
    if (!log.threatIndicator) return;

    workflows.forEach(workflow => {
      if (!workflow.enabled) return;

      workflow.triggers.forEach(trigger => {
        let shouldTrigger = false;

        switch (trigger.type) {
          case 'brute_force':
            if (log.source === 'auth' && log.level === 'error') {
              shouldTrigger = true;
            }
            break;
          case 'malware_detected':
            if (log.source === 'file_monitor' && log.level === 'critical') {
              shouldTrigger = true;
            }
            break;
          case 'high_severity_alert':
            if (log.level === 'critical') {
              shouldTrigger = true;
            }
            break;
          case 'data_exfiltration':
            if (log.source === 'network' && log.message.toLowerCase().includes('outbound')) {
              shouldTrigger = true;
            }
            break;
        }

        if (shouldTrigger) {
          setWorkflows(prev => prev.map(w => 
            w.id === workflow.id 
              ? { ...w, triggerCount: w.triggerCount + 1, lastTriggered: new Date().toISOString() }
              : w
          ));

          // Execute automated actions
          workflow.actions.forEach(actionId => {
            const action = responseActions.find(a => a.id === actionId);
            if (action?.automated && action.enabled) {
              executeAction(action, `${trigger.type}: ${log.message}`, workflow.id, workflow.name);
            }
          });

          setStats(prev => ({ ...prev, threatsDetected: prev.threatsDetected + 1 }));
        }
      });
    });
  }, [workflows, responseActions, executeAction]);

  // Start monitoring simulation
  const startMonitoring = useCallback(() => {
    setIsMonitoring(true);
    setIsPaused(false);
    toast.success('Network monitoring started');
  }, []);

  const stopMonitoring = useCallback(() => {
    setIsMonitoring(false);
    setIsPaused(false);
    toast.info('Network monitoring stopped');
  }, []);

  const pauseMonitoring = useCallback(() => {
    setIsPaused(true);
    toast.info('Network monitoring paused');
  }, []);

  const resumeMonitoring = useCallback(() => {
    setIsPaused(false);
    toast.info('Network monitoring resumed');
  }, []);

  // Ingest log manually
  const ingestLog = useCallback((log: Omit<LogEntry, 'id' | 'parsed'>) => {
    const entry: LogEntry = {
      ...log,
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      parsed: true,
    };
    
    setLogs(prev => [entry, ...prev.slice(0, 499)]);
    setStats(prev => ({ ...prev, logsIngested: prev.logsIngested + 1 }));
    
    if (entry.threatIndicator) {
      checkWorkflowTriggers(entry);
    }
  }, [checkWorkflowTriggers]);

  // Ingest file event manually
  const ingestFileEvent = useCallback((event: Omit<FileEvent, 'id'>) => {
    const fileEvent: FileEvent = {
      ...event,
      id: `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    };
    
    setFileEvents(prev => [fileEvent, ...prev.slice(0, 199)]);
    setStats(prev => ({ ...prev, fileEventsProcessed: prev.fileEventsProcessed + 1 }));

    if (fileEvent.isSuspicious) {
      const log: LogEntry = {
        id: `log-file-${Date.now()}`,
        timestamp: fileEvent.timestamp,
        source: 'file_monitor',
        level: 'critical',
        message: `Suspicious file activity: ${fileEvent.suspicionReason} - ${fileEvent.filePath}`,
        parsed: true,
        threatIndicator: true,
        details: { fileEvent } as unknown as Record<string, unknown>,
      };
      checkWorkflowTriggers(log);
    }
  }, [checkWorkflowTriggers]);

  // Toggle action enabled
  const toggleAction = useCallback((actionId: string) => {
    setResponseActions(prev => prev.map(a => 
      a.id === actionId ? { ...a, enabled: !a.enabled } : a
    ));
  }, []);

  // Toggle workflow enabled
  const toggleWorkflow = useCallback((workflowId: string) => {
    setWorkflows(prev => prev.map(w => 
      w.id === workflowId ? { ...w, enabled: !w.enabled } : w
    ));
  }, []);

  // Poll live data from Supabase
  const lastLiveTimestampRef = useRef<string | null>(null);

  useEffect(() => {
    if (!isMonitoring || isPaused || isDemoMode) return;

    const pollLiveData = async () => {
      try {
        // Fetch recent network_traffic
        let trafficQuery = supabase
          .from('network_traffic')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(50);

        if (lastLiveTimestampRef.current) {
          trafficQuery = trafficQuery.gt('created_at', lastLiveTimestampRef.current);
        }

        const { data: trafficData } = await trafficQuery;

        if (trafficData && trafficData.length > 0) {
          lastLiveTimestampRef.current = trafficData[0].created_at;
          const newLogs: LogEntry[] = trafficData.map((pkt) => ({
            id: pkt.id,
            timestamp: pkt.created_at,
            source: 'network' as const,
            level: pkt.is_suspicious ? 'warning' as const : 'info' as const,
            message: `${pkt.protocol} ${pkt.source_ip}:${pkt.port || 0} → ${pkt.destination_ip} (${pkt.packet_size || 0}B)`,
            sourceIP: pkt.source_ip,
            destinationIP: pkt.destination_ip,
            port: pkt.port || undefined,
            protocol: pkt.protocol,
            parsed: true,
            threatIndicator: pkt.is_suspicious || false,
          }));

          setLogs(prev => [...newLogs, ...prev].slice(0, 500));
          logCountRef.current += newLogs.length;
          setStats(prev => ({ ...prev, logsIngested: prev.logsIngested + newLogs.length }));
        }

        // Fetch recent live_alerts
        const { data: alertData } = await supabase
          .from('live_alerts')
          .select('*')
          .order('created_at', { ascending: false })
          .limit(20);

        if (alertData && alertData.length > 0) {
          const alertLogs: LogEntry[] = alertData.map((a) => ({
            id: `alert-${a.id}`,
            timestamp: a.created_at || new Date().toISOString(),
            source: 'firewall' as const,
            level: a.severity === 'high' ? 'critical' as const : 'error' as const,
            message: `[${a.alert_type}] ${a.description}`,
            sourceIP: a.source_ip,
            parsed: true,
            threatIndicator: true,
          }));

          // Merge without duplicates
          setLogs(prev => {
            const existingIds = new Set(prev.map(l => l.id));
            const newAlerts = alertLogs.filter(l => !existingIds.has(l.id));
            if (newAlerts.length === 0) return prev;
            return [...newAlerts, ...prev].slice(0, 500);
          });
        }
      } catch (err) {
        console.error('Live data poll error:', err);
      }
    };

    pollLiveData();
    const interval = setInterval(pollLiveData, 2000);

    const statsInterval = setInterval(() => {
      const now = Date.now();
      const elapsed = (now - lastSecondRef.current) / 1000;
      const rate = Math.round(logCountRef.current / elapsed);
      setStats(prev => ({ ...prev, logsPerSecond: rate }));
      logCountRef.current = 0;
      lastSecondRef.current = now;
    }, 1000);

    return () => {
      clearInterval(interval);
      clearInterval(statsInterval);
    };
  }, [isMonitoring, isPaused, isDemoMode]);

  // Run demo simulation
  useEffect(() => {
    if (!isMonitoring || isPaused || !isDemoMode) return;

    const logInterval = setInterval(() => {
      const log = generateLogEntry();
      setLogs(prev => [log, ...prev.slice(0, 499)]);
      logCountRef.current++;
      
      setStats(prev => ({ ...prev, logsIngested: prev.logsIngested + 1 }));
      
      if (log.threatIndicator) {
        checkWorkflowTriggers(log);
      }
    }, 200);

    const fileInterval = setInterval(() => {
      if (Math.random() > 0.7) {
        const fileEvent = generateFileEvent();
        setFileEvents(prev => [fileEvent, ...prev.slice(0, 199)]);
        setStats(prev => ({ ...prev, fileEventsProcessed: prev.fileEventsProcessed + 1 }));

        if (fileEvent.isSuspicious) {
          const log: LogEntry = {
            id: `log-file-${Date.now()}`,
            timestamp: fileEvent.timestamp,
            source: 'file_monitor',
            level: 'critical',
            message: `Suspicious file activity: ${fileEvent.suspicionReason} - ${fileEvent.filePath}`,
            parsed: true,
            threatIndicator: true,
          };
          checkWorkflowTriggers(log);
        }
      }
    }, 500);

    const statsInterval = setInterval(() => {
      const now = Date.now();
      const elapsed = (now - lastSecondRef.current) / 1000;
      const rate = Math.round(logCountRef.current / elapsed);
      
      setStats(prev => ({ ...prev, logsPerSecond: rate }));
      logCountRef.current = 0;
      lastSecondRef.current = now;
    }, 1000);

    return () => {
      clearInterval(logInterval);
      clearInterval(fileInterval);
      clearInterval(statsInterval);
    };
  }, [isMonitoring, isPaused, isDemoMode, generateLogEntry, generateFileEvent, checkWorkflowTriggers]);

  // Clear all logs
  const clearLogs = useCallback(() => {
    setLogs([]);
    setFileEvents([]);
    setExecutions([]);
    setStats({
      logsIngested: 0,
      fileEventsProcessed: 0,
      threatsDetected: 0,
      actionsExecuted: 0,
      logsPerSecond: 0,
    });
  }, []);

  return {
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
    ingestLog,
    ingestFileEvent,
    executeAction,
    toggleAction,
    toggleWorkflow,
    clearLogs,
  };
}
