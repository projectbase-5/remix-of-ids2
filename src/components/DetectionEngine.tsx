import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Brain, AlertTriangle, Play, Pause, FlaskConical } from "lucide-react";
import RuleManager from "./RuleManager";
import ThreatCorrelator from "./ThreatCorrelator";
import AttackSimulator from "./AttackSimulator";
import { useToast } from "@/hooks/use-toast";
import { useIDSDataStore, NetworkEvent, ThreatDetection } from "@/hooks/useIDSDataStore";
import { useThreatIntelligence } from "@/hooks/useThreatIntelligence";

export interface DetectionRule {
  id: string;
  name: string;
  type: "signature" | "anomaly" | "behavioral";
  severity: "low" | "medium" | "high";
  pattern: string;
  description: string;
  enabled: boolean;
  triggeredCount: number;
}

interface DetectionEngineProps {
  dataStore: ReturnType<typeof useIDSDataStore>;
}

const DetectionEngine = ({ dataStore }: DetectionEngineProps) => {
  const [isEngineRunning, setIsEngineRunning] = useState(true);
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>([]);
  const [engineStats, setEngineStats] = useState({
    eventsProcessed: 0,
    threatsDetected: 0,
    rulesTriggered: 0,
    processingRate: 0,
  });
  const { toast } = useToast();
  const { detectionRules: supabaseRules, loading: rulesLoading, addDetectionRule, updateDetectionRule, deleteDetectionRule } = useThreatIntelligence();

  // Sync detection rules from Supabase instead of using hardcoded defaults
  useEffect(() => {
    if (rulesLoading || !supabaseRules || supabaseRules.length === 0) {
      // Fallback to defaults only if no Supabase rules exist
      if (!rulesLoading && (!supabaseRules || supabaseRules.length === 0)) {
        setDetectionRules([
          {
            id: "rule-001",
            name: "Port Scan Detection",
            type: "signature",
            severity: "medium",
            pattern: "multiple_ports_same_ip",
            description: "Detects port scanning activities from single source",
            enabled: true,
            triggeredCount: 0,
          },
          {
            id: "rule-002",
            name: "DDoS Attack Detection",
            type: "behavioral",
            severity: "high",
            pattern: "high_volume_traffic",
            description: "Identifies distributed denial of service attacks",
            enabled: true,
            triggeredCount: 0,
          },
          {
            id: "rule-003",
            name: "Brute Force Login",
            type: "signature",
            severity: "high",
            pattern: "repeated_failed_auth",
            description: "Detects repeated authentication failures",
            enabled: true,
            triggeredCount: 0,
          },
          {
            id: "rule-004",
            name: "SQL Injection Attempt",
            type: "signature",
            severity: "high",
            pattern: "sql_injection_payload",
            description: "Identifies SQL injection attack patterns",
            enabled: true,
            triggeredCount: 0,
          },
          {
            id: "rule-005",
            name: "Abnormal Traffic Volume",
            type: "anomaly",
            severity: "medium",
            pattern: "traffic_anomaly",
            description: "Detects unusual traffic volume patterns",
            enabled: true,
            triggeredCount: 0,
          },
        ]);
      }
      return;
    }

    // Map Supabase rules to DetectionRule format
    const mapped: DetectionRule[] = supabaseRules.map((r) => {
      const ruleType = (r.rule_type || "signature").toLowerCase();
      let type: DetectionRule["type"] = "signature";
      if (ruleType.includes("anomaly")) type = "anomaly";
      else if (ruleType.includes("behavior")) type = "behavioral";

      const severity = (r.severity || "medium").toLowerCase() as DetectionRule["severity"];

      return {
        id: r.id,
        name: r.name,
        type,
        severity: ["low", "medium", "high"].includes(severity) ? severity : "medium",
        pattern: r.pattern || "",
        description: r.description || "",
        enabled: r.enabled !== false,
        triggeredCount: r.triggered_count || 0,
      };
    });

    setDetectionRules(mapped);
  }, [supabaseRules, rulesLoading]);

  // Demo event generation now lives in useIDSDataStore (global).
  // Keep engine stats in sync with dataStore metrics.
  useEffect(() => {
    if (!dataStore.isDemoMode) return;
    setEngineStats(prev => ({
      ...prev,
      eventsProcessed: dataStore.systemMetrics.packetsProcessed,
      processingRate: dataStore.systemMetrics.eventsPerSecond,
      threatsDetected: dataStore.systemMetrics.threatsBlocked,
    }));
  }, [dataStore.isDemoMode, dataStore.systemMetrics.packetsProcessed, dataStore.systemMetrics.eventsPerSecond, dataStore.systemMetrics.threatsBlocked]);

  const processNetworkEvent = (event: NetworkEvent) => {
    detectionRules.forEach(rule => {
      if (!rule.enabled) return;

      let isMatch = false;
      let confidence = 0;
      let attackType = "";

      switch (rule.pattern) {
        case "multiple_ports_same_ip":
          if (event.port > 1000 && event.flags.includes("SYN")) {
            isMatch = Math.random() > 0.9;
            confidence = 85;
            attackType = "Port Scan";
          }
          break;
        case "high_volume_traffic":
          if (event.packetSize > 1200) {
            isMatch = Math.random() > 0.95;
            confidence = 92;
            attackType = "DDoS Attack";
          }
          break;
        case "repeated_failed_auth":
          if (event.port === 22 || event.port === 3389) {
            isMatch = Math.random() > 0.93;
            confidence = 88;
            attackType = "Brute Force";
          }
          break;
        case "sql_injection_payload":
          if (event.payload && event.payload.includes("SELECT")) {
            isMatch = true;
            confidence = 95;
            attackType = "SQL Injection";
          }
          break;
        case "traffic_anomaly":
          if (event.packetSize < 100 || event.packetSize > 1400) {
            isMatch = Math.random() > 0.92;
            confidence = 75;
            attackType = "Traffic Anomaly";
          }
          break;
        default:
          // For Supabase-sourced rules with custom patterns
          if (rule.pattern && event.payload && event.payload.toLowerCase().includes(rule.pattern.toLowerCase())) {
            isMatch = true;
            confidence = 80;
            attackType = rule.name;
          }
          break;
      }

      if (isMatch) {
        generateThreatDetection(rule, event, confidence, attackType);
        setDetectionRules(prev => prev.map(r => 
          r.id === rule.id ? { ...r, triggeredCount: r.triggeredCount + 1 } : r
        ));
      }
    });
  };

  const generateThreatDetection = (
    rule: DetectionRule, 
    event: NetworkEvent, 
    confidence: number, 
    attackType: string
  ) => {
    const threatScore = calculateThreatScore(rule.severity, confidence, attackType);
    
    const threat: ThreatDetection = {
      id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      confidence,
      sourceIP: event.sourceIP,
      targetIP: event.destinationIP,
      attackType,
      description: `${attackType} detected from ${event.sourceIP} targeting ${event.destinationIP}`,
      evidence: [event],
      threatScore,
    };

    dataStore.addThreat(threat);
    
    setEngineStats(prev => ({
      ...prev,
      threatsDetected: prev.threatsDetected + 1,
      rulesTriggered: prev.rulesTriggered + 1,
    }));

    if (rule.severity === "high") {
      toast({
        title: `High Severity Threat Detected`,
        description: `${attackType} from ${event.sourceIP}`,
        variant: "destructive",
      });
    }
  };

  const calculateThreatScore = (severity: string, confidence: number, attackType: string): number => {
    let baseScore = 0;
    switch (severity) {
      case "low": baseScore = 25; break;
      case "medium": baseScore = 50; break;
      case "high": baseScore = 75; break;
    }
    const confidenceMultiplier = confidence / 100;
    const attackTypeBonus = attackType.includes("DDoS") || attackType.includes("SQL") ? 15 : 0;
    return Math.min(100, Math.round(baseScore * confidenceMultiplier + attackTypeBonus));
  };

  const toggleEngine = () => {
    setIsEngineRunning(!isEngineRunning);
    dataStore.setIsMonitoring(!isEngineRunning);
    toast({
      title: isEngineRunning ? "Detection Engine Stopped" : "Detection Engine Started",
      description: isEngineRunning ? "Threat detection has been paused" : "Real-time threat detection is now active",
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high": return "bg-destructive text-destructive-foreground";
      case "medium": return "bg-yellow-500 text-yellow-50";
      case "low": return "bg-green-500 text-green-50";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Brain className="h-6 w-6 text-primary" />
              <div>
                <CardTitle>Detection Engine Core</CardTitle>
                <CardDescription>
                  {dataStore.isDemoMode 
                    ? "Demo mode - generating synthetic events"
                    : "Live mode - processing real network data from Supabase"
                  }
                </CardDescription>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge className={isEngineRunning ? "bg-green-500 text-green-50" : "bg-red-500 text-red-50"}>
                {isEngineRunning ? "ACTIVE" : "STOPPED"}
              </Badge>
              {dataStore.isDemoMode && (
                <Button 
                  onClick={toggleEngine}
                  variant={isEngineRunning ? "destructive" : "default"}
                  className="flex items-center space-x-2"
                >
                  {isEngineRunning ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                  <span>{isEngineRunning ? "Stop Engine" : "Start Engine"}</span>
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{engineStats.eventsProcessed.toLocaleString()}</div>
              <div className="text-sm text-muted-foreground">Events Processed</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-destructive">{engineStats.threatsDetected}</div>
              <div className="text-sm text-muted-foreground">Threats Detected</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-500">{engineStats.rulesTriggered}</div>
              <div className="text-sm text-muted-foreground">Rules Triggered</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{engineStats.processingRate}/s</div>
              <div className="text-sm text-muted-foreground">Processing Rate</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="rules">Detection Rules</TabsTrigger>
          <TabsTrigger value="threats">Threat Analysis</TabsTrigger>
          <TabsTrigger value="correlator">Threat Correlator</TabsTrigger>
          <TabsTrigger value="simulations">Simulations</TabsTrigger>
        </TabsList>

        <TabsContent value="rules">
          <RuleManager 
            rules={detectionRules}
            onRulesUpdate={async (updatedRules) => {
              // Detect added rules
              const existingIds = new Set(detectionRules.map(r => r.id));
              const newRules = updatedRules.filter(r => !existingIds.has(r.id));
              for (const r of newRules) {
                await addDetectionRule({
                  name: r.name,
                  rule_type: r.type,
                  severity: r.severity,
                  pattern: r.pattern,
                  description: r.description || null,
                  enabled: r.enabled,
                });
              }

              // Detect deleted rules
              const updatedIds = new Set(updatedRules.map(r => r.id));
              const deletedRules = detectionRules.filter(r => !updatedIds.has(r.id));
              for (const r of deletedRules) {
                await deleteDetectionRule(r.id);
              }

              // Detect toggled rules
              for (const r of updatedRules) {
                const existing = detectionRules.find(e => e.id === r.id);
                if (existing && existing.enabled !== r.enabled) {
                  await updateDetectionRule(r.id, { enabled: r.enabled });
                }
              }

              setDetectionRules(updatedRules);
            }}
          />
        </TabsContent>

        <TabsContent value="threats">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5" />
                <span>Active Threats</span>
              </CardTitle>
              <CardDescription>Real-time threat detections and analysis</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 max-h-[500px] overflow-y-auto">
                {dataStore.threats.length === 0 ? (
                  <div className="text-center text-muted-foreground py-8">
                    No threats detected yet
                  </div>
                ) : (
                  dataStore.threats.map((threat) => (
                    <div key={threat.id} className="border rounded-lg p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Badge className={getSeverityColor(threat.severity)}>
                            {threat.severity.toUpperCase()}
                          </Badge>
                          <Badge variant="outline">{threat.attackType}</Badge>
                          <span className="text-sm text-muted-foreground">
                            {new Date(threat.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-sm">Confidence: {threat.confidence}%</span>
                          <div className="text-sm font-medium">Score: {threat.threatScore}</div>
                        </div>
                      </div>
                      <div className="text-sm">{threat.description}</div>
                      <div className="text-xs text-muted-foreground">
                        Rule: {threat.ruleName} | Evidence: {threat.evidence.length} event(s)
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="correlator">
          <ThreatCorrelator threats={dataStore.threats} networkEvents={dataStore.networkEvents} />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default DetectionEngine;
