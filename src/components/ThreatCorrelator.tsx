import { useState, useEffect, memo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Network, TrendingUp, Users, Globe } from "lucide-react";
import { ThreatDetection, NetworkEvent } from "@/hooks/useIDSDataStore";

interface ThreatCorrelatorProps {
  threats: ThreatDetection[];
  networkEvents: NetworkEvent[];
}

interface CorrelationResult {
  id: string;
  type: "ip_correlation" | "attack_pattern" | "time_correlation" | "geographical";
  description: string;
  confidence: number;
  relatedThreats: string[];
  severity: "low" | "medium" | "high";
}

interface AttackStatistics {
  totalAttacks: number;
  uniqueSourceIPs: number;
  mostCommonAttack: string;
  attackTrends: Array<{ type: string; count: number; percentage: number }>;
  timelineAnalysis: Array<{ hour: number; attackCount: number }>;
}

const ThreatCorrelator = memo(({ threats, networkEvents }: ThreatCorrelatorProps) => {
  const [correlations, setCorrelations] = useState<CorrelationResult[]>([]);
  const [statistics, setStatistics] = useState<AttackStatistics>({
    totalAttacks: 0,
    uniqueSourceIPs: 0,
    mostCommonAttack: "None",
    attackTrends: [],
    timelineAnalysis: [],
  });

  // Perform threat correlation analysis
  useEffect(() => {
    if (threats.length === 0) return;

    const newCorrelations: CorrelationResult[] = [];

    // IP-based correlation
    const ipGroups = threats.reduce((acc, threat) => {
      if (!acc[threat.sourceIP]) acc[threat.sourceIP] = [];
      acc[threat.sourceIP].push(threat);
      return acc;
    }, {} as Record<string, ThreatDetection[]>);

    Object.entries(ipGroups).forEach(([ip, ipThreats]) => {
      if (ipThreats.length > 1) {
        newCorrelations.push({
          id: `ip-corr-${ip}`,
          type: "ip_correlation",
          description: `Multiple attacks detected from IP ${ip}: ${ipThreats.map(t => t.attackType).join(", ")}`,
          confidence: Math.min(95, 70 + (ipThreats.length * 5)),
          relatedThreats: ipThreats.map(t => t.id),
          severity: ipThreats.some(t => t.severity === "high") ? "high" : "medium",
        });
      }
    });

    // Attack pattern correlation
    const attackPatterns = threats.reduce((acc, threat) => {
      if (!acc[threat.attackType]) acc[threat.attackType] = [];
      acc[threat.attackType].push(threat);
      return acc;
    }, {} as Record<string, ThreatDetection[]>);

    Object.entries(attackPatterns).forEach(([attackType, attacks]) => {
      if (attacks.length > 2) {
        const timeSpan = attacks.length > 1 
          ? (new Date(attacks[0].timestamp).getTime() - new Date(attacks[attacks.length - 1].timestamp).getTime()) / 1000 / 60
          : 0;

        if (timeSpan < 30) { // Attacks within 30 minutes
          newCorrelations.push({
            id: `pattern-corr-${attackType}`,
            type: "attack_pattern",
            description: `Coordinated ${attackType} attack pattern detected (${attacks.length} instances in ${timeSpan.toFixed(1)} minutes)`,
            confidence: 85,
            relatedThreats: attacks.map(a => a.id),
            severity: "high",
          });
        }
      }
    });

    // Time-based correlation
    const recentThreats = threats.filter(t => 
      new Date(t.timestamp).getTime() > Date.now() - (5 * 60 * 1000) // Last 5 minutes
    );

    if (recentThreats.length > 3) {
      newCorrelations.push({
        id: `time-corr-${Date.now()}`,
        type: "time_correlation",
        description: `High-frequency attack activity: ${recentThreats.length} threats in the last 5 minutes`,
        confidence: 80,
        relatedThreats: recentThreats.map(t => t.id),
        severity: "medium",
      });
    }

    setCorrelations(newCorrelations);

    // Calculate statistics
    const uniqueIPs = new Set(threats.map(t => t.sourceIP)).size;
    const attackTypeCounts = threats.reduce((acc, threat) => {
      acc[threat.attackType] = (acc[threat.attackType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const mostCommon = Object.entries(attackTypeCounts).reduce((a, b) => 
      (attackTypeCounts[a[0]] || 0) > (attackTypeCounts[b[0]] || 0) ? a : b
    )?.[0] || "None";

    const attackTrends = Object.entries(attackTypeCounts).map(([type, count]) => ({
      type,
      count: count || 0,
      percentage: Math.round(((count || 0) / threats.length) * 100),
    })).sort((a, b) => b.count - a.count);

    // Timeline analysis (last 24 hours)
    const timelineAnalysis = Array.from({ length: 24 }, (_, hour) => {
      const hourThreats = threats.filter(t => {
        const threatHour = new Date(t.timestamp).getHours();
        return threatHour === hour;
      });
      return { hour, attackCount: hourThreats.length };
    });

    setStatistics({
      totalAttacks: threats.length,
      uniqueSourceIPs: uniqueIPs,
      mostCommonAttack: mostCommon,
      attackTrends,
      timelineAnalysis,
    });
  }, [threats]);

  const getCorrelationColor = (type: string) => {
    switch (type) {
      case "ip_correlation": return "bg-red-500 text-red-50";
      case "attack_pattern": return "bg-orange-500 text-orange-50";
      case "time_correlation": return "bg-yellow-500 text-yellow-50";
      case "geographical": return "bg-blue-500 text-blue-50";
      default: return "bg-muted text-muted-foreground";
    }
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
      {/* Statistics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <TrendingUp className="h-4 w-4 text-destructive" />
              <div>
                <div className="text-2xl font-bold">{statistics.totalAttacks}</div>
                <div className="text-xs text-muted-foreground">Total Attacks</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Globe className="h-4 w-4 text-blue-500" />
              <div>
                <div className="text-2xl font-bold">{statistics.uniqueSourceIPs}</div>
                <div className="text-xs text-muted-foreground">Unique Source IPs</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Network className="h-4 w-4 text-orange-500" />
              <div>
                <div className="text-lg font-bold">{statistics.mostCommonAttack}</div>
                <div className="text-xs text-muted-foreground">Most Common Attack</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Users className="h-4 w-4 text-purple-500" />
              <div>
                <div className="text-2xl font-bold">{correlations.length}</div>
                <div className="text-xs text-muted-foreground">Correlations Found</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="correlations" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="correlations">Threat Correlations</TabsTrigger>
          <TabsTrigger value="trends">Attack Trends</TabsTrigger>
          <TabsTrigger value="timeline">Timeline Analysis</TabsTrigger>
        </TabsList>

        <TabsContent value="correlations">
          <Card>
            <CardHeader>
              <CardTitle>Threat Correlations</CardTitle>
              <CardDescription>
                Identified relationships and patterns between detected threats
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <div className="space-y-4">
                  {correlations.length === 0 ? (
                    <div className="text-center text-muted-foreground py-8">
                      No correlations detected yet
                    </div>
                  ) : (
                    correlations.map((correlation) => (
                      <div key={correlation.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <Badge className={getCorrelationColor(correlation.type)}>
                              {correlation.type.replace("_", " ").toUpperCase()}
                            </Badge>
                            <Badge className={getSeverityColor(correlation.severity)}>
                              {correlation.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <div className="text-sm">
                            Confidence: {correlation.confidence}%
                          </div>
                        </div>
                        <p className="text-sm mb-2">{correlation.description}</p>
                        <div className="text-xs text-muted-foreground">
                          Related threats: {correlation.relatedThreats.length}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="trends">
          <Card>
            <CardHeader>
              <CardTitle>Attack Type Distribution</CardTitle>
              <CardDescription>
                Breakdown of attack types and their frequency
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {statistics.attackTrends.map((trend) => (
                  <div key={trend.type} className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>{trend.type}</span>
                      <span>{trend.count} attacks ({trend.percentage}%)</span>
                    </div>
                    <Progress value={trend.percentage} className="h-2" />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle>24-Hour Attack Timeline</CardTitle>
              <CardDescription>
                Attack frequency distribution over the last 24 hours
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-12 gap-1 h-32">
                {statistics.timelineAnalysis.map((item) => (
                  <div key={item.hour} className="flex flex-col items-center space-y-1">
                    <div 
                      className="w-full bg-primary rounded-t"
                      style={{ 
                        height: `${Math.max(4, (item.attackCount / Math.max(...statistics.timelineAnalysis.map(t => t.attackCount))) * 100)}%` 
                      }}
                    />
                    <div className="text-xs text-muted-foreground">{item.hour}</div>
                  </div>
                ))}
              </div>
              <div className="text-center text-xs text-muted-foreground mt-2">
                Hours (0-23)
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
});

ThreatCorrelator.displayName = 'ThreatCorrelator';

export default ThreatCorrelator;
