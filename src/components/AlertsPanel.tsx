import { useState, memo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { AlertTriangle, Search, Clock, MapPin, Shield, Globe } from "lucide-react";
import { useIDSDataStore } from "@/hooks/useIDSDataStore";

interface AlertsPanelProps {
  dataStore: ReturnType<typeof useIDSDataStore>;
}

interface AlertMetadata {
  source_reputation?: {
    reputation_score: number;
    is_malicious: boolean;
    country_code: string | null;
    threat_types: string[];
    source: string;
  };
  destination_reputation?: {
    reputation_score: number;
    is_malicious: boolean;
  };
  summary?: {
    source_malicious: boolean;
    destination_malicious: boolean;
    max_threat_score: number;
    enriched_at: string;
  };
}

const AlertsPanel = memo(({ dataStore }: AlertsPanelProps) => {
  const [filter, setFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high": return "bg-destructive text-destructive-foreground";
      case "medium": return "bg-yellow-500 text-yellow-50";
      case "low": return "bg-green-500 text-green-50";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active": return "bg-red-500 text-red-50";
      case "investigating": return "bg-blue-500 text-blue-50";
      case "resolved": return "bg-green-500 text-green-50";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getReputationBadge = (score: number) => {
    if (score >= 80) return { color: "bg-red-600 text-white", label: "High Risk" };
    if (score >= 50) return { color: "bg-orange-500 text-white", label: "Suspicious" };
    if (score >= 25) return { color: "bg-yellow-500 text-yellow-50", label: "Low Risk" };
    return { color: "bg-green-500 text-green-50", label: "Clean" };
  };

  const filteredAlerts = dataStore.alerts.filter(alert => {
    const matchesSearch = alert.description.toLowerCase().includes(filter.toLowerCase()) ||
                         alert.sourceIP.includes(filter) ||
                         alert.type.toLowerCase().includes(filter.toLowerCase());
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const handleInvestigate = (alertId: string) => {
    dataStore.updateAlertStatus(alertId, "investigating");
  };

  const handleResolve = (alertId: string) => {
    dataStore.updateAlertStatus(alertId, "resolved");
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5" />
            <span>Security Alerts</span>
          </CardTitle>
          <CardDescription>Monitor and manage security incidents</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex space-x-4 mb-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search alerts..."
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>
            <div className="flex space-x-2">
              <Button
                variant={severityFilter === "all" ? "default" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("all")}
              >
                All
              </Button>
              <Button
                variant={severityFilter === "high" ? "destructive" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("high")}
              >
                High
              </Button>
              <Button
                variant={severityFilter === "medium" ? "secondary" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("medium")}
              >
                Medium
              </Button>
              <Button
                variant={severityFilter === "low" ? "default" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("low")}
              >
                Low
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Alerts List */}
      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[600px]">
            <div className="p-4 space-y-4">
              {filteredAlerts.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">
                  No alerts match your criteria
                </div>
              ) : (
                filteredAlerts.map((alert) => (
                  <div
                    key={alert.id}
                    className="border rounded-lg p-4 hover:bg-muted/50 transition-colors"
                  >
                    <div className="flex items-start justify-between space-x-4">
                      <div className="flex-1 space-y-2">
                        <div className="flex items-center space-x-2">
                          <Badge className={getSeverityColor(alert.severity)}>
                            {alert.severity.toUpperCase()}
                          </Badge>
                          <Badge variant="outline">{alert.type}</Badge>
                          <Badge className={getStatusColor(alert.status)}>
                            {alert.status}
                          </Badge>
                        </div>
                        
                        <h4 className="font-semibold">{alert.description}</h4>
                        
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm text-muted-foreground">
                          <div className="flex items-center space-x-1">
                            <Clock className="h-3 w-3" />
                            <span>{new Date(alert.timestamp).toLocaleString()}</span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <MapPin className="h-3 w-3" />
                            <span>From: {alert.sourceIP}</span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <Shield className="h-3 w-3" />
                            <span>Target: {alert.targetIP}</span>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex space-x-2">
                        {alert.status === "active" && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => handleInvestigate(alert.id)}
                          >
                            Investigate
                          </Button>
                        )}
                        {alert.status !== "resolved" && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => handleResolve(alert.id)}
                          >
                            Resolve
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
});

AlertsPanel.displayName = 'AlertsPanel';

export default AlertsPanel;
