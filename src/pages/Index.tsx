import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Clock, AlertTriangle, Activity, LogOut, User, Shield } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import NetworkTrafficChart from "@/components/NetworkTrafficChart";
import SystemStatus from "@/components/SystemStatus";
import NetworkEventsList from "@/components/NetworkEventsList";
import AlertsPanel from "@/components/AlertsPanel";
import DetectionEngine from "@/components/DetectionEngine";
import DemoModeToggle from "@/components/DemoModeToggle";
import MLModelManager from "@/components/MLModelManager";
import RealtimeInference from "@/components/RealtimeInference";
import AdaptiveLearning from "@/components/AdaptiveLearning";
import DatasetManager from "@/components/DatasetManager";
import MalwareSignatureManager from "@/components/MalwareSignatureManager";
import ThreatIntelligenceDashboard from "@/components/ThreatIntelligenceDashboard";
import EnhancedRuleManager from "@/components/EnhancedRuleManager";
import NetworkMonitor from "@/components/NetworkMonitor";
import IncidentResponse from "@/components/IncidentResponse";
import AlertNotifications from "@/components/AlertNotifications";
import CorrelationEngine from "@/components/CorrelationEngine";
import MLMetricsDashboard from "@/components/MLMetricsDashboard";
import ThreatHunter from "@/components/ThreatHunter";
import AssetInventory from "@/components/AssetInventory";
import NetworkTopology from "@/components/NetworkTopology";
import DataRetention from "@/components/DataRetention";
import RiskScoreDashboard from "@/components/RiskScoreDashboard";
import AttackTimeline from "@/components/AttackTimeline";
import { PWAInstallPrompt } from "@/components/PWAInstallPrompt";
import { OfflineBanner } from "@/components/OfflineBanner";
import { useIDSDataStore } from "@/hooks/useIDSDataStore";
import { useAuth } from "@/hooks/useAuth";
import { MLModel } from "@/hooks/useMLPipeline";
import { supabase } from "@/integrations/supabase/client";

const NetworkRiskCard = () => {
  const [risk, setRisk] = useState(0);
  const [count, setCount] = useState(0);
  useEffect(() => {
    supabase.from('host_risk_scores').select('total_risk,asset_multiplier').then(({ data }) => {
      if (data && data.length > 0) {
        const tw = data.reduce((s, h) => s + h.total_risk * h.asset_multiplier, 0);
        const w = data.reduce((s, h) => s + h.asset_multiplier, 0);
        setRisk(Math.round(tw / Math.max(w, 1)));
        setCount(data.length);
      }
    });
  }, []);
  const color = risk >= 70 ? 'text-destructive' : risk >= 40 ? 'text-yellow-500' : 'text-green-500';
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-4">
          <Shield className="h-8 w-8 text-muted-foreground" />
          <div className="flex-1">
            <div className="text-sm font-medium text-muted-foreground">Network Risk Score</div>
            <div className="flex items-center gap-3">
              <span className={`text-3xl font-bold ${color}`}>{risk}</span>
              <span className="text-sm text-muted-foreground">/ 100</span>
              <Progress value={risk} className="flex-1 h-2" />
              <span className="text-xs text-muted-foreground">{count} hosts</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

const Index = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const [activeModel, setActiveModel] = useState<MLModel | null>(null);
  const dataStore = useIDSDataStore();
  const { user, role, signOut } = useAuth();

  const renderContent = () => {
    switch (activeTab) {
      case "overview":
        return (
          <div className="space-y-6">
            <NetworkRiskCard />
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <NetworkTrafficChart dataStore={dataStore} />
              </div>
              <div>
                <SystemStatus dataStore={dataStore} />
              </div>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <AlertTriangle className="h-5 w-5" />
                    <span>Recent Threats</span>
                  </CardTitle>
                  <CardDescription>Latest security threats detected</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {dataStore.threats.slice(0, 5).map(threat => (
                      <div key={threat.id} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${threat.severity === 'high' ? 'bg-destructive' : threat.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'}`}></div>
                          <div>
                            <div className="font-medium text-sm">{threat.attackType}</div>
                            <div className="text-xs text-muted-foreground">{threat.sourceIP}</div>
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          <Clock className="h-3 w-3 inline mr-1" />
                          {new Date(threat.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                    ))}
                    {dataStore.threats.length === 0 && (
                      <div className="text-center text-muted-foreground py-4">No threats detected</div>
                    )}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Activity className="h-5 w-5" />
                    <span>Critical Alerts</span>
                  </CardTitle>
                  <CardDescription>High priority security alerts</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {dataStore.alerts.filter(a => a.severity === 'high' && a.status === 'active').slice(0, 5).map(alert => (
                      <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg border-destructive/30">
                        <div className="flex items-center space-x-3">
                          <AlertTriangle className="h-4 w-4 text-destructive" />
                          <div>
                            <div className="font-medium text-sm">{alert.type}</div>
                            <div className="text-xs text-muted-foreground">{alert.sourceIP}</div>
                          </div>
                        </div>
                        <Badge variant="destructive" className="text-xs">{alert.status}</Badge>
                      </div>
                    ))}
                    {dataStore.alerts.filter(a => a.severity === 'high' && a.status === 'active').length === 0 && (
                      <div className="text-center text-muted-foreground py-4">No critical alerts</div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        );
      case "monitor": return <NetworkMonitor isDemoMode={dataStore.isDemoMode} />;
      case "incidents": return <IncidentResponse isDemoMode={dataStore.isDemoMode} />;
      case "datasets": return <DatasetManager />;
      case "assets": return <AssetInventory isDemoMode={dataStore.isDemoMode} />;
      case "events": return <NetworkEventsList dataStore={dataStore} />;
      case "threats": return <ThreatIntelligenceDashboard isDemoMode={dataStore.isDemoMode} />;
      case "malware": return <MalwareSignatureManager isDemoMode={dataStore.isDemoMode} />;
      case "rules": return <EnhancedRuleManager isDemoMode={dataStore.isDemoMode} />;
      case "alerts": return <AlertsPanel dataStore={dataStore} />;
      case "engine": return <DetectionEngine dataStore={dataStore} />;
      case "ml": return <MLModelManager onModelTrained={setActiveModel} isDemoMode={dataStore.isDemoMode} />;
      case "inference": return <RealtimeInference activeModel={activeModel} isDemoMode={dataStore.isDemoMode} />;
      case "adaptive": return <AdaptiveLearning isDemoMode={dataStore.isDemoMode} />;
      case "notifications": return <AlertNotifications isDemoMode={dataStore.isDemoMode} />;
      case "correlation": return <CorrelationEngine isDemoMode={dataStore.isDemoMode} />;
      case "ml-metrics": return <MLMetricsDashboard isDemoMode={dataStore.isDemoMode} />;
      case "hunt": return <ThreatHunter isDemoMode={dataStore.isDemoMode} />;
      case "topology": return <NetworkTopology isDemoMode={dataStore.isDemoMode} />;
      case "retention": return <DataRetention isDemoMode={dataStore.isDemoMode} />;
      case "risk": return <RiskScoreDashboard isDemoMode={dataStore.isDemoMode} />;
      case "timeline": return <AttackTimeline isDemoMode={dataStore.isDemoMode} />;
      default: return null;
    }
  };

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full bg-background">
        <DashboardSidebar activeTab={activeTab} onTabChange={setActiveTab} />

        <div className="flex-1 flex flex-col min-w-0">
          <OfflineBanner />
          <PWAInstallPrompt />

          <header className="border-b bg-background sticky top-0 z-20">
            <div className="px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <SidebarTrigger />
                <div>
                  <h1 className="text-xl font-bold">Advanced IDS Dashboard</h1>
                  <p className="text-xs text-muted-foreground">
                    Intrusion Detection & Security Monitoring System
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={dataStore.systemMetrics.detectionEngineStatus === "online" ? "default" : "destructive"} className="animate-pulse">
                  {dataStore.systemMetrics.detectionEngineStatus.toUpperCase()}
                </Badge>
                <Badge variant="outline" className="capitalize">{role}</Badge>
                <div className="hidden md:flex items-center gap-2">
                  <User className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">{user?.email}</span>
                </div>
                <Button variant="ghost" size="sm" onClick={signOut}>
                  <LogOut className="h-4 w-4 mr-1" />
                  <span className="hidden sm:inline">Sign Out</span>
                </Button>
              </div>
            </div>
            <div className="px-4 pb-2">
              <DemoModeToggle isDemoMode={dataStore.isDemoMode} onToggle={dataStore.toggleDemoMode} />
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6">
            {renderContent()}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
};

export default Index;
