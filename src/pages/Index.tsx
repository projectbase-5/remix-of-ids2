import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Clock, AlertTriangle, Activity, LogOut, User } from "lucide-react";
import NetworkTrafficChart from "@/components/NetworkTrafficChart";
import SystemStatus from "@/components/SystemStatus";
import NetworkEventsList from "@/components/NetworkEventsList";
import ThreatCorrelator from "@/components/ThreatCorrelator";
import AlertsPanel from "@/components/AlertsPanel";
import DetectionEngine from "@/components/DetectionEngine";
import ThreatMap from "@/components/ThreatMap";
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
import MalwareBehaviorDashboard from "@/components/MalwareBehaviorDashboard";
import AssetInventory from "@/components/AssetInventory";
import NetworkTopology from "@/components/NetworkTopology";
import DataRetention from "@/components/DataRetention";
import { PWAInstallPrompt } from "@/components/PWAInstallPrompt";
import { OfflineBanner } from "@/components/OfflineBanner";
import { useIDSDataStore } from "@/hooks/useIDSDataStore";
import { useAuth } from "@/hooks/useAuth";
import { MLModel } from "@/hooks/useMLPipeline";
import logo from "@/assets/logo.png";
const Index = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const [activeModel, setActiveModel] = useState<MLModel | null>(null);
  const dataStore = useIDSDataStore();
  const { user, role, signOut } = useAuth();
  return <div className="min-h-screen bg-background">
      {/* Offline Banner */}
      <OfflineBanner />
      
      {/* PWA Install Prompt */}
      <PWAInstallPrompt />
      
      {/* Header */}
      <header className="border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              
              <div>
                <h1 className="text-2xl font-bold">Advanced IDS Dashboard</h1>
                <p className="text-sm text-muted-foreground">
                  Intrusion Detection & Security Monitoring System
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant={dataStore.systemMetrics.detectionEngineStatus === "online" ? "default" : "destructive"} className="animate-pulse">
                {dataStore.systemMetrics.detectionEngineStatus.toUpperCase()}
              </Badge>
              <Badge variant="outline" className="capitalize">{role}</Badge>
              <div className="flex items-center gap-2">
                <User className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">{user?.email}</span>
              </div>
              <Button variant="ghost" size="sm" onClick={signOut}>
                <LogOut className="h-4 w-4 mr-1" />Sign Out
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Demo Mode Toggle */}
      <div className="container mx-auto px-4 py-4">
        <DemoModeToggle isDemoMode={dataStore.isDemoMode} onToggle={dataStore.toggleDemoMode} />
      </div>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          {/* Navigation Tabs */}
          <div className="border-b overflow-x-auto">
            <TabsList className="inline-flex w-auto min-w-full">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="monitor">Monitor</TabsTrigger>
              <TabsTrigger value="incidents">Incidents</TabsTrigger>
              <TabsTrigger value="datasets">Datasets</TabsTrigger>
              <TabsTrigger value="threats">Threat Intel</TabsTrigger>
              <TabsTrigger value="malware">Malware Sigs</TabsTrigger>
              <TabsTrigger value="malware-behavior">Malware Behavior</TabsTrigger>
              <TabsTrigger value="rules">Detection Rules</TabsTrigger>
              <TabsTrigger value="assets">Assets</TabsTrigger>
              <TabsTrigger value="events">Events</TabsTrigger>
              <TabsTrigger value="alerts">Alerts</TabsTrigger>
              <TabsTrigger value="engine">Engine</TabsTrigger>
              <TabsTrigger value="map">Map</TabsTrigger>
              <TabsTrigger value="ml">ML Models</TabsTrigger>
              <TabsTrigger value="inference">Inference</TabsTrigger>
              <TabsTrigger value="adaptive">Adaptive</TabsTrigger>
              <TabsTrigger value="notifications">Notifications</TabsTrigger>
              <TabsTrigger value="correlation">Correlation</TabsTrigger>
              <TabsTrigger value="ml-metrics">ML Metrics</TabsTrigger>
              <TabsTrigger value="hunt">Hunt</TabsTrigger>
              <TabsTrigger value="topology">Topology</TabsTrigger>
              <TabsTrigger value="retention">Retention</TabsTrigger>
            </TabsList>
          </div>

          {/* Tab Content */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <NetworkTrafficChart dataStore={dataStore} />
              </div>
              <div>
                <SystemStatus dataStore={dataStore} />
              </div>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Recent Threats */}
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
                    {dataStore.threats.slice(0, 5).map(threat => <div key={threat.id} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${threat.severity === 'high' ? 'bg-red-500' : threat.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'}`}></div>
                          <div>
                            <div className="font-medium text-sm">{threat.attackType}</div>
                            <div className="text-xs text-muted-foreground">{threat.sourceIP}</div>
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          <Clock className="h-3 w-3 inline mr-1" />
                          {new Date(threat.timestamp).toLocaleTimeString()}
                        </div>
                      </div>)}
                    {dataStore.threats.length === 0 && <div className="text-center text-muted-foreground py-4">
                        No threats detected
                      </div>}
                  </div>
                </CardContent>
              </Card>

              {/* Critical Alerts */}
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
                    {dataStore.alerts.filter(alert => alert.severity === 'high' && alert.status === 'active').slice(0, 5).map(alert => <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg border-red-200">
                          <div className="flex items-center space-x-3">
                            <AlertTriangle className="h-4 w-4 text-red-500" />
                            <div>
                              <div className="font-medium text-sm">{alert.type}</div>
                              <div className="text-xs text-muted-foreground">{alert.sourceIP}</div>
                            </div>
                          </div>
                          <Badge variant="destructive" className="text-xs">
                            {alert.status}
                          </Badge>
                        </div>)}
                    {dataStore.alerts.filter(alert => alert.severity === 'high' && alert.status === 'active').length === 0 && <div className="text-center text-muted-foreground py-4">
                        No critical alerts
                      </div>}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="monitor">
            <NetworkMonitor isDemoMode={dataStore.isDemoMode} />
          </TabsContent>

          <TabsContent value="incidents">
            <IncidentResponse />
          </TabsContent>

          <TabsContent value="datasets">
            <DatasetManager />
          </TabsContent>

          <TabsContent value="assets">
            <AssetInventory />
          </TabsContent>

          <TabsContent value="events">
            <NetworkEventsList dataStore={dataStore} />
          </TabsContent>

          <TabsContent value="threats">
            <ThreatIntelligenceDashboard />
          </TabsContent>

          <TabsContent value="malware">
            <MalwareSignatureManager />
          </TabsContent>

          <TabsContent value="malware-behavior">
            <MalwareBehaviorDashboard />
          </TabsContent>

          <TabsContent value="rules">
            <EnhancedRuleManager />
          </TabsContent>

          <TabsContent value="alerts">
            <AlertsPanel dataStore={dataStore} />
          </TabsContent>

          <TabsContent value="engine">
            <DetectionEngine dataStore={dataStore} />
          </TabsContent>

          <TabsContent value="map">
            <ThreatMap threats={dataStore.threats} />
          </TabsContent>

          <TabsContent value="ml">
            <MLModelManager onModelTrained={setActiveModel} />
          </TabsContent>

          <TabsContent value="inference">
            <RealtimeInference activeModel={activeModel} />
          </TabsContent>

          <TabsContent value="adaptive">
            <AdaptiveLearning />
          </TabsContent>

          <TabsContent value="notifications">
            <AlertNotifications />
          </TabsContent>

          <TabsContent value="correlation">
            <CorrelationEngine />
          </TabsContent>

          <TabsContent value="ml-metrics">
            <MLMetricsDashboard />
          </TabsContent>

          <TabsContent value="hunt">
            <ThreatHunter />
          </TabsContent>
        </Tabs>
      </main>
    </div>;
};
export default Index;