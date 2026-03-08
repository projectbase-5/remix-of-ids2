
import { memo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Server, Cpu, HardDrive, Wifi, Shield } from "lucide-react";
import { useIDSDataStore } from "@/hooks/useIDSDataStore";

interface SystemStatusProps {
  dataStore: ReturnType<typeof useIDSDataStore>;
}

const SystemStatus = memo(({ dataStore }: SystemStatusProps) => {
  const { systemMetrics } = dataStore;

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online": return "bg-green-500 text-green-50";
      case "offline": return "bg-red-500 text-red-50";
      case "maintenance": return "bg-yellow-500 text-yellow-50";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Server className="h-5 w-5" />
          <span>System Status</span>
          <Badge className={dataStore.isDemoMode ? "bg-amber-500/20 text-amber-400 border-amber-500/30" : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"}>
            {dataStore.isDemoMode ? "DEMO" : "LIVE"}
          </Badge>
        </CardTitle>
        <CardDescription>Real-time system health monitoring</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Detection Engine Status */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="h-4 w-4" />
            <span className="font-medium">Detection Engine</span>
          </div>
          <Badge className={getStatusColor(systemMetrics.detectionEngineStatus)}>
            {systemMetrics.detectionEngineStatus.toUpperCase()}
          </Badge>
        </div>

        {/* System Metrics */}
        <div className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Cpu className="h-4 w-4" />
                <span className="text-sm font-medium">CPU Usage</span>
              </div>
              <span className="text-sm text-muted-foreground">{systemMetrics.cpuUsage.toFixed(1)}%</span>
            </div>
            <Progress 
              value={systemMetrics.cpuUsage} 
              className="h-2"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Server className="h-4 w-4" />
                <span className="text-sm font-medium">Memory Usage</span>
              </div>
              <span className="text-sm text-muted-foreground">{systemMetrics.memoryUsage.toFixed(1)}%</span>
            </div>
            <Progress 
              value={systemMetrics.memoryUsage} 
              className="h-2"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <HardDrive className="h-4 w-4" />
                <span className="text-sm font-medium">Disk Usage</span>
              </div>
              <span className="text-sm text-muted-foreground">{systemMetrics.diskUsage}%</span>
            </div>
            <Progress 
              value={systemMetrics.diskUsage} 
              className="h-2"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Wifi className="h-4 w-4" />
                <span className="text-sm font-medium">Network Health</span>
              </div>
              <span className="text-sm text-muted-foreground">{systemMetrics.networkHealth.toFixed(1)}%</span>
            </div>
            <Progress 
              value={systemMetrics.networkHealth} 
              className="h-2"
            />
          </div>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-2 gap-4 pt-4 border-t">
          <div className="text-center">
            <div className="text-2xl font-bold text-primary">{systemMetrics.packetsProcessed.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Packets Processed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-destructive">{systemMetrics.threatsBlocked}</div>
            <div className="text-xs text-muted-foreground">Threats Blocked</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
});

SystemStatus.displayName = 'SystemStatus';

export default SystemStatus;
