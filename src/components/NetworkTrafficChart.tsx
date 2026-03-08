import { memo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from "recharts";
import { Activity } from "lucide-react";
import { useIDSDataStore } from "@/hooks/useIDSDataStore";

interface NetworkTrafficChartProps {
  dataStore: ReturnType<typeof useIDSDataStore>;
}

const NetworkTrafficChart = memo(({ dataStore }: NetworkTrafficChartProps) => {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Activity className="h-5 w-5" />
          <span>Network Traffic</span>
        </CardTitle>
        <CardDescription>Real-time network traffic monitoring</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={dataStore.trafficData}>
              <defs>
                <linearGradient id="colorInbound" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorOutbound" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--secondary))" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="hsl(var(--secondary))" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--destructive))" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="hsl(var(--destructive))" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis 
                dataKey="time" 
                className="text-xs"
                tick={{ fontSize: 12 }}
              />
              <YAxis 
                className="text-xs"
                tick={{ fontSize: 12 }}
              />
              <Tooltip 
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '6px',
                }}
              />
              <Area
                type="monotone"
                dataKey="inbound"
                stroke="hsl(var(--primary))"
                fillOpacity={1}
                fill="url(#colorInbound)"
                name="Inbound (KB/s)"
              />
              <Area
                type="monotone"
                dataKey="outbound"
                stroke="hsl(var(--secondary))"
                fillOpacity={1}
                fill="url(#colorOutbound)"
                name="Outbound (KB/s)"
              />
              <Area
                type="monotone"
                dataKey="threats"
                stroke="hsl(var(--destructive))"
                fillOpacity={1}
                fill="url(#colorThreats)"
                name="Threats"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        
        <div className="flex justify-center space-x-6 mt-4">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-primary"></div>
            <span className="text-sm text-muted-foreground">Inbound Traffic</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-secondary"></div>
            <span className="text-sm text-muted-foreground">Outbound Traffic</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-destructive"></div>
            <span className="text-sm text-muted-foreground">Threats Detected</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
});

NetworkTrafficChart.displayName = 'NetworkTrafficChart';

export default NetworkTrafficChart;
