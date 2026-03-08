
import { useState, useEffect, memo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { Globe, TrendingUp, AlertTriangle } from "lucide-react";
import { aggregateThreatsByCountry } from "@/utils/geolocation";
import { ThreatDetection } from "@/hooks/useIDSDataStore";

interface ThreatData {
  country: string;
  count: number;
  type: string;
}

interface AttackTypeData {
  name: string;
  value: number;
  color: string;
}

interface ThreatMapProps {
  threats: ThreatDetection[];
}

const ThreatMap = memo(({ threats }: ThreatMapProps) => {
  const [threatsByCountry, setThreatsByCountry] = useState<ThreatData[]>([]);
  const [attackTypes, setAttackTypes] = useState<AttackTypeData[]>([]);

  useEffect(() => {
    if (threats.length === 0) {
      setThreatsByCountry([]);
      setAttackTypes([]);
      return;
    }

    // Use real threat data with geolocation
    const threatData = threats.map(threat => ({
      sourceIP: threat.sourceIP,
      attackType: threat.attackType,
    }));

    const countryData = aggregateThreatsByCountry(threatData);
    setThreatsByCountry(countryData);

    // Calculate attack type distribution from real data
    const typeCounts = threats.reduce((acc, threat) => {
      acc[threat.attackType] = (acc[threat.attackType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const colors = [
      "hsl(var(--destructive))",
      "hsl(var(--primary))", 
      "hsl(var(--secondary))",
      "hsl(var(--accent))",
      "hsl(var(--muted))",
      "hsl(var(--card))"
    ];

    const attackTypesData = Object.entries(typeCounts).map(([name, value], index) => ({
      name,
      value,
      color: colors[index % colors.length],
    })).sort((a, b) => b.value - a.value);

    setAttackTypes(attackTypesData);
  }, [threats]);

  if (threats.length === 0) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="text-center py-8">
            <Globe className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <p className="text-muted-foreground">No threat data available</p>
            <p className="text-sm text-muted-foreground mt-2">
              Geographic threat analysis will appear here when threats are detected
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threats by Country */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Globe className="h-5 w-5" />
              <span>Threats by Country</span>
            </CardTitle>
            <CardDescription>Geographic distribution of detected threats</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatsByCountry}>
                  <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                  <XAxis 
                    dataKey="country" 
                    className="text-xs"
                    tick={{ fontSize: 12 }}
                    angle={-45}
                    textAnchor="end"
                    height={60}
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
                  <Bar 
                    dataKey="count" 
                    fill="hsl(var(--primary))"
                    name="Threat Count"
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Attack Type Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <TrendingUp className="h-5 w-5" />
              <span>Attack Type Distribution</span>
            </CardTitle>
            <CardDescription>Breakdown of detected attack types</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={attackTypes}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {attackTypes.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '6px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top Threats Summary */}
      {threatsByCountry.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5" />
              <span>Top Threat Sources</span>
            </CardTitle>
            <CardDescription>Most active threat sources detected</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {threatsByCountry.slice(0, 5).map((threat, index) => (
                <div key={threat.country} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-bold">
                      {index + 1}
                    </div>
                    <div>
                      <div className="font-medium">{threat.country}</div>
                      <div className="text-sm text-muted-foreground">Primary: {threat.type}</div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant="destructive">{threat.count} attacks</Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
});

ThreatMap.displayName = 'ThreatMap';

export default ThreatMap;
