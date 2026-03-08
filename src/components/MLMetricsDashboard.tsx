import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { Brain, TrendingUp, Target, RefreshCw } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useRealtimeSubscription } from '@/hooks/useRealtimeSubscription';

interface ModelEval {
  id: string;
  model_id: string | null;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1_score: number | null;
  false_positive_rate: number | null;
  detection_rate: number | null;
  roc_auc: number | null;
  training_time_ms: number | null;
  created_at: string;
  evaluation_type: string;
}

interface ModelInfo {
  id: string;
  name: string;
  algorithm: string;
  status: string;
  is_active: boolean | null;
  created_at: string;
}

interface PredictionStat {
  prediction: string;
  count: number;
}

const COLORS = ['hsl(var(--primary))', 'hsl(var(--destructive))', 'hsl(210, 70%, 50%)', 'hsl(45, 80%, 50%)', 'hsl(150, 60%, 45%)', 'hsl(280, 60%, 55%)'];

const MLMetricsDashboard = () => {
  const [evaluations, setEvaluations] = useState<ModelEval[]>([]);
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [predictionStats, setPredictionStats] = useState<PredictionStat[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    const [evalsRes, modelsRes, predsRes] = await Promise.all([
      supabase.from('model_evaluations').select('*').order('created_at', { ascending: true }).limit(100),
      supabase.from('ml_models').select('id, name, algorithm, status, is_active, created_at').order('created_at', { ascending: false }),
      supabase.from('predictions').select('prediction').limit(1000),
    ]);
    setEvaluations((evalsRes.data as unknown as ModelEval[]) || []);
    setModels((modelsRes.data as unknown as ModelInfo[]) || []);

    // Aggregate prediction counts
    const counts: Record<string, number> = {};
    (predsRes.data || []).forEach((p: any) => { counts[p.prediction] = (counts[p.prediction] || 0) + 1; });
    setPredictionStats(Object.entries(counts).map(([prediction, count]) => ({ prediction, count })));
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  const handleRealtime = useCallback(() => { fetchData(); }, []);
  useRealtimeSubscription('model_evaluations', ['INSERT'], handleRealtime);
  useRealtimeSubscription('predictions', ['INSERT'], handleRealtime);

  const metricsOverTime = evaluations.map(e => ({
    date: new Date(e.created_at).toLocaleDateString(),
    accuracy: e.accuracy ? +(e.accuracy * 100).toFixed(1) : null,
    precision: e.precision ? +(e.precision * 100).toFixed(1) : null,
    recall: e.recall ? +(e.recall * 100).toFixed(1) : null,
    f1: e.f1_score ? +(e.f1_score * 100).toFixed(1) : null,
    fpr: e.false_positive_rate ? +(e.false_positive_rate * 100).toFixed(2) : null,
  }));

  const modelComparison = models.map(m => {
    const evals = evaluations.filter(e => e.model_id === m.id);
    const latest = evals[evals.length - 1];
    return {
      name: m.name,
      algorithm: m.algorithm,
      status: m.status,
      active: m.is_active,
      accuracy: latest?.accuracy ? +(latest.accuracy * 100).toFixed(1) : null,
      f1: latest?.f1_score ? +(latest.f1_score * 100).toFixed(1) : null,
      fpr: latest?.false_positive_rate ? +(latest.false_positive_rate * 100).toFixed(2) : null,
    };
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Brain className="h-5 w-5" />ML Performance Metrics</h2>
        <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{models.length}</div><div className="text-xs text-muted-foreground">Models</div></CardContent></Card>
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{evaluations.length}</div><div className="text-xs text-muted-foreground">Evaluations</div></CardContent></Card>
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{predictionStats.reduce((s, p) => s + p.count, 0)}</div><div className="text-xs text-muted-foreground">Predictions</div></CardContent></Card>
        <Card><CardContent className="pt-6 text-center"><div className="text-3xl font-bold">{models.filter(m => m.is_active).length}</div><div className="text-xs text-muted-foreground">Active Models</div></CardContent></Card>
      </div>

      <Tabs defaultValue="trends">
        <TabsList>
          <TabsTrigger value="trends">Accuracy Trends</TabsTrigger>
          <TabsTrigger value="predictions">Predictions</TabsTrigger>
          <TabsTrigger value="comparison">Model Comparison</TabsTrigger>
        </TabsList>

        <TabsContent value="trends">
          <Card>
            <CardHeader><CardTitle className="text-base">Metrics Over Time</CardTitle></CardHeader>
            <CardContent>
              {metricsOverTime.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">No evaluation data yet. Train and evaluate models to see trends.</div>
              ) : (
                <ResponsiveContainer width="100%" height={350}>
                  <LineChart data={metricsOverTime}>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                    <XAxis dataKey="date" className="text-xs" />
                    <YAxis domain={[0, 100]} className="text-xs" />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="accuracy" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="precision" stroke="hsl(210, 70%, 50%)" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="recall" stroke="hsl(150, 60%, 45%)" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="f1" stroke="hsl(280, 60%, 55%)" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          <Card className="mt-4">
            <CardHeader><CardTitle className="text-base">False Positive Rate Trend</CardTitle></CardHeader>
            <CardContent>
              {metricsOverTime.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">No data</div>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={metricsOverTime}>
                    <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                    <XAxis dataKey="date" className="text-xs" />
                    <YAxis className="text-xs" />
                    <Tooltip />
                    <Line type="monotone" dataKey="fpr" stroke="hsl(var(--destructive))" strokeWidth={2} name="FPR %" />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="predictions">
          <Card>
            <CardHeader><CardTitle className="text-base">Prediction Distribution</CardTitle></CardHeader>
            <CardContent>
              {predictionStats.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">No predictions yet</div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie data={predictionStats} dataKey="count" nameKey="prediction" cx="50%" cy="50%" outerRadius={100} label={({ prediction, count }) => `${prediction}: ${count}`}>
                        {predictionStats.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={predictionStats}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                      <XAxis dataKey="prediction" className="text-xs" />
                      <YAxis className="text-xs" />
                      <Tooltip />
                      <Bar dataKey="count" fill="hsl(var(--primary))" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="comparison">
          <Card>
            <CardHeader><CardTitle className="text-base">Model Comparison</CardTitle></CardHeader>
            <CardContent>
              {modelComparison.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">No models</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead><tr className="border-b">
                      <th className="text-left py-2 px-3">Model</th>
                      <th className="text-left py-2 px-3">Algorithm</th>
                      <th className="text-left py-2 px-3">Status</th>
                      <th className="text-right py-2 px-3">Accuracy</th>
                      <th className="text-right py-2 px-3">F1</th>
                      <th className="text-right py-2 px-3">FPR</th>
                    </tr></thead>
                    <tbody>
                      {modelComparison.map(m => (
                        <tr key={m.name} className="border-b">
                          <td className="py-2 px-3 font-medium">{m.name} {m.active && <Badge variant="default" className="ml-1 text-[10px]">Active</Badge>}</td>
                          <td className="py-2 px-3 text-muted-foreground">{m.algorithm}</td>
                          <td className="py-2 px-3"><Badge variant="outline">{m.status}</Badge></td>
                          <td className="py-2 px-3 text-right">{m.accuracy != null ? `${m.accuracy}%` : '—'}</td>
                          <td className="py-2 px-3 text-right">{m.f1 != null ? `${m.f1}%` : '—'}</td>
                          <td className="py-2 px-3 text-right">{m.fpr != null ? `${m.fpr}%` : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default MLMetricsDashboard;
