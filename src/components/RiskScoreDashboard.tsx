import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Shield, RefreshCw, Loader2, TrendingUp } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

interface HostRiskScore {
  id: string;
  ip_address: string;
  hostname: string | null;
  alert_score: number;
  anomaly_score: number;
  reputation_score: number;
  asset_multiplier: number;
  total_risk: number;
  risk_level: string;
  updated_at: string;
}

const SEVERITY_WEIGHTS: Record<string, number> = { critical: 40, high: 25, medium: 10, low: 3 };
const CRITICALITY_MULT: Record<string, number> = { critical: 2.0, high: 1.5, medium: 1.0, low: 0.5 };

const RiskScoreDashboard = () => {
  const [scores, setScores] = useState<HostRiskScore[]>([]);
  const [networkRisk, setNetworkRisk] = useState(0);
  const [loading, setLoading] = useState(false);

  const fetchScores = useCallback(async () => {
    const { data } = await supabase
      .from('host_risk_scores')
      .select('*')
      .order('total_risk', { ascending: false })
      .limit(50);
    if (data) {
      setScores(data);
      if (data.length > 0) {
        const totalW = data.reduce((s, h) => s + h.total_risk * h.asset_multiplier, 0);
        const weight = data.reduce((s, h) => s + h.asset_multiplier, 0);
        setNetworkRisk(Math.round(totalW / Math.max(weight, 1)));
      }
    }
  }, []);

  useEffect(() => { fetchScores(); }, [fetchScores]);

  const recalculate = useCallback(async () => {
    setLoading(true);
    try {
      // Fetch all data sources
      const [incRes, predRes, repRes, assetRes] = await Promise.all([
        supabase.from('scored_incidents').select('source_ip,severity,total_score').eq('status', 'open'),
        supabase.from('predictions').select('features,is_anomaly').eq('is_anomaly', true).order('created_at', { ascending: false }).limit(1000),
        supabase.from('ip_reputation').select('ip_address,reputation_score'),
        supabase.from('asset_inventory').select('ip_address,criticality,hostname').eq('is_active', true),
      ]);

      const alertScores: Record<string, number> = {};
      (incRes.data || []).forEach((i: any) => {
        const w = SEVERITY_WEIGHTS[i.severity] || 3;
        alertScores[i.source_ip] = (alertScores[i.source_ip] || 0) + w + Math.floor((i.total_score || 0) / 10);
      });

      const anomalyScores: Record<string, number> = {};
      (predRes.data || []).forEach((p: any) => {
        const ip = p.features?.source_ip || 'unknown';
        anomalyScores[ip] = (anomalyScores[ip] || 0) + 5;
      });

      const repPenalties: Record<string, number> = {};
      (repRes.data || []).forEach((r: any) => { repPenalties[r.ip_address] = 100 - (r.reputation_score || 50); });

      const multipliers: Record<string, number> = {};
      const hostnames: Record<string, string> = {};
      (assetRes.data || []).forEach((a: any) => {
        multipliers[a.ip_address] = CRITICALITY_MULT[a.criticality] || 1.0;
        hostnames[a.ip_address] = a.hostname || '';
      });

      const allIps = new Set([...Object.keys(alertScores), ...Object.keys(anomalyScores), ...Object.keys(repPenalties), ...Object.keys(multipliers)]);
      allIps.delete('unknown');

      const newScores: Omit<HostRiskScore, 'id' | 'updated_at'>[] = [];
      for (const ip of allIps) {
        const a = alertScores[ip] || 0;
        const an = anomalyScores[ip] || 0;
        const rep = repPenalties[ip] || 0;
        const mult = multipliers[ip] || 1.0;
        const total = Math.min(100, Math.round((a + an + rep) * mult));
        const level = total >= 80 ? 'critical' : total >= 60 ? 'high' : total >= 30 ? 'medium' : 'low';
        newScores.push({ ip_address: ip, hostname: hostnames[ip] || null, alert_score: a, anomaly_score: an, reputation_score: rep, asset_multiplier: mult, total_risk: total, risk_level: level });
      }

      // Upsert scores
      for (const s of newScores) {
        await supabase.from('host_risk_scores').upsert(s, { onConflict: 'ip_address' });
      }

      toast.success(`Recalculated risk for ${newScores.length} hosts`);
      await fetchScores();
    } catch (e) {
      toast.error('Recalculation failed: ' + String(e));
    }
    setLoading(false);
  }, [fetchScores]);

  const riskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      default: return 'secondary';
    }
  };

  const gaugeColor = networkRisk >= 70 ? 'text-destructive' : networkRisk >= 40 ? 'text-yellow-500' : 'text-green-500';

  return (
    <div className="space-y-6">
      {/* Network Risk Gauge */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5" />Network Risk Score</CardTitle>
          <CardDescription>Aggregate risk across all monitored hosts</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-8">
            <div className="text-center">
              <div className={`text-6xl font-bold ${gaugeColor}`}>{networkRisk}</div>
              <div className="text-sm text-muted-foreground mt-1">/ 100</div>
            </div>
            <div className="flex-1 space-y-3">
              <Progress value={networkRisk} className="h-4" />
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Low (0-29)</span><span>Medium (30-59)</span><span>High (60-79)</span><span>Critical (80+)</span>
              </div>
            </div>
            <Button onClick={recalculate} disabled={loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <RefreshCw className="h-4 w-4 mr-1" />}
              Recalculate
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Top Riskiest Hosts */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><TrendingUp className="h-4 w-4" />Top Riskiest Hosts</CardTitle>
        </CardHeader>
        <CardContent>
          {scores.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">No risk scores yet. Click Recalculate to compute.</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead className="text-right">Alerts</TableHead>
                  <TableHead className="text-right">Anomaly</TableHead>
                  <TableHead className="text-right">Reputation</TableHead>
                  <TableHead className="text-right">Multiplier</TableHead>
                  <TableHead className="text-right">Total Risk</TableHead>
                  <TableHead>Level</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scores.slice(0, 15).map(s => (
                  <TableRow key={s.id}>
                    <TableCell className="font-mono text-sm">{s.ip_address}</TableCell>
                    <TableCell className="text-sm">{s.hostname || '—'}</TableCell>
                    <TableCell className="text-right">{s.alert_score}</TableCell>
                    <TableCell className="text-right">{s.anomaly_score}</TableCell>
                    <TableCell className="text-right">{s.reputation_score}</TableCell>
                    <TableCell className="text-right">{s.asset_multiplier}×</TableCell>
                    <TableCell className="text-right font-bold">{s.total_risk}</TableCell>
                    <TableCell><Badge variant={riskColor(s.risk_level)}>{s.risk_level}</Badge></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default RiskScoreDashboard;
