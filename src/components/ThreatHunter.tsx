import { useState, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Search, Download, Save, Clock, Filter, Loader2, Crosshair } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

interface HuntResult {
  id: string;
  type: 'incident' | 'prediction' | 'ip_reputation';
  timestamp: string;
  sourceIP?: string;
  destinationIP?: string;
  severity?: string;
  category: string;
  details: string;
  score?: number;
}

interface SavedQuery {
  name: string;
  filters: HuntFilters;
}

interface HuntFilters {
  sourceIP: string;
  destinationIP: string;
  severity: string;
  timeRange: string;
  category: string;
  minScore: string;
}

const DEFAULT_FILTERS: HuntFilters = { sourceIP: '', destinationIP: '', severity: 'all', timeRange: '24h', category: 'all', minScore: '' };

const QUICK_FILTERS = [
  { label: 'Critical today', filters: { ...DEFAULT_FILTERS, severity: 'critical', timeRange: '24h' } },
  { label: 'Anomalies 1h', filters: { ...DEFAULT_FILTERS, category: 'anomaly', timeRange: '1h' } },
  { label: 'High score', filters: { ...DEFAULT_FILTERS, minScore: '70' } },
];

const ThreatHunter = () => {
  const [filters, setFilters] = useState<HuntFilters>(DEFAULT_FILTERS);
  const [results, setResults] = useState<HuntResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>(() => {
    try { return JSON.parse(localStorage.getItem('threat_hunt_queries') || '[]'); }
    catch { return []; }
  });

  const getTimeCutoff = (range: string): string => {
    const ms: Record<string, number> = { '1h': 3600000, '6h': 21600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
    return new Date(Date.now() - (ms[range] || 86400000)).toISOString();
  };

  const executeHunt = useCallback(async () => {
    setLoading(true);
    const cutoff = getTimeCutoff(filters.timeRange);
    const huntResults: HuntResult[] = [];

    try {
      // Query incidents
      let incidentQuery = supabase.from('incident_logs').select('*').gte('created_at', cutoff).order('created_at', { ascending: false }).limit(200);
      if (filters.sourceIP) incidentQuery = incidentQuery.ilike('source_ip', `%${filters.sourceIP}%`);
      if (filters.destinationIP) incidentQuery = incidentQuery.ilike('destination_ip', `%${filters.destinationIP}%`);
      if (filters.severity !== 'all') incidentQuery = incidentQuery.eq('severity', filters.severity);

      const { data: incidents } = await incidentQuery;
      incidents?.forEach((i: any) => {
        const score = (i.details as any)?.threat_score ?? 0;
        if (filters.minScore && score < parseInt(filters.minScore)) return;
        if (filters.category === 'anomaly' && !(i.details as any)?.anomaly_score) return;
        huntResults.push({
          id: i.id, type: 'incident', timestamp: i.created_at,
          sourceIP: i.source_ip, destinationIP: i.destination_ip,
          severity: i.severity, category: i.incident_type,
          details: `${i.incident_type} - ${i.protocol || 'N/A'}`,
          score,
        });
      });

      // Query predictions
      let predQuery = supabase.from('predictions').select('*').gte('created_at', cutoff).order('created_at', { ascending: false }).limit(200);
      const { data: predictions } = await predQuery;
      predictions?.forEach((p: any) => {
        if (filters.category !== 'all' && filters.category !== 'anomaly' && p.prediction !== filters.category) return;
        if (filters.category === 'anomaly' && !p.is_anomaly) return;
        const score = Math.round((p.confidence || 0) * 100);
        if (filters.minScore && score < parseInt(filters.minScore)) return;
        huntResults.push({
          id: p.id, type: 'prediction', timestamp: p.created_at,
          category: p.prediction, details: `Confidence: ${(p.confidence * 100).toFixed(1)}%`,
          score,
        });
      });

      // Query IP reputation
      if (filters.sourceIP) {
        const { data: ips } = await supabase.from('ip_reputation').select('*').ilike('ip_address', `%${filters.sourceIP}%`).limit(50);
        ips?.forEach((ip: any) => {
          huntResults.push({
            id: ip.id, type: 'ip_reputation', timestamp: ip.created_at,
            sourceIP: ip.ip_address, category: 'ip_reputation',
            details: `Score: ${ip.reputation_score} | ${ip.country_code || 'N/A'} | ${ip.asn_org || 'N/A'}`,
            score: 100 - ip.reputation_score,
          });
        });
      }

      huntResults.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setResults(huntResults);
      toast.success(`Found ${huntResults.length} results`);
    } catch (e) {
      toast.error('Hunt failed: ' + String(e));
    }
    setLoading(false);
  }, [filters]);

  const saveQuery = () => {
    const name = prompt('Query name:');
    if (!name) return;
    const updated = [...savedQueries, { name, filters: { ...filters } }];
    setSavedQueries(updated);
    localStorage.setItem('threat_hunt_queries', JSON.stringify(updated));
    toast.success('Query saved');
  };

  const exportCSV = () => {
    if (results.length === 0) return;
    const headers = ['ID', 'Type', 'Timestamp', 'Source IP', 'Dest IP', 'Severity', 'Category', 'Details', 'Score'];
    const rows = results.map(r => [r.id, r.type, r.timestamp, r.sourceIP || '', r.destinationIP || '', r.severity || '', r.category, r.details, r.score || '']);
    const csv = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `threat_hunt_${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const typeColor = (t: string) => t === 'incident' ? 'destructive' : t === 'prediction' ? 'default' : 'secondary';

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Crosshair className="h-5 w-5" />Threat Hunt</CardTitle>
          <CardDescription>Search across incidents, predictions, and IP reputation data</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Quick filters */}
          <div className="flex gap-2 flex-wrap">
            {QUICK_FILTERS.map(q => (
              <Button key={q.label} variant="outline" size="sm" onClick={() => { setFilters(q.filters); }}>
                <Filter className="h-3 w-3 mr-1" />{q.label}
              </Button>
            ))}
            {savedQueries.map(q => (
              <Button key={q.name} variant="secondary" size="sm" onClick={() => setFilters(q.filters)}>
                <Clock className="h-3 w-3 mr-1" />{q.name}
              </Button>
            ))}
          </div>

          {/* Filters */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <Input placeholder="Source IP" value={filters.sourceIP} onChange={e => setFilters(f => ({ ...f, sourceIP: e.target.value }))} />
            <Input placeholder="Dest IP" value={filters.destinationIP} onChange={e => setFilters(f => ({ ...f, destinationIP: e.target.value }))} />
            <Select value={filters.severity} onValueChange={v => setFilters(f => ({ ...f, severity: v }))}>
              <SelectTrigger><SelectValue placeholder="Severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filters.timeRange} onValueChange={v => setFilters(f => ({ ...f, timeRange: v }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="1h">Last Hour</SelectItem>
                <SelectItem value="6h">Last 6 Hours</SelectItem>
                <SelectItem value="24h">Last 24 Hours</SelectItem>
                <SelectItem value="7d">Last 7 Days</SelectItem>
                <SelectItem value="30d">Last 30 Days</SelectItem>
              </SelectContent>
            </Select>
            <Input placeholder="Min Score" type="number" value={filters.minScore} onChange={e => setFilters(f => ({ ...f, minScore: e.target.value }))} />
            <div className="flex gap-2">
              <Button onClick={executeHunt} disabled={loading} className="flex-1">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}Hunt
              </Button>
            </div>
          </div>

          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={saveQuery}><Save className="h-4 w-4 mr-1" />Save Query</Button>
            <Button variant="outline" size="sm" onClick={exportCSV} disabled={results.length === 0}><Download className="h-4 w-4 mr-1" />Export CSV</Button>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Results ({results.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {results.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">Run a hunt query to see results</div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {results.map(r => (
                <div key={r.id} className="flex items-center justify-between p-3 border rounded-lg text-sm">
                  <div className="flex items-center gap-3 min-w-0">
                    <Badge variant={typeColor(r.type)} className="text-[10px] shrink-0">{r.type}</Badge>
                    <div className="min-w-0">
                      <div className="font-medium truncate">{r.category}</div>
                      <div className="text-xs text-muted-foreground truncate">{r.details}</div>
                      {r.sourceIP && <div className="text-xs text-muted-foreground font-mono">{r.sourceIP}{r.destinationIP ? ` → ${r.destinationIP}` : ''}</div>}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {r.severity && <Badge variant={r.severity === 'critical' ? 'destructive' : 'outline'}>{r.severity}</Badge>}
                    {r.score != null && <span className={`text-sm font-bold ${r.score >= 70 ? 'text-destructive' : r.score >= 40 ? 'text-yellow-500' : 'text-muted-foreground'}`}>{r.score}</span>}
                    <span className="text-xs text-muted-foreground whitespace-nowrap">{new Date(r.timestamp).toLocaleString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatHunter;
