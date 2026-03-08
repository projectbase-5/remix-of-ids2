import { useState, useCallback, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Search, Download, Save, Clock, Filter, Loader2, Crosshair, Zap, Radio, Database, FileWarning, List } from 'lucide-react';
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

interface LogSearchFilters {
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  port: string;
  payloadKeyword: string;
  category: string;
  timeRange: string;
}

interface LogResult {
  id: string;
  table: string;
  timestamp: string;
  source_ip: string;
  destination_ip?: string;
  protocol?: string;
  port?: number;
  packet_size?: number;
  payload_preview?: string;
  is_suspicious?: boolean;
  severity?: string;
  alert_type?: string;
  description?: string;
}

const DEFAULT_LOG_FILTERS: LogSearchFilters = { sourceIP: '', destinationIP: '', protocol: 'all', port: '', payloadKeyword: '', category: 'all', timeRange: '24h' };

interface AdvancedHuntResult {
  id: string;
  hunt_type: string;
  source_ip: string;
  target: string;
  score: number;
  details: Record<string, any>;
  created_at: string;
}

interface SavedQuery { name: string; filters: HuntFilters; }
interface HuntFilters { sourceIP: string; destinationIP: string; severity: string; timeRange: string; category: string; minScore: string; }

const DEFAULT_FILTERS: HuntFilters = { sourceIP: '', destinationIP: '', severity: 'all', timeRange: '24h', category: 'all', minScore: '' };
const QUICK_FILTERS = [
  { label: 'Critical today', filters: { ...DEFAULT_FILTERS, severity: 'critical', timeRange: '24h' } },
  { label: 'Anomalies 1h', filters: { ...DEFAULT_FILTERS, category: 'anomaly', timeRange: '1h' } },
  { label: 'High score', filters: { ...DEFAULT_FILTERS, minScore: '70' } },
];

const HUNT_TYPES = [
  { id: 'rare_destination', label: 'Rare Destinations', icon: Radio, desc: 'Hosts contacting IPs seen by few others' },
  { id: 'dns_entropy', label: 'DNS Entropy / DGA', icon: Zap, desc: 'High entropy domains (DGA detection)' },
  { id: 'beaconing', label: 'Beaconing', icon: Radio, desc: 'Periodic C2-like connections' },
  { id: 'data_exfil', label: 'Data Exfiltration', icon: Database, desc: 'Abnormally high outbound data' },
];

const ThreatHunter = ({ isDemoMode }: { isDemoMode?: boolean }) => {
  const [filters, setFilters] = useState<HuntFilters>(DEFAULT_FILTERS);
  const [results, setResults] = useState<HuntResult[]>([]);
  const [advancedResults, setAdvancedResults] = useState<AdvancedHuntResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [advancedLoading, setAdvancedLoading] = useState<string | null>(null);
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>(() => {
    try { return JSON.parse(localStorage.getItem('threat_hunt_queries') || '[]'); } catch { return []; }
  });

  // Load advanced hunt results
  const fetchAdvancedResults = useCallback(async () => {
    if (isDemoMode) return;
    const { data } = await supabase.from('hunt_results').select('*').order('created_at', { ascending: false }).limit(200);
    if (data) setAdvancedResults(data.map(d => ({ ...d, details: (typeof d.details === 'object' && d.details !== null ? d.details : {}) as Record<string, any> })));
  }, [isDemoMode]);

  useEffect(() => {
    if (isDemoMode) {
      import('@/lib/demoData').then(({ demoHuntResults }) => {
        setAdvancedResults(demoHuntResults as AdvancedHuntResult[]);
      });
      return;
    }
    fetchAdvancedResults();
  }, [isDemoMode, fetchAdvancedResults]);

  const getTimeCutoff = (range: string): string => {
    const ms: Record<string, number> = { '1h': 3600000, '6h': 21600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
    return new Date(Date.now() - (ms[range] || 86400000)).toISOString();
  };

  const executeHunt = useCallback(async () => {
    setLoading(true);
    const cutoff = getTimeCutoff(filters.timeRange);
    const huntResults: HuntResult[] = [];
    try {
      let incidentQuery = supabase.from('incident_logs').select('*').gte('created_at', cutoff).order('created_at', { ascending: false }).limit(200);
      if (filters.sourceIP) incidentQuery = incidentQuery.ilike('source_ip', `%${filters.sourceIP}%`);
      if (filters.destinationIP) incidentQuery = incidentQuery.ilike('destination_ip', `%${filters.destinationIP}%`);
      if (filters.severity !== 'all') incidentQuery = incidentQuery.eq('severity', filters.severity);
      const { data: incidents } = await incidentQuery;
      incidents?.forEach((i: any) => {
        const score = (i.details as any)?.threat_score ?? 0;
        if (filters.minScore && score < parseInt(filters.minScore)) return;
        if (filters.category === 'anomaly' && !(i.details as any)?.anomaly_score) return;
        huntResults.push({ id: i.id, type: 'incident', timestamp: i.created_at, sourceIP: i.source_ip, destinationIP: i.destination_ip, severity: i.severity, category: i.incident_type, details: `${i.incident_type} - ${i.protocol || 'N/A'}`, score });
      });

      const { data: predictions } = await supabase.from('predictions').select('*').gte('created_at', cutoff).order('created_at', { ascending: false }).limit(200);
      predictions?.forEach((p: any) => {
        if (filters.category !== 'all' && filters.category !== 'anomaly' && p.prediction !== filters.category) return;
        if (filters.category === 'anomaly' && !p.is_anomaly) return;
        const score = Math.round((p.confidence || 0) * 100);
        if (filters.minScore && score < parseInt(filters.minScore)) return;
        huntResults.push({ id: p.id, type: 'prediction', timestamp: p.created_at, category: p.prediction, details: `Confidence: ${(p.confidence * 100).toFixed(1)}%`, score });
      });

      if (filters.sourceIP) {
        const { data: ips } = await supabase.from('ip_reputation').select('*').ilike('ip_address', `%${filters.sourceIP}%`).limit(50);
        ips?.forEach((ip: any) => {
          huntResults.push({ id: ip.id, type: 'ip_reputation', timestamp: ip.created_at, sourceIP: ip.ip_address, category: 'ip_reputation', details: `Score: ${ip.reputation_score} | ${ip.country_code || 'N/A'} | ${ip.asn_org || 'N/A'}`, score: 100 - ip.reputation_score });
        });
      }

      huntResults.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      setResults(huntResults);
      toast.success(`Found ${huntResults.length} results`);
    } catch (e) { toast.error('Hunt failed: ' + String(e)); }
    setLoading(false);
  }, [filters]);

  // Run an advanced hunt client-side using existing DB data
  const runAdvancedHunt = useCallback(async (huntType: string) => {
    setAdvancedLoading(huntType);
    try {
      let newResults: Omit<AdvancedHuntResult, 'id' | 'created_at'>[] = [];

      if (huntType === 'rare_destination') {
        const { data: traffic } = await supabase.from('network_traffic').select('source_ip,destination_ip').order('created_at', { ascending: false }).limit(1000);
        if (traffic) {
          const destSources: Record<string, Set<string>> = {};
          traffic.forEach((t: any) => { if (!destSources[t.destination_ip]) destSources[t.destination_ip] = new Set(); destSources[t.destination_ip].add(t.source_ip); });
          const rareDests = Object.entries(destSources).filter(([, s]) => s.size <= 2);
          const srcContacts: Record<string, Record<string, number>> = {};
          traffic.forEach((t: any) => { if (destSources[t.destination_ip]?.size <= 2) { if (!srcContacts[t.source_ip]) srcContacts[t.source_ip] = {}; srcContacts[t.source_ip][t.destination_ip] = (srcContacts[t.source_ip][t.destination_ip] || 0) + 1; } });
          Object.entries(srcContacts).forEach(([src, dests]) => {
            Object.entries(dests).forEach(([dst, count]) => {
              const score = Math.min(100, Math.round((1 / Math.max(destSources[dst].size, 1)) * 100 * Math.log2(count + 1)));
              newResults.push({ hunt_type: 'rare_destination', source_ip: src, target: dst, score, details: { contact_count: count, total_sources: destSources[dst].size } });
            });
          });
        }
      } else if (huntType === 'dns_entropy') {
        // Use destination IPs as proxy (real DNS data would need DNS logs)
        const { data: traffic } = await supabase.from('network_traffic').select('source_ip,destination_ip,payload_preview').order('created_at', { ascending: false }).limit(500);
        if (traffic) {
          traffic.forEach((t: any) => {
            const target = t.payload_preview || t.destination_ip;
            const entropy = shannonEntropy(target);
            if (entropy >= 3.5) {
              newResults.push({ hunt_type: 'dns_entropy', source_ip: t.source_ip, target, score: Math.min(100, Math.round((entropy / 5) * 100)), details: { entropy: Math.round(entropy * 1000) / 1000, length: target.length } });
            }
          });
        }
      } else if (huntType === 'beaconing') {
        const { data: traffic } = await supabase.from('network_traffic').select('source_ip,destination_ip,created_at').order('created_at', { ascending: false }).limit(1000);
        if (traffic) {
          const pairs: Record<string, number[]> = {};
          traffic.forEach((t: any) => { const k = `${t.source_ip}->${t.destination_ip}`; if (!pairs[k]) pairs[k] = []; pairs[k].push(new Date(t.created_at).getTime()); });
          Object.entries(pairs).forEach(([key, ts]) => {
            if (ts.length < 5) return;
            ts.sort((a, b) => a - b);
            const intervals = ts.slice(1).map((t, i) => t - ts[i]);
            const mean = intervals.reduce((s, v) => s + v, 0) / intervals.length;
            if (mean <= 0) return;
            const std = Math.sqrt(intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / intervals.length);
            const cv = std / mean;
            if (cv <= 0.15) {
              const [src, dst] = key.split('->');
              newResults.push({ hunt_type: 'beaconing', source_ip: src, target: dst, score: Math.min(100, Math.round((1 - cv) * 100)), details: { mean_interval_sec: Math.round(mean / 1000), jitter_cv: Math.round(cv * 10000) / 10000, connections: ts.length } });
            }
          });
        }
      } else if (huntType === 'data_exfil') {
        const { data: flows } = await supabase.from('flow_metrics_log').select('source_ip,total_bytes,unique_destinations').order('created_at', { ascending: false }).limit(500);
        if (flows) {
          const bytesBySrc: Record<string, number> = {};
          flows.forEach((f: any) => { bytesBySrc[f.source_ip] = (bytesBySrc[f.source_ip] || 0) + (f.total_bytes || 0); });
          const values = Object.values(bytesBySrc);
          const mean = values.reduce((s, v) => s + v, 0) / Math.max(values.length, 1);
          const std = Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / Math.max(values.length, 1));
          Object.entries(bytesBySrc).forEach(([src, total]) => {
            if (total >= 1_000_000) {
              const z = (total - mean) / Math.max(std, 1);
              newResults.push({ hunt_type: 'data_exfil', source_ip: src, target: `${Math.round(total / 1_000_000)}MB`, score: Math.min(100, Math.max(0, Math.round(z * 20))), details: { total_bytes: total, z_score: Math.round(z * 100) / 100 } });
            }
          });
        }
      }

      // Insert results into DB
      if (newResults.length > 0) {
        await supabase.from('hunt_results').insert(newResults);
      }
      toast.success(`${huntType}: ${newResults.length} findings`);
      await fetchAdvancedResults();
    } catch (e) { toast.error('Advanced hunt failed: ' + String(e)); }
    setAdvancedLoading(null);
  }, [fetchAdvancedResults]);

  const shannonEntropy = (s: string): number => {
    if (!s) return 0;
    const freq: Record<string, number> = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    const len = s.length;
    return -Object.values(freq).reduce((sum, count) => sum + (count / len) * Math.log2(count / len), 0);
  };

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
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `threat_hunt_${Date.now()}.csv`; a.click();
  };

  const typeColor = (t: string) => t === 'incident' ? 'destructive' : t === 'prediction' ? 'default' : 'secondary';
  const huntTypeColor = (t: string) => t === 'rare_destination' ? 'destructive' : t === 'dns_entropy' ? 'default' : t === 'beaconing' ? 'secondary' : 'outline';

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Crosshair className="h-5 w-5" />Threat Hunt</CardTitle>
          <CardDescription>Search across incidents, predictions, IP reputation, and run advanced hunts</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="search">
            <TabsList>
              <TabsTrigger value="search">Filter Search</TabsTrigger>
              <TabsTrigger value="advanced">Advanced Hunts</TabsTrigger>
              <TabsTrigger value="results">Hunt Results ({advancedResults.length})</TabsTrigger>
            </TabsList>

            {/* Filter Search Tab */}
            <TabsContent value="search" className="space-y-4 mt-4">
              <div className="flex gap-2 flex-wrap">
                {QUICK_FILTERS.map(q => (
                  <Button key={q.label} variant="outline" size="sm" onClick={() => setFilters(q.filters)}>
                    <Filter className="h-3 w-3 mr-1" />{q.label}
                  </Button>
                ))}
                {savedQueries.map(q => (
                  <Button key={q.name} variant="secondary" size="sm" onClick={() => setFilters(q.filters)}>
                    <Clock className="h-3 w-3 mr-1" />{q.name}
                  </Button>
                ))}
              </div>
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
                <Button onClick={executeHunt} disabled={loading}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}Hunt
                </Button>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={saveQuery}><Save className="h-4 w-4 mr-1" />Save Query</Button>
                <Button variant="outline" size="sm" onClick={exportCSV} disabled={results.length === 0}><Download className="h-4 w-4 mr-1" />Export CSV</Button>
              </div>

              {/* Filter Search Results */}
              {results.length > 0 && (
                <div className="space-y-2 max-h-[400px] overflow-y-auto mt-4">
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
              {results.length === 0 && <div className="text-center py-8 text-muted-foreground">Run a hunt query to see results</div>}
            </TabsContent>

            {/* Advanced Hunts Tab */}
            <TabsContent value="advanced" className="mt-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {HUNT_TYPES.map(h => (
                  <Card key={h.id} className="border">
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <h.icon className="h-5 w-5 mt-0.5 text-muted-foreground" />
                          <div>
                            <div className="font-medium">{h.label}</div>
                            <div className="text-xs text-muted-foreground mt-1">{h.desc}</div>
                          </div>
                        </div>
                        <Button size="sm" onClick={() => runAdvancedHunt(h.id)} disabled={advancedLoading === h.id}>
                          {advancedLoading === h.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4 mr-1" />}
                          Run
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            {/* Advanced Hunt Results Tab */}
            <TabsContent value="results" className="mt-4">
              {advancedResults.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">No advanced hunt results yet</div>
              ) : (
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {advancedResults.map(r => (
                    <div key={r.id} className="flex items-center justify-between p-3 border rounded-lg text-sm">
                      <div className="flex items-center gap-3 min-w-0">
                        <Badge variant={huntTypeColor(r.hunt_type)} className="text-[10px] shrink-0">{r.hunt_type}</Badge>
                        <div className="min-w-0">
                          <div className="font-mono text-xs">{r.source_ip} → {r.target}</div>
                          <div className="text-xs text-muted-foreground truncate">{JSON.stringify(r.details).slice(0, 80)}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <span className={`text-sm font-bold ${r.score >= 70 ? 'text-destructive' : r.score >= 40 ? 'text-yellow-500' : 'text-muted-foreground'}`}>{r.score}</span>
                        <span className="text-xs text-muted-foreground whitespace-nowrap">{new Date(r.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatHunter;
