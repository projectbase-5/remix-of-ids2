import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Loader2, Clock, Shield, Target, Crosshair, RefreshCw } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface TimelineEvent {
  timestamp: string;
  event_type: string;
  phase: string;
  description: string;
  severity: string;
  ref_id?: string;
  source?: string;
}

interface AttackTimelineData {
  id: string;
  source_ip: string;
  timeline_events: TimelineEvent[];
  kill_chain_phases: string[];
  total_events: number;
  first_event_at: string | null;
  last_event_at: string | null;
  is_active: boolean;
}

const PHASE_ORDER = [
  "reconnaissance",
  "weaponization",
  "delivery",
  "exploitation",
  "installation",
  "command_and_control",
  "exfiltration",
];

const PHASE_LABELS: Record<string, string> = {
  reconnaissance: "Recon",
  weaponization: "Weapon",
  delivery: "Delivery",
  exploitation: "Exploit",
  installation: "Install",
  command_and_control: "C2",
  exfiltration: "Exfil",
};

const PHASE_COLORS: Record<string, string> = {
  reconnaissance: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  weaponization: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  delivery: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  exploitation: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  installation: "bg-red-500/20 text-red-400 border-red-500/30",
  command_and_control: "bg-pink-500/20 text-pink-400 border-pink-500/30",
  exfiltration: "bg-destructive/20 text-destructive border-destructive/30",
  unknown: "bg-muted text-muted-foreground border-border",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-destructive",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-green-500",
};

const ALERT_TYPE_TO_PHASE: Record<string, string> = {
  "Port Scan": "reconnaissance", "port_scan": "reconnaissance",
  "DoS": "delivery", "dos": "delivery", "DDoS": "delivery",
  "Exploit": "exploitation", "exploit": "exploitation",
  "Malware": "installation", "malware": "installation",
  "Beaconing": "command_and_control", "beaconing": "command_and_control",
  "C2": "command_and_control",
  "Data Exfiltration": "exfiltration", "data_exfil": "exfiltration",
};

const HUNT_TYPE_TO_PHASE: Record<string, string> = {
  rare_destination: "reconnaissance",
  dns_entropy: "command_and_control",
  beaconing: "command_and_control",
  data_exfil: "exfiltration",
};

const AttackTimeline = ({ isDemoMode }: { isDemoMode?: boolean }) => {
  const [timelines, setTimelines] = useState<AttackTimelineData[]>([]);
  const [selectedIp, setSelectedIp] = useState<string>("all");
  const [sourceIps, setSourceIps] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [building, setBuilding] = useState(false);
  const { toast } = useToast();

  const fetchTimelines = useCallback(async () => {
    if (isDemoMode) return;
    setLoading(true);
    const { data, error } = await supabase
      .from("attack_timelines")
      .select("*")
      .order("last_event_at", { ascending: false });
    if (!error && data) {
      const parsed = data.map((d: any) => ({
        ...d,
        timeline_events: (d.timeline_events || []) as TimelineEvent[],
        kill_chain_phases: (d.kill_chain_phases || []) as string[],
      }));
      setTimelines(parsed);
      const ips = [...new Set(parsed.map((t) => t.source_ip))];
      setSourceIps(ips);
    }
    setLoading(false);
  }, [isDemoMode]);

  useEffect(() => {
    if (isDemoMode) {
      import('@/lib/demoData').then(({ demoAttackTimelines }) => {
        setTimelines(demoAttackTimelines as AttackTimelineData[]);
        setSourceIps([...new Set(demoAttackTimelines.map(t => t.source_ip))]);
        setLoading(false);
      });
      return;
    }
    fetchTimelines();
  }, [isDemoMode, fetchTimelines]);

  // Client-side timeline builder
  const buildTimelines = async () => {
    setBuilding(true);
    try {
      const { data: alerts } = await supabase.from("live_alerts").select("*").order("created_at", { ascending: true });
      const { data: incidents } = await supabase.from("scored_incidents").select("*").order("first_alert_at", { ascending: true });
      const { data: hunts } = await supabase.from("hunt_results").select("*").order("created_at", { ascending: true });

      const byIp: Record<string, TimelineEvent[]> = {};

      for (const a of alerts || []) {
        const ip = a.source_ip;
        if (!byIp[ip]) byIp[ip] = [];
        byIp[ip].push({
          timestamp: a.created_at || "",
          event_type: a.alert_type,
          phase: ALERT_TYPE_TO_PHASE[a.alert_type] || "unknown",
          description: a.description,
          severity: a.severity,
          ref_id: a.id,
          source: "alert",
        });
      }

      for (const inc of incidents || []) {
        const ip = inc.source_ip;
        if (!byIp[ip]) byIp[ip] = [];
        const types = (inc.attack_types as string[]) || [];
        let phase = "unknown";
        for (const t of types) {
          if (ALERT_TYPE_TO_PHASE[t]) { phase = ALERT_TYPE_TO_PHASE[t]; break; }
        }
        byIp[ip].push({
          timestamp: inc.first_alert_at,
          event_type: types.join(", ") || "Incident",
          phase,
          description: `Scored incident: ${inc.severity} severity, score ${inc.total_score}`,
          severity: inc.severity,
          ref_id: inc.id,
          source: "incident",
        });
      }

      for (const h of hunts || []) {
        const ip = h.source_ip;
        if (!byIp[ip]) byIp[ip] = [];
        byIp[ip].push({
          timestamp: h.created_at,
          event_type: h.hunt_type,
          phase: HUNT_TYPE_TO_PHASE[h.hunt_type] || "unknown",
          description: `Hunt: ${h.target} (score: ${h.score})`,
          severity: "medium",
          ref_id: h.id,
          source: "hunt",
        });
      }

      let upserted = 0;
      for (const [ip, events] of Object.entries(byIp)) {
        events.sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
        const phases = [...new Set(events.map(e => e.phase).filter(p => p !== "unknown"))];
        phases.sort((a, b) => (PHASE_ORDER.indexOf(a) ?? 99) - (PHASE_ORDER.indexOf(b) ?? 99));

        await supabase.from("attack_timelines").upsert({
          source_ip: ip,
          timeline_events: events as any,
          kill_chain_phases: phases as any,
          total_events: events.length,
          first_event_at: events[0]?.timestamp || null,
          last_event_at: events[events.length - 1]?.timestamp || null,
          is_active: true,
        }, { onConflict: "source_ip" });
        upserted++;
      }

      toast({ title: "Timelines Built", description: `${upserted} attack timelines assembled.` });
      await fetchTimelines();
    } catch (err) {
      toast({ title: "Error", description: "Failed to build timelines", variant: "destructive" });
    }
    setBuilding(false);
  };

  const filtered = selectedIp === "all" ? timelines : timelines.filter(t => t.source_ip === selectedIp);
  const activeCount = timelines.filter(t => t.is_active).length;
  const totalEvents = timelines.reduce((s, t) => s + t.total_events, 0);
  const maxPhases = timelines.reduce((max, t) => Math.max(max, t.kill_chain_phases.length), 0);

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <Target className="h-8 w-8 text-muted-foreground" />
            <div>
              <div className="text-2xl font-bold">{timelines.length}</div>
              <div className="text-xs text-muted-foreground">Attack Timelines</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <Shield className="h-8 w-8 text-muted-foreground" />
            <div>
              <div className="text-2xl font-bold">{activeCount}</div>
              <div className="text-xs text-muted-foreground">Active Attacks</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <Clock className="h-8 w-8 text-muted-foreground" />
            <div>
              <div className="text-2xl font-bold">{totalEvents}</div>
              <div className="text-xs text-muted-foreground">Total Events</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <Crosshair className="h-8 w-8 text-destructive" />
            <div>
              <div className="text-2xl font-bold">{maxPhases}</div>
              <div className="text-xs text-muted-foreground">Max Kill Chain Depth</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-4 flex-wrap">
        <Select value={selectedIp} onValueChange={setSelectedIp}>
          <SelectTrigger className="w-[220px]">
            <SelectValue placeholder="Filter by IP" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Source IPs</SelectItem>
            {sourceIps.map(ip => (
              <SelectItem key={ip} value={ip}>{ip}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={buildTimelines} disabled={building}>
          {building ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
          Build Timelines
        </Button>
      </div>

      {loading ? (
        <div className="flex justify-center py-12"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
      ) : filtered.length === 0 ? (
        <Card><CardContent className="p-8 text-center text-muted-foreground">No attack timelines found. Click "Build Timelines" to assemble from existing alerts and incidents.</CardContent></Card>
      ) : (
        filtered.map(tl => (
          <Card key={tl.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg font-mono">{tl.source_ip}</CardTitle>
                  <CardDescription>{tl.total_events} events · {tl.kill_chain_phases.length} kill chain phases</CardDescription>
                </div>
                {tl.is_active && <Badge variant="destructive">Active</Badge>}
              </div>
              {/* Kill Chain Progress */}
              <div className="flex gap-1 mt-3">
                {PHASE_ORDER.map(phase => {
                  const active = tl.kill_chain_phases.includes(phase);
                  return (
                    <div key={phase} className="flex-1 text-center">
                      <div className={`h-2 rounded-full ${active ? "bg-destructive" : "bg-muted"}`} />
                      <span className={`text-[10px] ${active ? "text-foreground font-medium" : "text-muted-foreground"}`}>
                        {PHASE_LABELS[phase] || phase}
                      </span>
                    </div>
                  );
                })}
              </div>
            </CardHeader>
            <CardContent>
              {/* Vertical Timeline */}
              <div className="relative ml-4 border-l-2 border-border pl-6 space-y-4">
                {tl.timeline_events.slice(0, 50).map((evt, idx) => (
                  <div key={idx} className="relative">
                    {/* Dot */}
                    <div className={`absolute -left-[31px] top-1 w-3 h-3 rounded-full border-2 border-background ${SEVERITY_DOT[evt.severity] || "bg-muted-foreground"}`} />
                    <div className="flex items-start gap-3">
                      <div className="text-xs text-muted-foreground whitespace-nowrap min-w-[70px]">
                        {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : "—"}
                      </div>
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${PHASE_COLORS[evt.phase] || PHASE_COLORS.unknown}`}>
                        {PHASE_LABELS[evt.phase] || evt.phase}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{evt.event_type}</div>
                        <div className="text-xs text-muted-foreground truncate">{evt.description}</div>
                      </div>
                      {evt.source && (
                        <Badge variant="secondary" className="text-[10px]">{evt.source}</Badge>
                      )}
                    </div>
                  </div>
                ))}
                {tl.timeline_events.length > 50 && (
                  <div className="text-xs text-muted-foreground">…and {tl.timeline_events.length - 50} more events</div>
                )}
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
};

export default AttackTimeline;
