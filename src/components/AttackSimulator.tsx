import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Crosshair, Zap, Radio, Database, Play, Loader2, CheckCircle } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface SimulationType {
  id: string;
  label: string;
  icon: React.ElementType;
  description: string;
  severity: "high" | "critical";
  defaultTarget: string;
}

const SIMULATIONS: SimulationType[] = [
  { id: "port_scan", label: "Port Scan", icon: Crosshair, description: "Rapid SYN packets to many ports from a single source IP", severity: "high", defaultTarget: "192.168.1.100" },
  { id: "ddos", label: "DoS Flood", icon: Zap, description: "High-volume large packets from multiple spoofed sources", severity: "critical", defaultTarget: "192.168.1.1" },
  { id: "beacon", label: "C2 Beacon", icon: Radio, description: "Periodic callbacks to a suspicious external C2 server", severity: "high", defaultTarget: "203.0.113.50" },
  { id: "exfiltration", label: "Data Exfiltration", icon: Database, description: "Large outbound transfers to an external destination", severity: "critical", defaultTarget: "198.51.100.25" },
];

interface SimResult {
  type: string;
  packets: number;
  alerts: number;
}

const AttackSimulator = () => {
  const [running, setRunning] = useState<string | null>(null);
  const [targetIPs, setTargetIPs] = useState<Record<string, string>>({});
  const [results, setResults] = useState<SimResult[]>([]);

  const getTarget = (sim: SimulationType) => targetIPs[sim.id] || sim.defaultTarget;

  const runSimulation = async (sim: SimulationType) => {
    setRunning(sim.id);
    const target = getTarget(sim);

    try {
      let packets: any[] = [];
      let alertData: any = null;

      if (sim.id === "port_scan") {
        const ports = Array.from({ length: 50 }, () => Math.floor(Math.random() * 65535) + 1);
        packets = ports.map(port => ({
          source_ip: "10.99.1.50",
          destination_ip: target,
          protocol: "TCP",
          port,
          packet_size: Math.floor(Math.random() * 24) + 40,
          flags: ["SYN"],
          is_suspicious: true,
        }));
        alertData = { alert_type: "Port Scan", severity: "high", source_ip: "10.99.1.50", destination_ip: target, detection_module: "attack_simulator", description: `Simulated port scan: ${packets.length} ports on ${target}`, metadata: { simulation: true, ports_scanned: packets.length } };
      } else if (sim.id === "ddos") {
        packets = Array.from({ length: 100 }, () => ({
          source_ip: `10.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`,
          destination_ip: target,
          protocol: Math.random() > 0.5 ? "TCP" : "UDP",
          port: [80, 443, 53][Math.floor(Math.random() * 3)],
          packet_size: Math.floor(Math.random() * 300) + 1200,
          flags: ["SYN"],
          is_suspicious: true,
        }));
        alertData = { alert_type: "DDoS Flood", severity: "critical", source_ip: "multiple", destination_ip: target, detection_module: "attack_simulator", description: `Simulated DDoS: ${packets.length} packets targeting ${target}`, metadata: { simulation: true, total_packets: packets.length } };
      } else if (sim.id === "beacon") {
        packets = Array.from({ length: 20 }, (_, i) => ({
          source_ip: "192.168.1.42",
          destination_ip: target,
          protocol: "TCP",
          port: [443, 8443, 4444][Math.floor(Math.random() * 3)],
          packet_size: Math.floor(Math.random() * 140) + 60,
          flags: ["SYN", "ACK", "PSH"],
          payload_preview: `beacon_${String(i).padStart(4, "0")}`,
          is_suspicious: true,
        }));
        alertData = { alert_type: "C2 Beacon", severity: "high", source_ip: "192.168.1.42", destination_ip: target, detection_module: "attack_simulator", description: `Simulated C2 beacon: ${packets.length} callbacks to ${target}`, metadata: { simulation: true, beacon_count: packets.length } };
      } else if (sim.id === "exfiltration") {
        packets = Array.from({ length: 45 }, () => ({
          source_ip: "192.168.1.88",
          destination_ip: target,
          protocol: Math.random() > 0.5 ? "TCP" : "UDP",
          port: [443, 53, 8080][Math.floor(Math.random() * 3)],
          packet_size: Math.floor(Math.random() * 200) + 1300,
          flags: ["ACK", "PSH"],
          payload_preview: "base64_encoded_data...",
          is_suspicious: true,
        }));
        alertData = { alert_type: "Data Exfiltration", severity: "critical", source_ip: "192.168.1.88", destination_ip: target, detection_module: "attack_simulator", description: `Simulated exfiltration: ${packets.length} large packets to ${target}`, metadata: { simulation: true, total_packets: packets.length } };
      }

      // Insert packets
      const { error: pErr } = await supabase.from("network_traffic").insert(packets);
      if (pErr) throw pErr;

      // Insert alert
      let alertCount = 0;
      if (alertData) {
        const { error: aErr } = await supabase.from("live_alerts").insert([alertData]);
        if (!aErr) alertCount = 1;
      }

      setResults(prev => [{ type: sim.label, packets: packets.length, alerts: alertCount }, ...prev.slice(0, 9)]);
      toast.success(`${sim.label}: ${packets.length} packets + ${alertCount} alert inserted`);
    } catch (e: any) {
      toast.error(`Simulation failed: ${e.message}`);
    }
    setRunning(null);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {SIMULATIONS.map(sim => (
          <Card key={sim.id} className="border">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base flex items-center gap-2">
                  <sim.icon className="h-4 w-4" />
                  {sim.label}
                </CardTitle>
                <Badge variant={sim.severity === "critical" ? "destructive" : "default"}>
                  {sim.severity}
                </Badge>
              </div>
              <CardDescription className="text-xs">{sim.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex gap-2">
                <Input
                  placeholder="Target IP"
                  value={targetIPs[sim.id] || ""}
                  onChange={e => setTargetIPs(prev => ({ ...prev, [sim.id]: e.target.value }))}
                  className="text-sm h-8"
                />
                <Button
                  size="sm"
                  onClick={() => runSimulation(sim)}
                  disabled={running !== null}
                  className="shrink-0"
                >
                  {running === sim.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                </Button>
              </div>
              <div className="text-xs text-muted-foreground">
                Default target: <span className="font-mono">{sim.defaultTarget}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {results.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Simulation Results</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-[200px] overflow-y-auto">
              {results.map((r, i) => (
                <div key={i} className="flex items-center justify-between p-2 border rounded text-sm">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="font-medium">{r.type}</span>
                  </div>
                  <div className="flex items-center gap-3 text-muted-foreground text-xs">
                    <span>{r.packets} packets</span>
                    <span>{r.alerts} alert(s)</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default AttackSimulator;
