import { useState, useEffect, useCallback, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RefreshCw, Network, Globe, Server, Search, ZoomIn, ZoomOut } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface TopologyEdge {
  id: string;
  source_ip: string;
  destination_ip: string;
  connection_count: number;
  protocols: unknown;
  bytes_transferred: number;
  first_seen: string;
  last_seen: string;
}

interface AssetInfo {
  ip_address: string;
  hostname: string | null;
  device_type: string;
  criticality: string;
}

interface GraphNode {
  ip: string;
  x: number;
  y: number;
  connections: number;
  isGateway: boolean;
  asset?: AssetInfo;
}

const NetworkTopology = () => {
  const [edges, setEdges] = useState<TopologyEdge[]>([]);
  const [assets, setAssets] = useState<Record<string, AssetInfo>>({});
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [edgeRes, assetRes] = await Promise.all([
        supabase.from("network_topology").select("*").order("connection_count", { ascending: false }).limit(500),
        supabase.from("asset_inventory").select("ip_address, hostname, device_type, criticality"),
      ]);

      if (edgeRes.data) setEdges(edgeRes.data);
      if (assetRes.data) {
        const map: Record<string, AssetInfo> = {};
        assetRes.data.forEach((a) => (map[a.ip_address] = a));
        setAssets(map);
      }
    } catch (e) {
      toast.error("Failed to load topology data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Build nodes from edges
  const nodes: GraphNode[] = (() => {
    const nodeMap: Record<string, { connections: number }> = {};
    edges.forEach((e) => {
      nodeMap[e.source_ip] = nodeMap[e.source_ip] || { connections: 0 };
      nodeMap[e.destination_ip] = nodeMap[e.destination_ip] || { connections: 0 };
      nodeMap[e.source_ip].connections += e.connection_count;
      nodeMap[e.destination_ip].connections += e.connection_count;
    });

    const ips = Object.keys(nodeMap);
    const maxConn = Math.max(...ips.map((ip) => nodeMap[ip].connections), 1);

    return ips.map((ip, i) => {
      const angle = (2 * Math.PI * i) / ips.length;
      const radius = 180;
      return {
        ip,
        x: 250 + radius * Math.cos(angle),
        y: 250 + radius * Math.sin(angle),
        connections: nodeMap[ip].connections,
        isGateway: nodeMap[ip].connections > maxConn * 0.5,
        asset: assets[ip],
      };
    });
  })();

  // Draw topology on canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const w = 500;
    const h = 500;
    canvas.width = w * window.devicePixelRatio;
    canvas.height = h * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio * zoom, window.devicePixelRatio * zoom);
    ctx.clearRect(0, 0, w / zoom, h / zoom);

    const nodeMap: Record<string, GraphNode> = {};
    nodes.forEach((n) => (nodeMap[n.ip] = n));

    // Draw edges
    edges.forEach((e) => {
      const src = nodeMap[e.source_ip];
      const dst = nodeMap[e.destination_ip];
      if (!src || !dst) return;
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(dst.x, dst.y);
      const intensity = Math.min(e.connection_count / 50, 1);
      ctx.strokeStyle = `hsla(220, 60%, 50%, ${0.15 + intensity * 0.6})`;
      ctx.lineWidth = 1 + intensity * 2;
      ctx.stroke();
    });

    // Draw nodes
    nodes.forEach((n) => {
      const radius = n.isGateway ? 10 : 6;
      const isSelected = selectedNode === n.ip;
      ctx.beginPath();
      ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = isSelected
        ? "hsl(220, 80%, 50%)"
        : n.isGateway
        ? "hsl(30, 80%, 55%)"
        : "hsl(220, 50%, 65%)";
      ctx.fill();
      ctx.strokeStyle = "hsl(0, 0%, 100%)";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Label
      ctx.fillStyle = "hsl(220, 20%, 30%)";
      ctx.font = "9px sans-serif";
      ctx.textAlign = "center";
      const label = n.asset?.hostname || n.ip;
      ctx.fillText(label.length > 18 ? label.slice(0, 16) + "…" : label, n.x, n.y + radius + 12);
    });
  }, [edges, nodes, zoom, selectedNode, assets]);

  const filteredEdges = edges.filter(
    (e) =>
      !search ||
      e.source_ip.includes(search) ||
      e.destination_ip.includes(search)
  );

  const formatBytes = (b: number) => {
    if (b > 1e9) return `${(b / 1e9).toFixed(1)} GB`;
    if (b > 1e6) return `${(b / 1e6).toFixed(1)} MB`;
    if (b > 1e3) return `${(b / 1e3).toFixed(1)} KB`;
    return `${b} B`;
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Nodes</CardDescription>
            <CardTitle className="text-2xl">{nodes.length}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Edges</CardDescription>
            <CardTitle className="text-2xl">{edges.length}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Gateways</CardDescription>
            <CardTitle className="text-2xl">{nodes.filter((n) => n.isGateway).length}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Traffic</CardDescription>
            <CardTitle className="text-2xl">
              {formatBytes(edges.reduce((s, e) => s + e.bytes_transferred, 0))}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Graph Visualization */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Network className="h-5 w-5" />
                Network Topology Graph
              </CardTitle>
              <CardDescription>Device-to-device connection map</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="icon" onClick={() => setZoom((z) => Math.max(0.5, z - 0.2))}>
                <ZoomOut className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="icon" onClick={() => setZoom((z) => Math.min(2, z + 0.2))}>
                <ZoomIn className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="sm" onClick={fetchData} disabled={loading}>
                <RefreshCw className={`h-4 w-4 mr-1 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {nodes.length === 0 ? (
            <div className="text-center text-muted-foreground py-12">
              <Globe className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p>No topology data yet. Start the network mapper agent to discover connections.</p>
            </div>
          ) : (
            <div className="flex justify-center">
              <canvas
                ref={canvasRef}
                style={{ width: 500, height: 500 }}
                className="border rounded-lg bg-muted/30"
                onClick={(e) => {
                  const rect = (e.target as HTMLCanvasElement).getBoundingClientRect();
                  const x = (e.clientX - rect.left) / zoom;
                  const y = (e.clientY - rect.top) / zoom;
                  const clicked = nodes.find(
                    (n) => Math.hypot(n.x - x, n.y - y) < 15
                  );
                  setSelectedNode(clicked?.ip || null);
                }}
              />
            </div>
          )}

          {selectedNode && (
            <div className="mt-4 p-4 border rounded-lg bg-muted/20">
              <div className="flex items-center gap-2 mb-2">
                <Server className="h-4 w-4" />
                <span className="font-medium">{selectedNode}</span>
                {assets[selectedNode] && (
                  <>
                    <Badge variant="outline">{assets[selectedNode].device_type}</Badge>
                    <Badge variant={assets[selectedNode].criticality === "critical" ? "destructive" : "secondary"}>
                      {assets[selectedNode].criticality}
                    </Badge>
                  </>
                )}
              </div>
              {assets[selectedNode]?.hostname && (
                <p className="text-sm text-muted-foreground">Hostname: {assets[selectedNode].hostname}</p>
              )}
            </div>
          )}

          <div className="flex items-center gap-4 mt-4 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded-full" style={{ background: "hsl(30, 80%, 55%)" }} />
              Gateway
            </div>
            <div className="flex items-center gap-1">
              <div className="w-3 h-3 rounded-full" style={{ background: "hsl(220, 50%, 65%)" }} />
              Regular Node
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Connection Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Connections</CardTitle>
            <div className="relative w-64">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Filter by IP..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Connections</TableHead>
                <TableHead>Protocols</TableHead>
                <TableHead>Traffic</TableHead>
                <TableHead>Last Seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredEdges.slice(0, 50).map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="font-mono text-sm">
                    {assets[e.source_ip]?.hostname || e.source_ip}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {assets[e.destination_ip]?.hostname || e.destination_ip}
                  </TableCell>
                  <TableCell>{e.connection_count.toLocaleString()}</TableCell>
                  <TableCell>
                    {(Array.isArray(e.protocols) ? e.protocols : []).map((p: string) => (
                      <Badge key={p} variant="outline" className="mr-1 text-xs">{p}</Badge>
                    ))}
                  </TableCell>
                  <TableCell>{formatBytes(e.bytes_transferred)}</TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {new Date(e.last_seen).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
              {filteredEdges.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No connections found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default NetworkTopology;
