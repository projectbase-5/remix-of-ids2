import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Monitor, Server, Database, Globe, Search, Plus, Laptop, HardDrive, AlertTriangle, CheckCircle } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface Asset {
  id: string;
  ip_address: string;
  hostname: string | null;
  device_type: string;
  os: string | null;
  owner: string | null;
  department: string | null;
  criticality: string;
  is_active: boolean;
  last_seen: string;
  first_seen: string;
  mac_address: string | null;
  open_ports: number[];
  services: string[];
  notes: string | null;
}

const DEVICE_TYPE_OPTIONS = [
  "unknown", "server", "linux_server", "windows_workstation",
  "linux_endpoint", "endpoint", "database_server", "dns_server",
  "mail_server", "router", "switch", "firewall", "printer", "iot",
];

const CRITICALITY_OPTIONS = ["critical", "high", "medium", "low"];

const getDeviceIcon = (type: string) => {
  if (type.includes("server")) return <Server className="h-4 w-4" />;
  if (type.includes("database")) return <Database className="h-4 w-4" />;
  if (type.includes("workstation") || type.includes("endpoint") || type.includes("laptop"))
    return <Laptop className="h-4 w-4" />;
  if (type.includes("router") || type.includes("switch") || type.includes("firewall"))
    return <Globe className="h-4 w-4" />;
  return <Monitor className="h-4 w-4" />;
};

const getCriticalityColor = (c: string) => {
  switch (c) {
    case "critical": return "bg-destructive text-destructive-foreground";
    case "high": return "bg-orange-500 text-white";
    case "medium": return "bg-yellow-500 text-yellow-50";
    case "low": return "bg-green-500 text-green-50";
    default: return "bg-muted text-muted-foreground";
  }
};

const isStale = (lastSeen: string) => {
  const diff = Date.now() - new Date(lastSeen).getTime();
  return diff > 24 * 60 * 60 * 1000; // 24h
};

const AssetInventory = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [critFilter, setCritFilter] = useState("all");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editAsset, setEditAsset] = useState<Asset | null>(null);

  // Form state
  const [form, setForm] = useState({
    ip_address: "", hostname: "", device_type: "unknown", os: "",
    owner: "", department: "", criticality: "medium", notes: "",
  });

  const fetchAssets = async () => {
    const { data, error } = await supabase
      .from("asset_inventory")
      .select("*")
      .order("last_seen", { ascending: false });
    if (error) {
      console.error("Error fetching assets:", error);
    } else {
      setAssets((data || []).map((a: Record<string, unknown>) => ({
        ...a,
        open_ports: Array.isArray(a.open_ports) ? a.open_ports : [],
        services: Array.isArray(a.services) ? a.services : [],
      })) as Asset[]);
    }
    setLoading(false);
  };

  useEffect(() => { fetchAssets(); }, []);

  // Realtime subscription
  useEffect(() => {
    const channel = supabase
      .channel("asset_inventory_changes")
      .on("postgres_changes", { event: "*", schema: "public", table: "asset_inventory" }, () => {
        fetchAssets();
      })
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, []);

  const filtered = useMemo(() => {
    return assets.filter(a => {
      const matchSearch = !search ||
        a.ip_address.includes(search) ||
        (a.hostname || "").toLowerCase().includes(search.toLowerCase()) ||
        (a.owner || "").toLowerCase().includes(search.toLowerCase());
      const matchType = typeFilter === "all" || a.device_type === typeFilter;
      const matchCrit = critFilter === "all" || a.criticality === critFilter;
      return matchSearch && matchType && matchCrit;
    });
  }, [assets, search, typeFilter, critFilter]);

  const stats = useMemo(() => ({
    total: assets.length,
    servers: assets.filter(a => a.device_type.includes("server")).length,
    endpoints: assets.filter(a => a.device_type.includes("endpoint") || a.device_type.includes("workstation")).length,
    unknown: assets.filter(a => a.device_type === "unknown").length,
    stale: assets.filter(a => isStale(a.last_seen)).length,
    critical: assets.filter(a => a.criticality === "critical").length,
  }), [assets]);

  const openAdd = () => {
    setEditAsset(null);
    setForm({ ip_address: "", hostname: "", device_type: "unknown", os: "", owner: "", department: "", criticality: "medium", notes: "" });
    setDialogOpen(true);
  };

  const openEdit = (asset: Asset) => {
    setEditAsset(asset);
    setForm({
      ip_address: asset.ip_address,
      hostname: asset.hostname || "",
      device_type: asset.device_type,
      os: asset.os || "",
      owner: asset.owner || "",
      department: asset.department || "",
      criticality: asset.criticality,
      notes: asset.notes || "",
    });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!form.ip_address.trim()) {
      toast.error("IP address is required");
      return;
    }
    const payload = {
      ip_address: form.ip_address.trim(),
      hostname: form.hostname || null,
      device_type: form.device_type,
      os: form.os || null,
      owner: form.owner || null,
      department: form.department || null,
      criticality: form.criticality,
      notes: form.notes || null,
    };

    if (editAsset) {
      const { error } = await supabase
        .from("asset_inventory")
        .update(payload)
        .eq("id", editAsset.id);
      if (error) toast.error(error.message);
      else toast.success("Asset updated");
    } else {
      const { error } = await supabase
        .from("asset_inventory")
        .insert(payload);
      if (error) toast.error(error.message);
      else toast.success("Asset added");
    }
    setDialogOpen(false);
    fetchAssets();
  };

  const handleDelete = async (id: string) => {
    const { error } = await supabase.from("asset_inventory").delete().eq("id", id);
    if (error) toast.error(error.message);
    else toast.success("Asset deleted");
    fetchAssets();
  };

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "Total Assets", value: stats.total, icon: <HardDrive className="h-4 w-4" /> },
          { label: "Servers", value: stats.servers, icon: <Server className="h-4 w-4" /> },
          { label: "Endpoints", value: stats.endpoints, icon: <Laptop className="h-4 w-4" /> },
          { label: "Unknown", value: stats.unknown, icon: <Monitor className="h-4 w-4" /> },
          { label: "Stale (>24h)", value: stats.stale, icon: <AlertTriangle className="h-4 w-4 text-yellow-500" /> },
          { label: "Critical", value: stats.critical, icon: <AlertTriangle className="h-4 w-4 text-destructive" /> },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="p-4 flex items-center gap-3">
              {s.icon}
              <div>
                <div className="text-2xl font-bold">{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Filters + Add */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <HardDrive className="h-5 w-5" />
                Asset Inventory
              </CardTitle>
              <CardDescription>Track and classify network hosts</CardDescription>
            </div>
            <Button size="sm" onClick={openAdd}>
              <Plus className="h-4 w-4 mr-1" /> Add Asset
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3 mb-4">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search IP, hostname, owner..." value={search} onChange={e => setSearch(e.target.value)} className="pl-8" />
            </div>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-[160px]"><SelectValue placeholder="Device type" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {DEVICE_TYPE_OPTIONS.map(t => <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={critFilter} onValueChange={setCritFilter}>
              <SelectTrigger className="w-[140px]"><SelectValue placeholder="Criticality" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                {CRITICALITY_OPTIONS.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>

          <ScrollArea className="h-[500px]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>OS</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Criticality</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow><TableCell colSpan={9} className="text-center py-8 text-muted-foreground">Loading...</TableCell></TableRow>
                ) : filtered.length === 0 ? (
                  <TableRow><TableCell colSpan={9} className="text-center py-8 text-muted-foreground">No assets found</TableCell></TableRow>
                ) : (
                  filtered.map(a => (
                    <TableRow key={a.id} className="cursor-pointer hover:bg-muted/50" onClick={() => openEdit(a)}>
                      <TableCell className="font-mono text-sm">{a.ip_address}</TableCell>
                      <TableCell>{a.hostname || <span className="text-muted-foreground">—</span>}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          {getDeviceIcon(a.device_type)}
                          <span className="text-sm">{a.device_type.replace(/_/g, " ")}</span>
                        </div>
                      </TableCell>
                      <TableCell>{a.os || "—"}</TableCell>
                      <TableCell>{a.owner || "—"}</TableCell>
                      <TableCell><Badge className={getCriticalityColor(a.criticality)}>{a.criticality}</Badge></TableCell>
                      <TableCell>
                        {isStale(a.last_seen) ? (
                          <Badge variant="outline" className="text-yellow-600 border-yellow-400">
                            <AlertTriangle className="h-3 w-3 mr-1" /> Stale
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-green-600 border-green-400">
                            <CheckCircle className="h-3 w-3 mr-1" /> Active
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{new Date(a.last_seen).toLocaleString()}</TableCell>
                      <TableCell>
                        <Button variant="ghost" size="sm" onClick={e => { e.stopPropagation(); handleDelete(a.id); }}>
                          Delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Add/Edit Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editAsset ? "Edit Asset" : "Add Asset"}</DialogTitle>
            <DialogDescription>
              {editAsset ? "Update asset details" : "Register a new network asset"}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>IP Address *</Label>
                <Input value={form.ip_address} onChange={e => setForm({ ...form, ip_address: e.target.value })} disabled={!!editAsset} />
              </div>
              <div>
                <Label>Hostname</Label>
                <Input value={form.hostname} onChange={e => setForm({ ...form, hostname: e.target.value })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Device Type</Label>
                <Select value={form.device_type} onValueChange={v => setForm({ ...form, device_type: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {DEVICE_TYPE_OPTIONS.map(t => <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>OS</Label>
                <Input value={form.os} onChange={e => setForm({ ...form, os: e.target.value })} placeholder="e.g. Windows 11, Ubuntu 22.04" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Owner</Label>
                <Input value={form.owner} onChange={e => setForm({ ...form, owner: e.target.value })} />
              </div>
              <div>
                <Label>Department</Label>
                <Input value={form.department} onChange={e => setForm({ ...form, department: e.target.value })} />
              </div>
            </div>
            <div>
              <Label>Criticality</Label>
              <Select value={form.criticality} onValueChange={v => setForm({ ...form, criticality: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {CRITICALITY_OPTIONS.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Notes</Label>
              <Input value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSave}>{editAsset ? "Update" : "Add"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default AssetInventory;
