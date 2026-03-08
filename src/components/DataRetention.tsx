import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Trash2, Plus, RefreshCw, Database, Clock, AlertTriangle } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface RetentionPolicy {
  id: string;
  table_name: string;
  retention_days: number;
  archive_before_delete: boolean;
  is_active: boolean;
  last_cleanup_at: string | null;
  rows_deleted: number;
  created_at: string;
}

const MANAGED_TABLES = [
  "network_traffic",
  "system_metrics_log",
  "flow_metrics_log",
  "live_alerts",
  "incident_logs",
  "predictions",
  "network_topology",
  "correlation_events",
];

const DataRetention = () => {
  const [policies, setPolicies] = useState<RetentionPolicy[]>([]);
  const [loading, setLoading] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newTable, setNewTable] = useState("");
  const [newDays, setNewDays] = useState(30);
  const [newArchive, setNewArchive] = useState(false);

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    const { data, error } = await supabase
      .from("retention_policies")
      .select("*")
      .order("table_name");
    if (data) setPolicies(data as RetentionPolicy[]);
    if (error) toast.error("Failed to load retention policies");
    setLoading(false);
  }, []);

  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);

  const addPolicy = async () => {
    if (!newTable) return;
    const { error } = await supabase.from("retention_policies").insert({
      table_name: newTable,
      retention_days: newDays,
      archive_before_delete: newArchive,
      is_active: true,
    });
    if (error) {
      toast.error(error.message);
    } else {
      toast.success(`Policy added for ${newTable}`);
      setDialogOpen(false);
      setNewTable("");
      setNewDays(30);
      setNewArchive(false);
      fetchPolicies();
    }
  };

  const togglePolicy = async (id: string, isActive: boolean) => {
    await supabase.from("retention_policies").update({ is_active: isActive }).eq("id", id);
    fetchPolicies();
  };

  const deletePolicy = async (id: string) => {
    await supabase.from("retention_policies").delete().eq("id", id);
    toast.success("Policy deleted");
    fetchPolicies();
  };

  const updateDays = async (id: string, days: number) => {
    await supabase.from("retention_policies").update({ retention_days: days }).eq("id", id);
    fetchPolicies();
  };

  const runCleanup = async () => {
    setCleaning(true);
    try {
      const { data, error } = await supabase.functions.invoke("cleanup-data", {
        body: {},
      });
      if (error) throw error;
      const totalDeleted = data?.total_deleted || 0;
      toast.success(`Cleanup complete: ${totalDeleted} rows deleted`);
      fetchPolicies();
    } catch (e: any) {
      toast.error(`Cleanup failed: ${e.message}`);
    } finally {
      setCleaning(false);
    }
  };

  const usedTables = new Set(policies.map((p) => p.table_name));
  const availableTables = MANAGED_TABLES.filter((t) => !usedTables.has(t));
  const totalDeleted = policies.reduce((s, p) => s + (p.rows_deleted || 0), 0);
  const activePolicies = policies.filter((p) => p.is_active).length;

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active Policies</CardDescription>
            <CardTitle className="text-2xl">{activePolicies}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Policies</CardDescription>
            <CardTitle className="text-2xl">{policies.length}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Rows Cleaned</CardDescription>
            <CardTitle className="text-2xl">{totalDeleted.toLocaleString()}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Managed Tables</CardDescription>
            <CardTitle className="text-2xl">{MANAGED_TABLES.length}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Actions */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Retention Policies
              </CardTitle>
              <CardDescription>Configure how long data is kept per table</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="destructive"
                size="sm"
                onClick={runCleanup}
                disabled={cleaning || activePolicies === 0}
              >
                <Trash2 className={`h-4 w-4 mr-1 ${cleaning ? "animate-spin" : ""}`} />
                {cleaning ? "Cleaning..." : "Run Cleanup Now"}
              </Button>

              <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                <DialogTrigger asChild>
                  <Button size="sm" disabled={availableTables.length === 0}>
                    <Plus className="h-4 w-4 mr-1" />
                    Add Policy
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Add Retention Policy</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4 pt-4">
                    <div>
                      <Label>Table</Label>
                      <Select value={newTable} onValueChange={setNewTable}>
                        <SelectTrigger><SelectValue placeholder="Select table" /></SelectTrigger>
                        <SelectContent>
                          {availableTables.map((t) => (
                            <SelectItem key={t} value={t}>{t}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label>Retention (days)</Label>
                      <Input
                        type="number"
                        min={1}
                        value={newDays}
                        onChange={(e) => setNewDays(Number(e.target.value))}
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch checked={newArchive} onCheckedChange={setNewArchive} />
                      <Label>Archive before delete</Label>
                    </div>
                    <Button className="w-full" onClick={addPolicy}>Create Policy</Button>
                  </div>
                </DialogContent>
              </Dialog>

              <Button variant="outline" size="sm" onClick={fetchPolicies} disabled={loading}>
                <RefreshCw className={`h-4 w-4 mr-1 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Table</TableHead>
                <TableHead>Retention</TableHead>
                <TableHead>Archive</TableHead>
                <TableHead>Active</TableHead>
                <TableHead>Rows Deleted</TableHead>
                <TableHead>Last Cleanup</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="font-mono text-sm">{p.table_name}</TableCell>
                  <TableCell>
                    <Input
                      type="number"
                      min={1}
                      className="w-20 h-8"
                      value={p.retention_days}
                      onChange={(e) => updateDays(p.id, Number(e.target.value))}
                    />
                  </TableCell>
                  <TableCell>
                    <Badge variant={p.archive_before_delete ? "default" : "outline"}>
                      {p.archive_before_delete ? "Yes" : "No"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={p.is_active}
                      onCheckedChange={(v) => togglePolicy(p.id, v)}
                    />
                  </TableCell>
                  <TableCell>{(p.rows_deleted || 0).toLocaleString()}</TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {p.last_cleanup_at ? (
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(p.last_cleanup_at).toLocaleString()}
                      </span>
                    ) : (
                      "Never"
                    )}
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" onClick={() => deletePolicy(p.id)}>
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {policies.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    No retention policies configured. Add one to manage data lifecycle.
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

export default DataRetention;
