import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useThreatIntelligence } from '@/hooks/useThreatIntelligence';
import { supabase } from '@/integrations/supabase/client';
import { Settings, Plus, Trash2, Shield, Zap, Eye, ShieldOff, Ban } from 'lucide-react';
import { toast } from 'sonner';

// ── Detection Rules Sub-component ──────────────────────────────
const DetectionRulesTab = ({ isDemoMode }: { isDemoMode?: boolean }) => {
  const { 
    detectionRules, 
    loading, 
    addDetectionRule, 
    updateDetectionRule, 
    deleteDetectionRule 
  } = useThreatIntelligence({ isDemoMode });

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [newRule, setNewRule] = useState({
    name: '', rule_type: 'signature', severity: 'medium', pattern: '',
    regex_pattern: '', rate_limit_threshold: '', rate_limit_window_seconds: '',
    yara_rule: '', description: '', mitre_attack_id: '', enabled: true,
  });

  const handleCreateRule = async () => {
    if (!newRule.name || !newRule.pattern) return;
    await addDetectionRule({
      name: newRule.name, rule_type: newRule.rule_type, severity: newRule.severity,
      pattern: newRule.pattern, regex_pattern: newRule.regex_pattern || null,
      rate_limit_threshold: newRule.rate_limit_threshold ? parseInt(newRule.rate_limit_threshold) : null,
      rate_limit_window_seconds: newRule.rate_limit_window_seconds ? parseInt(newRule.rate_limit_window_seconds) : null,
      yara_rule: newRule.yara_rule || null, description: newRule.description || null,
      mitre_attack_id: newRule.mitre_attack_id || null, enabled: newRule.enabled,
    });
    setNewRule({ name: '', rule_type: 'signature', severity: 'medium', pattern: '', regex_pattern: '', rate_limit_threshold: '', rate_limit_window_seconds: '', yara_rule: '', description: '', mitre_attack_id: '', enabled: true });
    setIsCreateDialogOpen(false);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-destructive text-destructive-foreground';
      case 'medium': return 'bg-yellow-500 text-yellow-50';
      case 'low': return 'bg-green-500 text-green-50';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'signature': return <Shield className="h-4 w-4" />;
      case 'anomaly': return <Zap className="h-4 w-4" />;
      case 'behavioral': return <Eye className="h-4 w-4" />;
      default: return <Shield className="h-4 w-4" />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'signature': return 'bg-blue-500 text-blue-50';
      case 'anomaly': return 'bg-purple-500 text-purple-50';
      case 'behavioral': return 'bg-orange-500 text-orange-50';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div>
      <div className="flex justify-end mb-4">
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button className="flex items-center space-x-2">
              <Plus className="h-4 w-4" /><span>Create Rule</span>
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[700px] max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Advanced Detection Rule</DialogTitle>
              <DialogDescription>Define a new rule with regex patterns, rate limiting, and YARA support</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Name</Label>
                <Input value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} className="col-span-3" placeholder="Rule name" />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Type</Label>
                <Select value={newRule.rule_type} onValueChange={(v) => setNewRule({ ...newRule, rule_type: v })}>
                  <SelectTrigger className="col-span-3"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="signature">Signature-based</SelectItem>
                    <SelectItem value="anomaly">Anomaly Detection</SelectItem>
                    <SelectItem value="behavioral">Behavioral Analysis</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Severity</Label>
                <Select value={newRule.severity} onValueChange={(v) => setNewRule({ ...newRule, severity: v })}>
                  <SelectTrigger className="col-span-3"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Pattern ID</Label>
                <Input value={newRule.pattern} onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })} className="col-span-3" placeholder="e.g., SQL_INJECTION, BRUTE_FORCE" />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Regex Pattern</Label>
                <Textarea value={newRule.regex_pattern} onChange={(e) => setNewRule({ ...newRule, regex_pattern: e.target.value })} className="col-span-3 font-mono text-sm" placeholder="Regular expression for matching" />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Rate Limit</Label>
                <div className="col-span-3 flex space-x-2">
                  <Input value={newRule.rate_limit_threshold} onChange={(e) => setNewRule({ ...newRule, rate_limit_threshold: e.target.value })} placeholder="Threshold" type="number" />
                  <Input value={newRule.rate_limit_window_seconds} onChange={(e) => setNewRule({ ...newRule, rate_limit_window_seconds: e.target.value })} placeholder="Window (seconds)" type="number" />
                </div>
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">MITRE ATT&CK</Label>
                <Input value={newRule.mitre_attack_id} onChange={(e) => setNewRule({ ...newRule, mitre_attack_id: e.target.value })} className="col-span-3" placeholder="e.g., T1190" />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">YARA Rule</Label>
                <Textarea value={newRule.yara_rule} onChange={(e) => setNewRule({ ...newRule, yara_rule: e.target.value })} className="col-span-3 font-mono text-sm h-24" placeholder={'rule example {\n  strings:\n    $a = "malware"\n  condition:\n    $a\n}'} />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Description</Label>
                <Textarea value={newRule.description} onChange={(e) => setNewRule({ ...newRule, description: e.target.value })} className="col-span-3" placeholder="Rule description" />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Enabled</Label>
                <Switch checked={newRule.enabled} onCheckedChange={(checked) => setNewRule({ ...newRule, enabled: checked })} />
              </div>
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>Cancel</Button>
              <Button onClick={handleCreateRule}>Create Rule</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <ScrollArea className="h-[500px]">
        {loading ? (
          <div className="text-center py-8 text-muted-foreground">Loading rules...</div>
        ) : detectionRules.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">No detection rules configured</div>
        ) : (
          <div className="space-y-4">
            {detectionRules.map((rule) => (
              <div key={rule.id} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    {getTypeIcon(rule.rule_type)}
                    <h4 className="font-semibold">{rule.name}</h4>
                    <Badge className={getTypeColor(rule.rule_type)}>{rule.rule_type}</Badge>
                    <Badge className={getSeverityColor(rule.severity)}>{rule.severity}</Badge>
                    {rule.mitre_attack_id && <Badge variant="outline" className="font-mono text-xs">{rule.mitre_attack_id}</Badge>}
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch checked={rule.enabled} onCheckedChange={() => updateDetectionRule(rule.id, { enabled: !rule.enabled })} />
                    <Button size="sm" variant="outline" onClick={() => deleteDetectionRule(rule.id)}><Trash2 className="h-3 w-3" /></Button>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{rule.description}</p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                  <div className="bg-muted/50 rounded p-2"><span className="font-medium">Pattern:</span><span className="font-mono ml-1">{rule.pattern}</span></div>
                  {rule.regex_pattern && <div className="bg-muted/50 rounded p-2"><span className="font-medium">Regex:</span><span className="font-mono ml-1 break-all">{rule.regex_pattern}</span></div>}
                  {rule.rate_limit_threshold && <div className="bg-muted/50 rounded p-2"><span className="font-medium">Rate Limit:</span><span className="ml-1">{rule.rate_limit_threshold} / {rule.rate_limit_window_seconds}s</span></div>}
                  <div className="bg-muted/50 rounded p-2"><span className="font-medium">Triggered:</span><span className="ml-1">{rule.triggered_count} times</span></div>
                </div>
                {rule.yara_rule && (
                  <div className="mt-3">
                    <details className="text-xs">
                      <summary className="cursor-pointer font-medium text-muted-foreground">YARA Rule</summary>
                      <pre className="mt-2 bg-muted/50 rounded p-2 font-mono whitespace-pre-wrap">{rule.yara_rule}</pre>
                    </details>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  );
};

// ── Suppression Rules Sub-component ────────────────────────────
interface SuppressionRule {
  id: string;
  rule_type: string;
  value: string;
  description: string | null;
  is_active: boolean;
  suppressed_count: number;
  created_at: string;
}

const SuppressionRulesTab = () => {
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newRule, setNewRule] = useState({ rule_type: 'trusted_ip', value: '', description: '' });

  const fetchRules = async () => {
    const { data, error } = await supabase
      .from('suppression_rules')
      .select('*')
      .order('created_at', { ascending: false });
    if (!error && data) setRules(data as SuppressionRule[]);
    setLoading(false);
  };

  useEffect(() => { fetchRules(); }, []);

  const handleCreate = async () => {
    if (!newRule.value) return;
    const { error } = await supabase.from('suppression_rules').insert({
      rule_type: newRule.rule_type,
      value: newRule.value,
      description: newRule.description || null,
    });
    if (error) { toast.error('Failed to create rule'); return; }
    toast.success('Suppression rule created');
    setNewRule({ rule_type: 'trusted_ip', value: '', description: '' });
    setIsCreateOpen(false);
    fetchRules();
  };

  const handleToggle = async (id: string, currentActive: boolean) => {
    await supabase.from('suppression_rules').update({ is_active: !currentActive }).eq('id', id);
    fetchRules();
  };

  const handleDelete = async (id: string) => {
    await supabase.from('suppression_rules').delete().eq('id', id);
    toast.success('Rule deleted');
    fetchRules();
  };

  const getRuleTypeInfo = (type: string) => {
    switch (type) {
      case 'trusted_ip': return { label: 'Trusted IP', color: 'bg-green-500 text-green-50', icon: <Shield className="h-4 w-4" /> };
      case 'severity_filter': return { label: 'Severity Filter', color: 'bg-yellow-500 text-yellow-50', icon: <ShieldOff className="h-4 w-4" /> };
      case 'rate_limit': return { label: 'Rate Limit', color: 'bg-blue-500 text-blue-50', icon: <Zap className="h-4 w-4" /> };
      case 'pattern_ignore': return { label: 'Pattern Ignore', color: 'bg-purple-500 text-purple-50', icon: <Ban className="h-4 w-4" /> };
      default: return { label: type, color: 'bg-muted text-muted-foreground', icon: <Shield className="h-4 w-4" /> };
    }
  };

  const getValuePlaceholder = (type: string) => {
    switch (type) {
      case 'trusted_ip': return '192.168.1.1';
      case 'severity_filter': return 'medium (suppress below this)';
      case 'rate_limit': return '10:60 (max 10 alerts per 60s per IP)';
      case 'pattern_ignore': return 'Regex pattern, e.g. Port Scan.*';
      default: return '';
    }
  };

  const totalSuppressed = rules.reduce((sum, r) => sum + (r.suppressed_count || 0), 0);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-4 text-sm text-muted-foreground">
          <span>Active rules: <strong className="text-foreground">{rules.filter(r => r.is_active).length}</strong></span>
          <span>Total suppressed: <strong className="text-foreground">{totalSuppressed}</strong></span>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button className="flex items-center space-x-2"><Plus className="h-4 w-4" /><span>Add Suppression Rule</span></Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <DialogHeader>
              <DialogTitle>Create Suppression Rule</DialogTitle>
              <DialogDescription>Add a rule to filter out noisy or false-positive alerts</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Type</Label>
                <Select value={newRule.rule_type} onValueChange={(v) => setNewRule({ ...newRule, rule_type: v })}>
                  <SelectTrigger className="col-span-3"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="trusted_ip">Trusted IP</SelectItem>
                    <SelectItem value="severity_filter">Severity Filter</SelectItem>
                    <SelectItem value="rate_limit">Rate Limit</SelectItem>
                    <SelectItem value="pattern_ignore">Pattern Ignore</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Value</Label>
                <Input value={newRule.value} onChange={(e) => setNewRule({ ...newRule, value: e.target.value })} className="col-span-3" placeholder={getValuePlaceholder(newRule.rule_type)} />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label className="text-right">Description</Label>
                <Textarea value={newRule.description} onChange={(e) => setNewRule({ ...newRule, description: e.target.value })} className="col-span-3" placeholder="Optional description" />
              </div>
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setIsCreateOpen(false)}>Cancel</Button>
              <Button onClick={handleCreate}>Create Rule</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <ScrollArea className="h-[500px]">
        {loading ? (
          <div className="text-center py-8 text-muted-foreground">Loading suppression rules...</div>
        ) : rules.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">No suppression rules configured</div>
        ) : (
          <div className="space-y-3">
            {rules.map((rule) => {
              const info = getRuleTypeInfo(rule.rule_type);
              return (
                <div key={rule.id} className="border rounded-lg p-4 flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    {info.icon}
                    <div>
                      <div className="flex items-center space-x-2">
                        <Badge className={info.color}>{info.label}</Badge>
                        <span className="font-mono text-sm">{rule.value}</span>
                      </div>
                      {rule.description && <p className="text-xs text-muted-foreground mt-1">{rule.description}</p>}
                      <p className="text-xs text-muted-foreground mt-1">Suppressed: {rule.suppressed_count} alerts</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Switch checked={rule.is_active} onCheckedChange={() => handleToggle(rule.id, rule.is_active)} />
                    <Button size="sm" variant="outline" onClick={() => handleDelete(rule.id)}><Trash2 className="h-3 w-3" /></Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </ScrollArea>
    </div>
  );
};

// ── Main Component ─────────────────────────────────────────────
const EnhancedRuleManager = ({ isDemoMode }: { isDemoMode?: boolean }) => {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Settings className="h-5 w-5" />
          <span>Enhanced Detection Rules</span>
        </CardTitle>
        <CardDescription>
          Advanced rule management with regex patterns, rate limiting, MITRE ATT&CK mapping, and alert suppression
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="detection">
          <TabsList>
            <TabsTrigger value="detection">Detection Rules</TabsTrigger>
            <TabsTrigger value="suppression">Suppression Rules</TabsTrigger>
          </TabsList>
          <TabsContent value="detection">
            <DetectionRulesTab isDemoMode={isDemoMode} />
          </TabsContent>
          <TabsContent value="suppression">
            <SuppressionRulesTab />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default EnhancedRuleManager;
