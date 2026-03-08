import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Bell, Mail, Webhook, Plus, Trash2, TestTube, Loader2 } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import RoleGate from '@/components/RoleGate';
import { useRealtimeSubscription } from '@/hooks/useRealtimeSubscription';

interface NotificationConfig {
  id: string;
  config_type: string;
  target: string;
  severity_threshold: string;
  is_active: boolean;
  last_sent_at: string | null;
  created_at: string;
}

const AlertNotifications = () => {
  const [configs, setConfigs] = useState<NotificationConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [newType, setNewType] = useState<string>('email');
  const [newTarget, setNewTarget] = useState('');
  const [newThreshold, setNewThreshold] = useState('critical');
  const [testing, setTesting] = useState<string | null>(null);

  const fetchConfigs = async () => {
    const { data } = await supabase.from('notification_configs').select('*').order('created_at', { ascending: false });
    setConfigs((data as unknown as NotificationConfig[]) || []);
    setLoading(false);
  };

  useEffect(() => { fetchConfigs(); }, []);

  const handleRealtime = useCallback(() => { fetchConfigs(); }, []);
  useRealtimeSubscription('notification_configs', ['INSERT', 'UPDATE', 'DELETE'], handleRealtime);

  const addConfig = async () => {
    if (!newTarget.trim()) { toast.error('Enter a target'); return; }
    const { error } = await supabase.from('notification_configs').insert([{
      config_type: newType, target: newTarget.trim(), severity_threshold: newThreshold
    }]);
    if (error) { toast.error('Failed to add'); return; }
    toast.success('Notification config added');
    setNewTarget('');
    fetchConfigs();
  };

  const toggleActive = async (id: string, active: boolean) => {
    await supabase.from('notification_configs').update({ is_active: !active }).eq('id', id);
    fetchConfigs();
  };

  const deleteConfig = async (id: string) => {
    await supabase.from('notification_configs').delete().eq('id', id);
    toast.success('Deleted');
    fetchConfigs();
  };

  const testNotification = async (config: NotificationConfig) => {
    setTesting(config.id);
    try {
      const { data, error } = await supabase.functions.invoke('send-alert-notification', {
        body: {
          incident_type: 'test_alert',
          severity: 'critical',
          threat_score: 95,
          source_ip: '192.168.1.100',
          details: { test: true, message: 'This is a test notification' }
        }
      });
      if (error) throw error;
      toast.success('Test notification sent');
    } catch (e) {
      toast.error('Test failed: ' + String(e));
    }
    setTesting(null);
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Bell className="h-5 w-5" />Notification Settings</CardTitle>
          <CardDescription>Configure email and webhook alerts for security incidents</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3 items-end">
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Type</label>
              <Select value={newType} onValueChange={setNewType}>
                <SelectTrigger className="w-[120px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="email">Email</SelectItem>
                  <SelectItem value="webhook">Webhook</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1 flex-1 min-w-[200px]">
              <label className="text-xs text-muted-foreground">{newType === 'email' ? 'Email Address' : 'Webhook URL'}</label>
              <Input value={newTarget} onChange={e => setNewTarget(e.target.value)} placeholder={newType === 'email' ? 'team@example.com' : 'https://hooks.slack.com/...'} />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Min Severity</label>
              <Select value={newThreshold} onValueChange={setNewThreshold}>
                <SelectTrigger className="w-[120px]"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <RoleGate allowedRoles={['admin']}>
              <Button onClick={addConfig}><Plus className="h-4 w-4 mr-1" />Add</Button>
            </RoleGate>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Active Configurations</CardTitle></CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : configs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">No notification configs. Add one above.</div>
          ) : (
            <div className="space-y-3">
              {configs.map(c => (
                <div key={c.id} className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center gap-3">
                    {c.config_type === 'email' ? <Mail className="h-4 w-4 text-muted-foreground" /> : <Webhook className="h-4 w-4 text-muted-foreground" />}
                    <div>
                      <div className="text-sm font-medium">{c.target}</div>
                      <div className="text-xs text-muted-foreground">
                        Threshold: <Badge variant="outline" className="text-xs">{c.severity_threshold}</Badge>
                        {c.last_sent_at && ` · Last sent: ${new Date(c.last_sent_at).toLocaleString()}`}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="icon" onClick={() => testNotification(c)} disabled={testing === c.id}>
                      {testing === c.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <TestTube className="h-4 w-4" />}
                    </Button>
                    <RoleGate allowedRoles={['admin', 'analyst']}>
                      <Switch checked={c.is_active} onCheckedChange={() => toggleActive(c.id, c.is_active)} />
                    </RoleGate>
                    <RoleGate allowedRoles={['admin']}>
                      <Button variant="ghost" size="icon" onClick={() => deleteConfig(c.id)}><Trash2 className="h-4 w-4 text-destructive" /></Button>
                    </RoleGate>
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

export default AlertNotifications;
