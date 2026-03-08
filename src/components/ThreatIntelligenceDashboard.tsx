import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { useThreatIntelligence } from '@/hooks/useThreatIntelligence';
import { Globe, Search, RefreshCw, Shield, AlertTriangle, Wifi, Server, MapPin } from 'lucide-react';

const ThreatIntelligenceDashboard = () => {
  const { 
    ipReputations, 
    threatFeeds, 
    incidentLogs, 
    loading, 
    checking, 
    checkIPReputation,
    refresh 
  } = useThreatIntelligence();
  
  const [ipInput, setIPInput] = useState('');
  const [checkResult, setCheckResult] = useState<{
    ip_address: string;
    reputation_score: number;
    is_malicious: boolean;
    threat_types: string[];
    country_code: string | null;
    is_tor_exit: boolean;
    is_vpn: boolean;
    is_proxy: boolean;
    source: string;
    isp: string | null;
    domain: string | null;
    usage_type: string | null;
    abuse_reports: number;
    cached: boolean;
  } | null>(null);

  const handleCheckIP = async () => {
    if (!ipInput.trim()) return;
    const result = await checkIPReputation(ipInput.trim());
    if (result) {
      setCheckResult(result);
    }
  };

  const getReputationColor = (score: number) => {
    if (score >= 80) return 'text-red-500';
    if (score >= 50) return 'text-orange-500';
    if (score >= 25) return 'text-yellow-500';
    return 'text-green-500';
  };

  const getReputationBgColor = (score: number) => {
    if (score >= 80) return 'bg-red-500';
    if (score >= 50) return 'bg-orange-500';
    if (score >= 25) return 'bg-yellow-500';
    return 'bg-green-500';
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

  const maliciousCount = ipReputations.filter(ip => ip.reputation_score >= 50).length;
  const torExitCount = ipReputations.filter(ip => ip.is_tor_exit).length;
  const recentIncidents = incidentLogs.filter(i => {
    const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
    return new Date(i.created_at) > hourAgo;
  }).length;

  return (
    <div className="space-y-6">
      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total IPs Tracked</p>
                <p className="text-2xl font-bold">{ipReputations.length}</p>
              </div>
              <Globe className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Malicious IPs</p>
                <p className="text-2xl font-bold text-destructive">{maliciousCount}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-destructive" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Tor Exit Nodes</p>
                <p className="text-2xl font-bold text-orange-500">{torExitCount}</p>
              </div>
              <Wifi className="h-8 w-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Recent Incidents</p>
                <p className="text-2xl font-bold">{recentIncidents}</p>
              </div>
              <Server className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center space-x-2">
                <Globe className="h-5 w-5" />
                <span>Threat Intelligence</span>
              </CardTitle>
              <CardDescription>IP reputation checking and threat feed management</CardDescription>
            </div>
            <Button variant="outline" onClick={refresh} disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="check" className="space-y-4">
            <TabsList>
              <TabsTrigger value="check">Check IP</TabsTrigger>
              <TabsTrigger value="reputation">IP Database ({ipReputations.length})</TabsTrigger>
              <TabsTrigger value="feeds">Threat Feeds ({threatFeeds.length})</TabsTrigger>
              <TabsTrigger value="incidents">Incidents ({incidentLogs.length})</TabsTrigger>
            </TabsList>

            <TabsContent value="check" className="space-y-4">
              <div className="flex space-x-2">
                <Input
                  value={ipInput}
                  onChange={(e) => setIPInput(e.target.value)}
                  placeholder="Enter IP address to check (e.g., 192.168.1.1)"
                  className="flex-1"
                />
                <Button onClick={handleCheckIP} disabled={checking || !ipInput.trim()}>
                  <Search className="h-4 w-4 mr-2" />
                  {checking ? 'Checking...' : 'Check IP'}
                </Button>
              </div>

              {checkResult && (
                <Card className={checkResult.is_malicious ? 'border-destructive' : 'border-green-500'}>
                  <CardContent className="pt-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <div className="flex items-center space-x-4 mb-4">
                          {checkResult.is_malicious ? (
                            <AlertTriangle className="h-10 w-10 text-destructive" />
                          ) : (
                            <Shield className="h-10 w-10 text-green-500" />
                          )}
                          <div>
                            <h4 className="font-semibold text-lg">{checkResult.ip_address}</h4>
                            <p className={`text-sm ${getReputationColor(checkResult.reputation_score)}`}>
                              {checkResult.is_malicious ? 'Malicious IP Detected' : 'Clean IP'}
                            </p>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <div className="flex items-center space-x-2">
                            <MapPin className="h-4 w-4" />
                            <span>Country: {checkResult.country_code || 'Unknown'}</span>
                          </div>
                          {checkResult.is_tor_exit && (
                            <Badge variant="outline" className="bg-purple-100 text-purple-800">Tor Exit Node</Badge>
                          )}
                          {checkResult.is_vpn && (
                            <Badge variant="outline" className="bg-blue-100 text-blue-800">VPN</Badge>
                          )}
                          {checkResult.is_proxy && (
                            <Badge variant="outline" className="bg-orange-100 text-orange-800">Proxy</Badge>
                          )}
                        </div>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground mb-2">Reputation Score</p>
                        <div className="flex items-center space-x-4">
                          <Progress 
                            value={checkResult.reputation_score} 
                            className={`flex-1 ${getReputationBgColor(checkResult.reputation_score)}`} 
                          />
                          <span className={`text-2xl font-bold ${getReputationColor(checkResult.reputation_score)}`}>
                            {checkResult.reputation_score}/100
                          </span>
                        </div>
                        {checkResult.threat_types.length > 0 && (
                          <div className="mt-4">
                            <p className="text-sm text-muted-foreground mb-2">Threat Types</p>
                            <div className="flex flex-wrap gap-2">
                              {checkResult.threat_types.map((type, idx) => (
                                <Badge key={idx} variant="destructive">{type}</Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="reputation">
              <ScrollArea className="h-[400px]">
                {loading ? (
                  <div className="text-center py-8 text-muted-foreground">Loading...</div>
                ) : ipReputations.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">No IPs in database</div>
                ) : (
                  <div className="space-y-2">
                    {ipReputations.map((ip) => (
                      <div key={ip.id} className="border rounded-lg p-3 flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          <div className={`w-2 h-2 rounded-full ${getReputationBgColor(ip.reputation_score)}`} />
                          <div>
                            <span className="font-mono">{ip.ip_address}</span>
                            <div className="flex items-center space-x-2 mt-1">
                              {ip.country_code && (
                                <Badge variant="outline" className="text-xs">{ip.country_code}</Badge>
                              )}
                              {ip.is_tor_exit && <Badge variant="outline" className="text-xs">Tor</Badge>}
                              {ip.threat_types?.slice(0, 2).map((t, i) => (
                                <Badge key={i} variant="secondary" className="text-xs">{t}</Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <span className={`text-lg font-bold ${getReputationColor(ip.reputation_score)}`}>
                            {ip.reputation_score}
                          </span>
                          <p className="text-xs text-muted-foreground">{ip.abuse_reports} reports</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </TabsContent>

            <TabsContent value="feeds">
              <ScrollArea className="h-[400px]">
                {threatFeeds.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">No threat feeds configured</div>
                ) : (
                  <div className="space-y-3">
                    {threatFeeds.map((feed) => (
                      <div key={feed.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-3">
                            <Server className="h-5 w-5" />
                            <span className="font-semibold">{feed.name}</span>
                            <Badge variant={feed.is_active ? 'default' : 'secondary'}>
                              {feed.is_active ? 'Active' : 'Inactive'}
                            </Badge>
                          </div>
                          <Badge variant="outline">{feed.feed_type}</Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          <p>URL: {feed.url || 'N/A'}</p>
                          <p>Update frequency: Every {feed.update_frequency_hours} hours</p>
                          <p>Entries: {feed.entries_count} | Last updated: {feed.last_updated ? new Date(feed.last_updated).toLocaleString() : 'Never'}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </TabsContent>

            <TabsContent value="incidents">
              <ScrollArea className="h-[400px]">
                {incidentLogs.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">No incidents logged</div>
                ) : (
                  <div className="space-y-2">
                    {incidentLogs.map((incident) => (
                      <div key={incident.id} className="border rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-3">
                            <AlertTriangle className="h-4 w-4" />
                            <span className="font-semibold">{incident.incident_type}</span>
                            <Badge className={getSeverityColor(incident.severity)}>{incident.severity}</Badge>
                            <Badge variant="outline">{incident.status}</Badge>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(incident.created_at).toLocaleString()}
                          </span>
                        </div>
                        <div className="text-sm text-muted-foreground grid grid-cols-2 gap-2">
                          {incident.source_ip && <span>Source: {incident.source_ip}:{incident.source_port}</span>}
                          {incident.destination_ip && <span>Dest: {incident.destination_ip}:{incident.destination_port}</span>}
                          {incident.protocol && <span>Protocol: {incident.protocol}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatIntelligenceDashboard;
