
import { NetworkEvent, ThreatDetection } from './useIDSDataStore';

export interface DerivedMetrics {
  eventsPerSecond: number;
  cpuUsage: number;
  memoryUsage: number;
  networkHealth: number;
  inboundTraffic: number;
  outboundTraffic: number;
}

export const useMetricsCalculator = () => {
  const calculateMetrics = (
    events: NetworkEvent[],
    threats: ThreatDetection[],
    timeWindowMs: number = 60000
  ): DerivedMetrics => {
    const now = Date.now();
    const cutoff = now - timeWindowMs;
    
    // Filter events in time window
    const recentEvents = events.filter(event => 
      new Date(event.timestamp).getTime() > cutoff
    );
    
    const recentThreats = threats.filter(threat =>
      new Date(threat.timestamp).getTime() > cutoff
    );

    // Calculate events per second
    const eventsPerSecond = recentEvents.length / (timeWindowMs / 1000);

    // Calculate traffic volumes based on actual packet sizes and IP direction
    const { inbound, outbound } = recentEvents.reduce((acc, event) => {
      const isInbound = isInboundTraffic(event.destinationIP);
      if (isInbound) {
        acc.inbound += event.packetSize;
      } else {
        acc.outbound += event.packetSize;
      }
      return acc;
    }, { inbound: 0, outbound: 0 });

    // Calculate system load based on event volume and threat density
    const baseLoad = Math.min(90, (eventsPerSecond / 50) * 100);
    const threatLoad = Math.min(20, recentThreats.length * 2);
    const cpuUsage = Math.max(15, baseLoad + threatLoad);

    // Memory usage based on event backlog
    const memoryUsage = Math.max(25, Math.min(85, 30 + (events.length / 100) * 10));

    // Network health based on threat ratio
    const threatRatio = recentEvents.length > 0 ? recentThreats.length / recentEvents.length : 0;
    const networkHealth = Math.max(85, 100 - (threatRatio * 50));

    return {
      eventsPerSecond: Math.round(eventsPerSecond * 10) / 10,
      cpuUsage: Math.round(cpuUsage * 10) / 10,
      memoryUsage: Math.round(memoryUsage * 10) / 10,
      networkHealth: Math.round(networkHealth * 10) / 10,
      inboundTraffic: Math.round(inbound / 1024), // Convert to KB
      outboundTraffic: Math.round(outbound / 1024), // Convert to KB
    };
  };

  const isInboundTraffic = (destinationIP: string): boolean => {
    // Simple heuristic: traffic to private subnets is inbound
    return destinationIP.startsWith('192.168.') || 
           destinationIP.startsWith('10.') || 
           destinationIP.startsWith('172.16.');
  };

  return { calculateMetrics };
};
