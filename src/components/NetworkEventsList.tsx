
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Clock, Globe, Server, Shield } from "lucide-react";
import { NetworkEvent } from "@/hooks/useIDSDataStore";

interface NetworkEventsListProps {
  dataStore: {
    networkEvents: NetworkEvent[];
  };
}

const NetworkEventsList = ({ dataStore }: NetworkEventsListProps) => {
  const { networkEvents } = dataStore;

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'tcp': return 'bg-blue-500';
      case 'udp': return 'bg-green-500';
      case 'icmp': return 'bg-yellow-500';
      case 'http': return 'bg-purple-500';
      case 'https': return 'bg-indigo-500';
      default: return 'bg-gray-500';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatPacketSize = (size: number) => {
    if (size < 1024) return `${size}B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)}KB`;
    return `${(size / (1024 * 1024)).toFixed(1)}MB`;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Globe className="h-5 w-5" />
          <span>Network Events</span>
        </CardTitle>
        <CardDescription>
          Real-time network traffic and packet analysis ({networkEvents.length} events)
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[600px]">
          <div className="space-y-3">
            {networkEvents.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No network events detected</p>
                <p className="text-sm">Enable demo mode to see simulated traffic</p>
              </div>
            ) : (
              networkEvents.map((event) => (
                <div
                  key={event.id}
                  className="border rounded-lg p-4 hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className={`w-3 h-3 rounded-full ${getProtocolColor(event.protocol)}`}></div>
                      <div>
                        <div className="font-medium text-sm">{event.protocol.toUpperCase()}</div>
                        <div className="text-xs text-muted-foreground">Port {event.port}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-muted-foreground flex items-center">
                        <Clock className="h-3 w-3 mr-1" />
                        {formatTimestamp(event.timestamp)}
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                    <div>
                      <div className="text-xs font-medium text-muted-foreground mb-1">Source</div>
                      <div className="text-sm font-mono">{event.sourceIP}</div>
                    </div>
                    <div>
                      <div className="text-xs font-medium text-muted-foreground mb-1">Destination</div>
                      <div className="text-sm font-mono">{event.destinationIP}</div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Badge variant="outline" className="text-xs">
                        {formatPacketSize(event.packetSize)}
                      </Badge>
                      {event.flags && event.flags.length > 0 && (
                        <div className="flex space-x-1">
                          {event.flags.map((flag, index) => (
                            <Badge key={index} variant="secondary" className="text-xs">
                              {flag}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    {event.payload && (
                      <Shield className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>

                  {event.payload && (
                    <div className="mt-3 pt-3 border-t">
                      <div className="text-xs font-medium text-muted-foreground mb-1">Payload Preview</div>
                      <div className="text-xs font-mono bg-muted p-2 rounded truncate">
                        {event.payload.substring(0, 100)}
                        {event.payload.length > 100 && '...'}
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default NetworkEventsList;
