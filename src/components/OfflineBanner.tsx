import { useOnlineStatus } from '@/hooks/useOnlineStatus';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { WifiOff, Wifi } from 'lucide-react';
import { useEffect, useState } from 'react';

export const OfflineBanner = () => {
  const isOnline = useOnlineStatus();
  const [showBanner, setShowBanner] = useState(!isOnline);
  const [justCameOnline, setJustCameOnline] = useState(false);

  useEffect(() => {
    if (!isOnline) {
      setShowBanner(true);
      setJustCameOnline(false);
    } else if (showBanner && isOnline) {
      // Was offline, now online
      setJustCameOnline(true);
      const timer = setTimeout(() => {
        setShowBanner(false);
        setJustCameOnline(false);
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [isOnline, showBanner]);

  if (!showBanner) return null;

  return (
    <div className="fixed top-0 left-0 right-0 z-50 animate-in slide-in-from-top-5">
      <Alert
        variant={justCameOnline ? 'default' : 'destructive'}
        className={`rounded-none border-x-0 border-t-0 ${
          justCameOnline
            ? 'bg-green-500/10 border-green-500/20 text-green-500'
            : 'bg-destructive/10'
        }`}
      >
        {justCameOnline ? (
          <Wifi className="h-4 w-4" />
        ) : (
          <WifiOff className="h-4 w-4" />
        )}
        <AlertDescription className="font-medium">
          {justCameOnline
            ? 'Connection restored - You\'re back online!'
            : 'You\'re offline - Some features may be limited'}
        </AlertDescription>
      </Alert>
    </div>
  );
};