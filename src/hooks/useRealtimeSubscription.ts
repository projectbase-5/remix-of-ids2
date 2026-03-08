import { useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import type { RealtimePostgresChangesPayload } from '@supabase/supabase-js';

type Event = 'INSERT' | 'UPDATE' | 'DELETE';

export function useRealtimeSubscription(
  table: string,
  events: Event[],
  callback: (payload: RealtimePostgresChangesPayload<any>) => void
) {
  useEffect(() => {
    const channel = supabase.channel(`realtime-${table}`);
    
    events.forEach(event => {
      channel.on(
        'postgres_changes' as any,
        { event, schema: 'public', table },
        callback
      );
    });

    channel.subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [table, callback]);
}
