/**
 * useAuth — Centralised authentication state via React Context
 * =============================================================
 * Wraps a single Supabase `onAuthStateChange` subscription so that
 * every component calling `useAuth()` shares the same session, user,
 * and role state.  This avoids the "Should have a queue" React error
 * that occurred when multiple standalone hooks each called `useState`
 * independently inside concurrent renders.
 *
 * Role lookup:
 *   After login the provider queries `user_roles` to determine whether
 *   the user is an admin, analyst, or viewer.  The default is "viewer".
 *
 * Supabase deadlock avoidance:
 *   `fetchRole` is called inside a `setTimeout(…, 0)` from the
 *   `onAuthStateChange` callback.  This ensures the Supabase auth
 *   listener finishes synchronously before we issue another Supabase
 *   call, avoiding a known internal deadlock in the JS client.
 */

import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { supabase } from '@/integrations/supabase/client';
import type { Session, User } from '@supabase/supabase-js';

export type AppRole = 'admin' | 'analyst' | 'viewer';

interface AuthState {
  session: Session | null;
  user: User | null;
  role: AppRole;
  loading: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

/**
 * AuthProvider — mount once at the app root (`<App />`).
 * Provides session, user, role, and signOut to all descendants.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [role, setRole] = useState<AppRole>('viewer');
  const [loading, setLoading] = useState(true);

  /**
   * fetchRole — look up the user's role from the `user_roles` table.
   * Falls back to "viewer" if no row is found.
   */
  const fetchRole = useCallback(async (userId: string) => {
    const { data } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', userId)
      .limit(1)
      .single();
    if (data?.role) {
      setRole(data.role as AppRole);
    }
  }, []);

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      async (_event, newSession) => {
        setSession(newSession);
        setUser(newSession?.user ?? null);
        if (newSession?.user) {
          // setTimeout(…, 0) — defer the DB call to avoid Supabase deadlock
          setTimeout(() => fetchRole(newSession.user.id), 0);
        } else {
          setRole('viewer');
        }
        setLoading(false);
      }
    );

    // Eagerly hydrate on mount
    supabase.auth.getSession().then(({ data: { session: s } }) => {
      setSession(s);
      setUser(s?.user ?? null);
      if (s?.user) {
        fetchRole(s.user.id);
      }
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, [fetchRole]);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    setSession(null);
    setUser(null);
    setRole('viewer');
  }, []);

  return (
    <AuthContext.Provider value={{ session, user, role, loading, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * useAuth — consume the auth context. Must be used inside `<AuthProvider>`.
 */
export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
