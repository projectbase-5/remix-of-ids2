import { useState, useRef, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { Navigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

type VideoState = 'loading' | 'ready' | 'playing' | 'failed';

function VideoBg() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [videoState, setVideoState] = useState<VideoState>('loading');
  const retryCount = useRef(0);
  const maxRetries = 5;

  const attemptPlay = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    // Force muted + playsInline for autoplay compliance
    video.muted = true;
    video.playsInline = true;
    video.play().then(() => {
      setVideoState('playing');
      retryCount.current = 0;
    }).catch((err) => {
      console.warn('[VideoBg] play() rejected:', err.name);
      if (retryCount.current < maxRetries) {
        retryCount.current++;
        const delay = Math.min(500 * Math.pow(2, retryCount.current - 1), 4000);
        setTimeout(attemptPlay, delay);
      } else {
        setVideoState('failed');
      }
    });
  }, []);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const onCanPlay = () => {
      setVideoState('ready');
      attemptPlay();
    };
    const onPlaying = () => setVideoState('playing');
    const onStalled = () => {
      console.warn('[VideoBg] stalled — retrying');
      attemptPlay();
    };
    const onError = () => {
      console.error('[VideoBg] video error');
      setVideoState('failed');
    };

    video.addEventListener('canplay', onCanPlay);
    video.addEventListener('playing', onPlaying);
    video.addEventListener('stalled', onStalled);
    video.addEventListener('error', onError);

    // Attempt play immediately in case already buffered
    if (video.readyState >= 3) {
      attemptPlay();
    }

    // Resume on visibility / focus changes
    const handleVisibility = () => {
      if (!document.hidden) attemptPlay();
    };
    const handleFocus = () => attemptPlay();
    const handlePageShow = () => attemptPlay();

    document.addEventListener('visibilitychange', handleVisibility);
    window.addEventListener('focus', handleFocus);
    window.addEventListener('pageshow', handlePageShow);

    return () => {
      video.removeEventListener('canplay', onCanPlay);
      video.removeEventListener('playing', onPlaying);
      video.removeEventListener('stalled', onStalled);
      video.removeEventListener('error', onError);
      document.removeEventListener('visibilitychange', handleVisibility);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('pageshow', handlePageShow);
    };
  }, [attemptPlay]);

  return (
    <>
      {/* Always-present black fallback — never shows white */}
      <div className="fixed inset-0 z-0 bg-black" />
      {/* Animated gradient fallback if video fails */}
      {videoState === 'failed' && (
        <div
          className="fixed inset-0 z-0"
          style={{
            background: 'radial-gradient(ellipse at 30% 50%, hsl(200 80% 12%) 0%, hsl(220 60% 6%) 60%, black 100%)',
          }}
        />
      )}
      <video
        ref={videoRef}
        autoPlay
        muted
        loop
        playsInline
        preload="auto"
        className="fixed inset-0 w-full h-full object-cover z-0"
        style={{
          pointerEvents: 'none',
          background: 'black',
          opacity: videoState === 'playing' ? 1 : 0,
          transition: 'opacity 0.6s ease-in',
        }}
      >
        <source src="/videos/auth-bg.mp4" type="video/mp4" />
      </video>
      <div className="fixed inset-0 bg-black/40 z-0" />
    </>
  );
}

export default function Auth() {
  const { session, loading: authLoading } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);

  if (session && !authLoading) {
    return <Navigate to="/" replace />;
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      toast.error(error.message);
    } else {
      toast.success('Logged in');
    }
    setLoading(false);
  };

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: window.location.origin,
        data: { display_name: displayName || email },
      },
    });
    if (error) {
      toast.error(error.message);
    } else {
      toast.success('Account created! Check email to confirm.');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center relative p-4" style={{ background: 'black' }}>
      <VideoBg />
      {authLoading ? (
        <Loader2 className="h-8 w-8 animate-spin text-white/70 z-10" />
      ) : (
        <Card className="w-full max-w-md z-10 backdrop-blur-xl bg-black/30 border border-white/20 shadow-2xl">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-2">
              <Shield className="h-10 w-10 text-cyan-400" />
            </div>
            <CardTitle className="text-2xl text-white">IDS Security Dashboard</CardTitle>
            <CardDescription className="text-white/60">Sign in to access the security monitoring system</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="login">
              <TabsList className="grid w-full grid-cols-2 bg-transparent border-0">
                <TabsTrigger value="login" className="text-white/70 data-[state=active]:bg-white/20 data-[state=active]:text-white">Sign In</TabsTrigger>
                <TabsTrigger value="signup" className="text-white/70 data-[state=active]:bg-white/20 data-[state=active]:text-white">Sign Up</TabsTrigger>
              </TabsList>
              <TabsContent value="login">
                <form onSubmit={handleLogin} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="login-email" className="text-white/80">Email</Label>
                    <Input id="login-email" type="email" value={email} onChange={e => setEmail(e.target.value)} required className="bg-white/10 border-white/20 text-white placeholder:text-white/50 focus-visible:ring-cyan-400/50" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="login-password" className="text-white/80">Password</Label>
                    <Input id="login-password" type="password" value={password} onChange={e => setPassword(e.target.value)} required className="bg-white/10 border-white/20 text-white placeholder:text-white/50 focus-visible:ring-cyan-400/50" />
                  </div>
                  <Button type="submit" className="w-full bg-cyan-500/80 hover:bg-cyan-400/90 text-white backdrop-blur-sm border border-cyan-400/30" disabled={loading}>
                    {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}Sign In
                  </Button>
                </form>
              </TabsContent>
              <TabsContent value="signup">
                <form onSubmit={handleSignup} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="signup-name" className="text-white/80">Display Name</Label>
                    <Input id="signup-name" value={displayName} onChange={e => setDisplayName(e.target.value)} className="bg-white/10 border-white/20 text-white placeholder:text-white/50 focus-visible:ring-cyan-400/50" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signup-email" className="text-white/80">Email</Label>
                    <Input id="signup-email" type="email" value={email} onChange={e => setEmail(e.target.value)} required className="bg-white/10 border-white/20 text-white placeholder:text-white/50 focus-visible:ring-cyan-400/50" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="signup-password" className="text-white/80">Password</Label>
                    <Input id="signup-password" type="password" value={password} onChange={e => setPassword(e.target.value)} required minLength={6} className="bg-white/10 border-white/20 text-white placeholder:text-white/50 focus-visible:ring-cyan-400/50" />
                  </div>
                  <Button type="submit" className="w-full bg-cyan-500/80 hover:bg-cyan-400/90 text-white backdrop-blur-sm border border-cyan-400/30" disabled={loading}>
                    {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}Create Account
                  </Button>
                </form>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
