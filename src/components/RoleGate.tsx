import { useAuth, type AppRole } from '@/hooks/useAuth';

interface RoleGateProps {
  allowedRoles: AppRole[];
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export default function RoleGate({ allowedRoles, children, fallback = null }: RoleGateProps) {
  const { role } = useAuth();
  if (!allowedRoles.includes(role)) return <>{fallback}</>;
  return <>{children}</>;
}
