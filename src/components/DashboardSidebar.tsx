import {
  LayoutDashboard,
  Radio,
  FileSearch,
  Settings2,
  Bug,
  ShieldAlert,
  Link2,
  Crosshair,
  Gauge,
  Clock,
  AlertOctagon,
  Bell,
  List,
  Database,
  Server,
  Network,
  Archive,
  Brain,
  Zap,
  RefreshCw,
  BarChart3,
  ChevronDown,
  MessageSquareWarning,
  Cog,
} from "lucide-react";

import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

interface NavItem {
  title: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavGroup {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    label: "Operations",
    icon: LayoutDashboard,
    items: [
      { title: "Overview", value: "overview", icon: LayoutDashboard },
      { title: "Monitor", value: "monitor", icon: Radio },
      { title: "Alerts", value: "alerts", icon: MessageSquareWarning },
      { title: "Events", value: "events", icon: List },
    ],
  },
  {
    label: "Incidents",
    icon: AlertOctagon,
    items: [
      { title: "Incidents", value: "incidents", icon: AlertOctagon },
      { title: "Correlation", value: "correlation", icon: Link2 },
      { title: "Timeline", value: "timeline", icon: Clock },
    ],
  },
  {
    label: "Intelligence",
    icon: Crosshair,
    items: [
      { title: "Threat Intel", value: "threats", icon: ShieldAlert },
      { title: "Hunt", value: "hunt", icon: Crosshair },
      { title: "Risk Dashboard", value: "risk", icon: Gauge },
      { title: "Assets", value: "assets", icon: Server },
    ],
  },
  {
    label: "Topology",
    icon: Network,
    items: [
      { title: "Topology", value: "topology", icon: Network },
    ],
  },
  {
    label: "Detection Engine",
    icon: Brain,
    items: [
      { title: "Engine", value: "engine", icon: Settings2 },
      { title: "ML Models", value: "ml", icon: Brain },
      { title: "Inference", value: "inference", icon: Zap },
      { title: "Adaptive", value: "adaptive", icon: RefreshCw },
      { title: "ML Metrics", value: "ml-metrics", icon: BarChart3 },
    ],
  },
  {
    label: "Configuration",
    icon: Cog,
    items: [
      { title: "Detection Rules", value: "rules", icon: FileSearch },
      { title: "Malware Sigs", value: "malware", icon: Bug },
      { title: "Datasets", value: "datasets", icon: Database },
      { title: "Retention", value: "retention", icon: Archive },
    ],
  },
  {
    label: "Notifications",
    icon: Bell,
    items: [
      { title: "Notifications", value: "notifications", icon: Bell },
    ],
  },
];

interface DashboardSidebarProps {
  activeTab: string;
  onTabChange: (value: string) => void;
}

export function DashboardSidebar({ activeTab, onTabChange }: DashboardSidebarProps) {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border">
        <div className="flex items-center gap-2 px-2 py-1">
          {!collapsed && (
            <span className="font-semibold text-sm text-sidebar-foreground truncate">
              IDS Navigation
            </span>
          )}
        </div>
      </SidebarHeader>
      <SidebarContent>
        {navGroups.map((group) => {
          const groupActive = group.items.some((i) => i.value === activeTab);
          // Single-item groups render without collapsible
          if (group.items.length === 1) {
            const item = group.items[0];
            return (
              <SidebarGroup key={group.label}>
                <SidebarMenu>
                  <SidebarMenuItem>
                    <SidebarMenuButton
                      isActive={activeTab === item.value}
                      tooltip={item.title}
                      onClick={() => onTabChange(item.value)}
                    >
                      <item.icon className="h-4 w-4 shrink-0" />
                      {!collapsed && <span>{item.title}</span>}
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                </SidebarMenu>
              </SidebarGroup>
            );
          }

          return (
            <Collapsible
              key={group.label}
              defaultOpen={groupActive || group.label === "Operations"}
              className="group/collapsible"
            >
              <SidebarGroup>
                <CollapsibleTrigger asChild>
                  <SidebarGroupLabel className="cursor-pointer hover:bg-sidebar-accent rounded-md pr-2">
                    <group.icon className="h-4 w-4 mr-2 shrink-0" />
                    {!collapsed && (
                      <>
                        <span className="flex-1">{group.label}</span>
                        <ChevronDown className="h-3 w-3 ml-auto transition-transform group-data-[state=open]/collapsible:rotate-180" />
                      </>
                    )}
                  </SidebarGroupLabel>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      {group.items.map((item) => (
                        <SidebarMenuItem key={item.value}>
                          <SidebarMenuButton
                            isActive={activeTab === item.value}
                            tooltip={item.title}
                            onClick={() => onTabChange(item.value)}
                          >
                            <item.icon className="h-4 w-4 shrink-0" />
                            {!collapsed && <span>{item.title}</span>}
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      ))}
                    </SidebarMenu>
                  </SidebarGroupContent>
                </CollapsibleContent>
              </SidebarGroup>
            </Collapsible>
          );
        })}
      </SidebarContent>
    </Sidebar>
  );
}
