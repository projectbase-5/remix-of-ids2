import {
  LayoutDashboard,
  Radio,
  FileSearch,
  Settings2,
  Bug,
  Skull,
  ShieldAlert,
  Link2,
  Crosshair,
  Gauge,
  Clock,
  AlertOctagon,
  Bell,
  MessageSquareWarning,
  List,
  Database,
  Server,
  Network,
  Archive,
  Brain,
  Zap,
  RefreshCw,
  BarChart3,
  Globe,
  ChevronDown,
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
import logo from "@/assets/logo.png";

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
    label: "Overview",
    icon: LayoutDashboard,
    items: [
      { title: "Dashboard", value: "overview", icon: LayoutDashboard },
    ],
  },
  {
    label: "Detection",
    icon: ShieldAlert,
    items: [
      { title: "Monitor", value: "monitor", icon: Radio },
      { title: "Detection Rules", value: "rules", icon: FileSearch },
      { title: "Engine", value: "engine", icon: Settings2 },
      { title: "Malware Sigs", value: "malware", icon: Bug },
      { title: "Malware Behavior", value: "malware-behavior", icon: Skull },
    ],
  },
  {
    label: "Intelligence",
    icon: Crosshair,
    items: [
      { title: "Threat Intel", value: "threats", icon: ShieldAlert },
      { title: "Correlation", value: "correlation", icon: Link2 },
      { title: "Hunt", value: "hunt", icon: Crosshair },
      { title: "Risk Scores", value: "risk", icon: Gauge },
      { title: "Timeline", value: "timeline", icon: Clock },
    ],
  },
  {
    label: "Response",
    icon: AlertOctagon,
    items: [
      { title: "Incidents", value: "incidents", icon: AlertOctagon },
      { title: "Alerts", value: "alerts", icon: MessageSquareWarning },
      { title: "Notifications", value: "notifications", icon: Bell },
    ],
  },
  {
    label: "Data",
    icon: Database,
    items: [
      { title: "Events", value: "events", icon: List },
      { title: "Datasets", value: "datasets", icon: Database },
      { title: "Assets", value: "assets", icon: Server },
      { title: "Topology", value: "topology", icon: Network },
      { title: "Retention", value: "retention", icon: Archive },
    ],
  },
  {
    label: "ML",
    icon: Brain,
    items: [
      { title: "ML Models", value: "ml", icon: Brain },
      { title: "Inference", value: "inference", icon: Zap },
      { title: "Adaptive", value: "adaptive", icon: RefreshCw },
      { title: "ML Metrics", value: "ml-metrics", icon: BarChart3 },
    ],
  },
  {
    label: "Map",
    icon: Globe,
    items: [
      { title: "Threat Map", value: "map", icon: Globe },
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
          return (
            <Collapsible key={group.label} defaultOpen={groupActive || group.label === "Overview"} className="group/collapsible">
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
