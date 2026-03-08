

# Sidebar Navigation with Grouped Pages

## Structure

Replace the 22-tab horizontal bar with a collapsible sidebar. Pages are grouped into 7 sections:

| Group | Items |
|---|---|
| **Operations** | Overview, Monitor, Alerts, Events |
| **Incidents** | Incidents, Correlation, Timeline |
| **Intelligence** | Threat Intel, Hunt, Risk Dashboard, Assets |
| **Topology** | Topology (absorbs Map — ThreatMap rendered inside NetworkTopology or kept as "Topology") |
| **Detection Engine** | Engine (main), ML Models, Inference, Adaptive, ML Metrics (sub-tabs within Engine page) |
| **Configuration** | Detection Rules, Malware Sigs, Datasets, Retention |
| **Notifications** | Notifications |

## Changes

### 1. Rewrite `src/components/DashboardSidebar.tsx`

New grouped nav matching above structure. Each group is a collapsible section with icon. The "Detection Engine" and "Configuration" groups have nested items. Sidebar uses `collapsible="icon"` mode.

### 2. Rewrite `src/pages/Index.tsx`

- Wrap in `SidebarProvider` with `SidebarTrigger` in header (always visible)
- Remove horizontal `Tabs`/`TabsList`/`TabsTrigger`
- Keep `activeTab` state driven by sidebar clicks
- Remove `map` tab — merge into `topology` (render `ThreatMap` as a tab inside `NetworkTopology`, or just remove the separate map route and keep Topology)
- For "Detection Engine" group: clicking sub-items (ml, inference, adaptive, ml-metrics) still sets `activeTab` to those values and renders their components directly. The sidebar just visually nests them under "Detection Engine"
- Same for "Configuration" group items

### 3. Remove `map` from navigation

The `ThreatMap` component stays in codebase but is no longer a top-level nav item. Topology replaces it.

### Files

| Action | File |
|---|---|
| Modify | `src/components/DashboardSidebar.tsx` — new grouped structure |
| Modify | `src/pages/Index.tsx` — sidebar layout, remove tab bar, remove map tab |

