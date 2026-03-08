

# Final Architecture — Sidebar Navigation Reorganization

## Problem

The dashboard has 23 tabs in a flat horizontal scroll bar. The user's architecture diagram defines clear **layered groupings**. The system needs to be reorganized with a sidebar navigation matching these layers.

## Plan

### 1. Replace Tab Bar with Sidebar Navigation

Convert `Index.tsx` from horizontal `Tabs` to a **collapsible sidebar** layout using the existing `src/components/ui/sidebar.tsx` and `react-resizable-panels`. Group pages by architecture layer:

| Group | Pages |
|-------|-------|
| **Overview** | Overview |
| **Detection** | Monitor, Detection Rules, Engine, Malware Sigs, Malware Behavior |
| **Intelligence** | Threat Intel, Correlation, Hunt, Risk Scores, Timeline |
| **Response** | Incidents, Alerts, Notifications |
| **Data** | Events, Datasets, Assets, Topology, Retention |
| **ML** | ML Models, Inference, Adaptive, ML Metrics |
| **Map** | Map |

### 2. Sidebar Component

Create `src/components/DashboardSidebar.tsx`:
- Collapsible groups with icons matching each architecture layer
- Active page highlight
- Mobile-responsive (sheet/drawer on small screens)
- Keep the same component rendering logic, just change navigation

### 3. Modify `src/pages/Index.tsx`

- Replace `TabsList` + `TabsTrigger` with sidebar
- Keep all `TabsContent` blocks (or switch to conditional rendering based on `activeTab` state)
- Preserve the header, demo toggle, and all existing components

### 4. No Database Changes

All modules already exist and work. This is purely a navigation/layout restructure.

## Files Summary

| Action | File |
|--------|------|
| **Create** | `src/components/DashboardSidebar.tsx` — grouped sidebar navigation |
| **Modify** | `src/pages/Index.tsx` — replace tab bar with sidebar layout |

