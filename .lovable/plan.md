

# Show Only Group Icons When Sidebar Is Collapsed

## Problem
When the sidebar is collapsed, it currently shows every individual page icon (~20+ icons). The user wants it to show only the group-level icons (~7 icons), matching the first screenshot.

## Approach
When `collapsed` is true, render one `SidebarMenuButton` per **group** (using the group's icon), not per item. Clicking the group icon navigates to either the currently active item within that group, or the first item in that group.

## Changes

### `src/components/DashboardSidebar.tsx`
- Remove the `if (collapsed)` block that renders all individual items (lines 170-188)
- In the multi-item group section, when collapsed, render a single button with the **group icon** and a tooltip showing the group label
- For single-item groups, keep current behavior (already shows one icon)
- On click: if the active tab is already within that group, keep it; otherwise navigate to the first item

This reduces the collapsed sidebar from ~20 icons down to 7 group icons: Operations, Incidents, Intelligence, Topology, Detection Engine, Configuration, Notifications.

