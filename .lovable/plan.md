

## Plan: Default to Live Mode

**Change**: In `src/hooks/useIDSDataStore.ts` line 86, change `useState(true)` to `useState(false)` so the app starts in Live Mode by default. Users can still toggle Demo Mode on via the switch.

**Single line change** — no other files affected since the toggle UI already supports both states.

