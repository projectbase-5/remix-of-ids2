# Welcome to your Lovable project

## Project info

**URL**: https://lovable.dev/projects/03fce7e1-2ac0-4ece-9dfe-c27597a1fdd6

## How can I edit this code?

There are several ways of editing your application.

**Use Lovable**

Simply visit the [Lovable Project](https://lovable.dev/projects/03fce7e1-2ac0-4ece-9dfe-c27597a1fdd6) and start prompting.

Changes made via Lovable will be committed automatically to this repo.

**Use your preferred IDE**

If you want to work locally using your own IDE, you can clone this repo and push changes. Pushed changes will also be reflected in Lovable.

The only requirement is having Node.js & npm installed - [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating)

Follow these steps:

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## How can I deploy this project?

Simply open [Lovable](https://lovable.dev/projects/03fce7e1-2ac0-4ece-9dfe-c27597a1fdd6) and click on Share -> Publish.

## Can I connect a custom domain to my Lovable project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://docs.lovable.dev/tips-tricks/custom-domain#step-by-step-guide)

## PWA (Progressive Web App) Features

This project is configured as a Progressive Web App (PWA), which means:

✅ **Installable** - Can be installed on mobile devices and desktops  
✅ **Offline Support** - Works offline with cached data  
✅ **Fast Loading** - Assets are precached for instant loading  
✅ **App-like Experience** - Runs in standalone mode without browser UI

### Local Development with PWA

When running locally in VS Code or any IDE:

```sh
# Start development server (PWA disabled for hot-reload)
npm run dev

# App runs on: http://localhost:8080
```

The development server runs on **port 8080** as configured in `vite.config.ts`. Service worker is disabled during development to prevent caching issues.

### Testing PWA Features Locally

To test PWA features (install prompt, offline mode, etc.):

```sh
# Build production version
npm run build

# Preview production build with PWA enabled
npm run preview

# Access at: http://localhost:4173
```

### Install on Mobile Devices

**Access from your phone/tablet:**
1. Find your computer's local IP address:
   - Windows: `ipconfig`
   - Mac/Linux: `ifconfig` or `ip addr`
2. On your mobile device (connected to same WiFi), visit:
   - `http://YOUR_LOCAL_IP:8080` (dev server)
   - `http://YOUR_LOCAL_IP:4173` (preview server)

**Install on Android:**
- Chrome will show an "Install" prompt
- Or tap the menu and select "Install app"

**Install on iOS:**
- Tap the Share button in Safari
- Scroll down and tap "Add to Home Screen"
- Tap "Add" in the top right

### Install on Desktop

**Chrome/Edge:**
- Click the install icon (⊕) in the address bar
- Or click the menu → "Install IDS Dashboard"

**The app will:**
- Appear in your app drawer/start menu
- Run in a standalone window
- Work offline with cached data
- Update automatically in the background

## Real-Time Intrusion Detection System

### How It Works

A Python agent (`docs/ids_agent.py`) captures live network packets using **scapy** and feeds them through two detection modules in real time:

- **Port Scan Detector** — flags a source IP that contacts 15+ unique destination ports within a 10-second sliding window.
- **DoS / DDoS Detector** — flags a source IP sending 100+ packets per second, or an overall traffic spike exceeding 3× the rolling baseline.

Detected alerts are deduplicated locally (same type + source within 60 seconds) and POSTed to a Supabase edge function.

### Detection Pipeline

```
Packet captured (scapy)
  → PortScanDetector + DoSDetector + FlowAggregator
  → Every 2 s: check() → alerts[] → AlertManager deduplicates
  → POST to ingest-traffic edge function
  → Edge function inserts into live_alerts (with server-side dedupe)
  → Frontend polls live_alerts every 2 s → toast notification
```

The edge function also runs **server-side backup detection** on each batch (10+ unique ports = port scan, 50+ packets = DoS) as a safety net.

### Alert Flow

When a high-severity alert is inserted into `live_alerts`, the React dashboard picks it up within 2–4 seconds and shows a destructive toast notification with the attack type and source IP.

### Running the Agent

```sh
# 1. Install dependencies
pip install scapy psutil requests

# 2. Set your API key in docs/ids_agent.py
#    AGENT_API_KEY = "your-secret-key"
#    (must match the AGENT_API_KEY secret in your Supabase project)

# 3. Run (requires root for raw socket capture)
sudo python docs/ids_agent.py
```

### Testing

Simulate attacks to verify the pipeline end-to-end:

```sh
# Port scan (requires nmap)
nmap -sS -p 1-100 <TARGET_IP>

# SYN flood / DoS (requires hping3)
sudo hping3 -S --flood -p 80 <TARGET_IP>
```

Alerts should appear in the dashboard within seconds.
