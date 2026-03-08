import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './index.css'
import { registerSW } from 'virtual:pwa-register'

// Register service worker
const updateSW = registerSW({
  onNeedRefresh() {
    if (confirm('New version available! Click OK to update.')) {
      updateSW(true);
    }
  },
  onOfflineReady() {
    console.log('App ready to work offline');
  },
});

// Monitor online/offline status
window.addEventListener('online', () => {
  console.log('App is back online');
});

window.addEventListener('offline', () => {
  console.log('App is offline - working with cached data');
});

createRoot(document.getElementById("root")!).render(<App />);
