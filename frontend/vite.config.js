import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Explicit SPA mode: unmatched HTML navigations fall back to index.html.
  appType: 'spa',
  server: {
    // Listen on IPv4 + IPv6. Binding only to ::1 makes http://127.0.0.1:3000
    // (and many port-forward/preview tools) fail to connect.
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      }
    }
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    strictPort: true,
  }
})
