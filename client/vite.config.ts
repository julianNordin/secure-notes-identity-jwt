import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    // Pinned, and strict on purpose. The API's CORS policy names this exact
    // origin, so Vite quietly falling back to 5174 when the port is busy would
    // not look like a port problem - it would look like every request suddenly
    // being blocked by the browser for no reason.
    port: 5173,
    strictPort: true,
  },
})
