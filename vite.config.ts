import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  server: {
    // Honour PORT so a supervising tool can place the dev server on a free
    // port instead of Vite silently picking the next one up.
    port: Number(process.env.PORT) || 5174,
  },
  build: {
    // ag-grid is ~1.1MB raw and there is nothing to be done about that. It is
    // behind the lazy boundary, so it never sits on the critical path — and a
    // build that always prints a warning is a build whose output stops being
    // read. The number to watch instead is the eager entry chunk, ~320kB.
    chunkSizeWarningLimit: 1200,
    // ag-grid alone is ~325kB gzipped and none of it is needed to paint the
    // upload screen, so the dashboard is behind a lazy boundary (see App.tsx)
    // and these two get their own chunks on top of that.
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: 'ag-grid', test: /node_modules[\\/]ag-grid/ },
            { name: 'charts', test: /node_modules[\\/](recharts|d3-|victory-|decimal\.js)/ },
          ],
        },
      },
    },
  },
})
