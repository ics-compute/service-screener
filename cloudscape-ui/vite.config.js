import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  base: './',
  build: {
    outDir: 'dist',
    assetsInlineLimit: 100000000,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true
      }
    }
  },
  test: {
    // Components render through Cloudscape, which needs a DOM.
    environment: 'jsdom',
    globals: true,
    include: ['src/**/*.{test,spec}.{js,jsx}']
  }
})
