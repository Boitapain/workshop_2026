import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/engine": "http://localhost:8080", "/prom": "http://localhost:8080", "/probe": "http://localhost:8080", "/ml": "http://localhost:8080" } },
});
