import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
    plugins: [react()],
    server: {
        proxy: {
            '/login': 'http://localhost:8080',
            '/refresh': 'http://localhost:8080',
            '/logout': 'http://localhost:8080',
            '/me': 'http://localhost:8080',
        },
    },
})