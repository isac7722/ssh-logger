import { defineConfig } from '@playwright/test'
export default defineConfig({testDir:'.',testMatch:'*.spec.ts',workers:1,use:{baseURL:process.env.TEST_URL||'http://localhost:18080',headless:true},reporter:'list',outputDir:'/tmp/sshlogger-browser-results'})
