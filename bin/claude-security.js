#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Starting Claude Security Reviewer v3.0...');

const serverPath = path.join(__dirname, '..', 'server.py');
const python = spawn('python', [serverPath], {
    stdio: 'inherit',
    shell: true
});

python.on('error', (err) => {
    console.error('❌ Failed to start server:', err.message);
    console.log('Ensure Python is installed and added to your PATH.');
});

python.on('exit', (code) => {
    console.log(`Server exited with code ${code}`);
});
