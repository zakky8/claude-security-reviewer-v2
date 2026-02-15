#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');

console.log('\n\x1b[36m\x1b[1m┌─────────────────────────────────────────────────────────┐');
console.log('│                                                         │');
console.log('│   🛡️  \x1b[37mGET SHIT DONE - SECURITY v3.0\x1b[36m                     │');
console.log('│   \x1b[90mAgentic Security for Claude Code\x1b[36m                      │');
console.log('│                                                         │');
console.log('└─────────────────────────────────────────────────────────┘\x1b[0m\n');

const serverPath = path.join(__dirname, '..', 'server.py');
const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

const python = spawn(pythonCmd, [serverPath], {
    stdio: 'inherit',
    shell: true
});

python.on('error', (err) => {
    console.error('\x1b[91m❌ Failed to start server:\x1b[0m', err.message);
    console.log('Ensure Python is installed and added to your PATH.');
});

python.on('exit', (code) => {
    if (code !== 0) {
        console.log(`\x1b[90mServer exited with code ${code}\x1b[0m`);
    }
});
