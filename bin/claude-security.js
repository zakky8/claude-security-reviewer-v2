#!/usr/bin/env node
console.log('--- JS ENTRY POINT STARTED ---');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

console.log('\n\x1b[36m\x1b[1m┌─────────────────────────────────────────────────────────┐');
console.log('│                                                         │');
console.log('│   🛡️  \x1b[37mGET SHIT DONE - SECURITY v3.0\x1b[36m                     │');
console.log('│   \x1b[90mAgentic Security for Claude Code\x1b[36m                      │');
console.log('│                                                         │');
console.log('└─────────────────────────────────────────────────────────┘\x1b[0m\n');

const serverPath = path.join(__dirname, '..', 'server.py');

// Handle Uninstall Command
if (process.argv.includes('uninstall')) {
    console.log('🗑️  Initiating uninstallation...');
    const uninstallScript = process.platform === 'win32' ? 'uninstall.bat' : './uninstall.sh';
    const uninstallPath = path.join(__dirname, '..', uninstallScript);

    const child = spawn(uninstallPath, [], {
        stdio: 'inherit',
        shell: true,
        cwd: process.cwd()
    });

    child.on('exit', (code) => {
        process.exit(code);
    });
    return;
}

// Debug: Verify file exists
if (!fs.existsSync(serverPath)) {
    console.error('\x1b[91m❌ Error: server.py not found at:\x1b[0m', serverPath);
    process.exit(1);
}

const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

console.log(`\x1b[90mStarting Python server via: ${pythonCmd}...\x1b[0m`);

const python = spawn(pythonCmd, [serverPath], {
    stdio: 'inherit'
});

python.on('error', (err) => {
    console.error('\x1b[91m❌ Failed to start server:\x1b[0m', err.message);
    console.log('Ensure Python is installed and added to your PATH.');
});

python.on('exit', (code) => {
    if (code !== 0 && code !== null) {
        console.log(`\x1b[90mServer exited with code ${code}\x1b[0m`);
    }
});
