# 🕵️ Claude Code Security Reviewer v2.0

**Claude Code Security Reviewer** is an elite, AI-powered security analysis engine that transforms Claude into a **Senior Security Engineer**. Designed for developers, security teams, and **Autonomous AI Agents**, it identifies critical vulnerabilities in your codebase before they reach production.

Powered by **Claude 3.5 Sonnet**, it audits local code, ZIP uploads, and entire **GitHub Repositories** with high precision, providing detailed findings that include real-world **Exploit Scenarios** and **Confidence Scores**.

---

## 🌟 Key Updates in v2.0

- **🚀 Direct GitHub Scanning**: Paste any GitHub URL (or sub-links like `/tree/` or `/blob/`) to perform a comprehensive repo-wide security audit.
- **🧠 Smart Context Prioritization**: Intelligent scoring system that identifies and prioritizes security-critical files (`auth`, `api`, `config`, `crypto`) to ensure the most vulnerable logic is always analyzed first.
- **📊 Advanced Finding Schema**: Reports now include **Confidence Scores**, **Exploit Scenarios** (how an attacker would use the flaw), and structured **Categories**.
- **⚡ Dynamic Context Packing**: 
  - **Power Users**: Up to **200,000 characters** per scan for Claude 3.5 Sonnet / GPT-4o.
  - **Safe Mode**: Automatic fallback for smaller models (Nemotron/Llama) with individual file truncation to prevent "Context Window" errors.

---

## 🖥️ Local Web Interface

Experience a premium, dark-themed security dashboard with glassmorphism aesthetics.

### Quick Start (Web)
1. **Install Dependencies**:
   ```bash
   pip install fastapi uvicorn jinja2 python-multipart openai anthropic
   ```
2. **Launch Server**:
   ```bash
   python server.py
   ```
3. **Audit**: Open `http://localhost:8000`. Choose your provider (Anthropic, OpenAI, or OpenRouter), paste a GitHub link, or upload your ZIP/folders.

### Features
- **Real-time Progress**: Visual loader and status indicators.
- **Vulnerability Cards**: Detailed breakdown with exploit scenarios and code context.
- **Risk Summary**: High/Medium/Low dashboard overview.
- **Responsive Design**: Audits from your phone or desktop.

---

## 🛡️ Security Analysis Methodology

The tool uses a multi-phased analysis approach inspired by professional penetration testing:

1. **Contextual Research**: Analyzes the structural architecture of the code.
2. **Vulnerability Assessment**: Cross-references code against common attack vectors (OWASP Top 10).
3. **Exploit Verification**: Simulates how an attacker might leverage the vulnerability to ensure findings are actionable and high-confidence.

### Coverage
- **Injection**: SQLi, NoSQLi, Command Injection, SSRF.
- **Auth & Authz**: Broken Access Control, JWT flaws, Session fixation.
- **Crypto**: Weak algorithms, hardcoded secrets, insecure entropy.
- **Business Logic**: Input validation bypasses, race conditions.

---

## 🐙 GitHub Action Integration

Seamlessly integrate security reviews into your CI/CD pipeline.

### Use it in your PRs
Add this to `.github/workflows/security.yml`:

```yaml
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-username/claude-security-v2@main
        with:
          api-provider: 'anthropic' # or 'openai', 'openrouter'
          api-key: ${{ secrets.CLAUDE_API_KEY }}
          model-name: 'claude-3-5-sonnet-20241022'
```

---

---

### ⚡ One-Click Installation (For Users & Agents)
Use these commands to fully automate the setup. **AI Agents** can run these to "equip" themselves with the security analysis subsystem in seconds.

**Linux / macOS / WSL / Cloud Agents**:
```bash
curl -sSL https://raw.githubusercontent.com/your-username/repo/main/install.sh | bash
```

**Windows / Local Agents**:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-username/repo/main/install.bat" -OutFile "install.bat"; .\install.bat
```

---

## 🛠️ Installation & Platform Support

This tool can be installed and run anywhere Python is available. Use the guide below for your specific environment.

### 1. Base Installation (Required for All)
First, get the code and dependencies onto your system:
```bash
# Get the code
git clone https://github.com/your-username/claude-security-v2.git
cd claude-security-v2

# Install Core & Web dependencies
pip install -r claudecode/requirements.txt
```

---

### 2. Choose Your Mode
Once installed, choose how you want to use the tool:

| Platform / Mode | How to Run / Install |
|:--- |:--- |
| **Local Web UI** | Run `python server.py` and open `localhost:8000` |
| **Autonomous Agent** | Point your agent to `claudecode/github_action_audit.py` or use the API |
| **Docker / Cloud** | Use `docker-compose up -d` (Includes auto-restarts) |
| **GitHub Actions** | Add the repository to your `.github/workflows/security.yml` |
| **VPS (Ubuntu/etc)** | Use `pm2 start server.py` to keep it running 24/7 |

---

### 3. API & Agentic Setup (OpenClaw / Antigravity)
Agents can either import the logic directly or talk to the local API.

**To run as an Agentic Tool:**
1. Start the subsystem: `python server.py &`
2. Configure your agent to call `POST http://localhost:8000/api/scan` with the code/URL.
3. The agent receives structured JSON to auto-fix vulnerabilities.

---

### 5. Docker Deployment (Cloud & VPS)
Recommended for **DigitalOcean, AWS, or Heroku**:

1. **Build the Image**:
   ```bash
   docker build -t claude-security .
   ```

2. **Run with Docker Compose**:
   ```bash
   docker-compose up -d
   ```
   *The app will automatically restart if the server reboots.*

---

### 6. VPS Deployment (Direct)
If you are using a Linux VPS (Ubuntu/Debian):

1. **Install PM2** (Process Manager):
   ```bash
   npm install -g pm2
   ```

2. **Start the App**:
   ```bash
   pm2 start server.py --name "security-audit" --interpreter python3
   pm2 save
   pm2 startup
   ```

---

### 7. Cloud Platform One-Click (Railway / Render / Fly.io)
Since this project includes a `Dockerfile`, you can simply:
1. Fork this repository.
2. Connect your repository to **Railway.app** or **Render.com**.
3. It will automatically detect the Dockerfile, build it, and provide a public URL.

---

### 8. Agentic AI & Integration (OpenClaw / AutoGPT / Antigravity)
Autonomous agents can use this tool in two ways depending on their architecture:

#### A. Local API Pattern (Subsystem)
The agent runs the server (`python server.py`) and uses it as a private security API on `localhost:8000`. This is ideal for agents that prefer communicating via HTTP/JSON.

#### B. Direct Python Pattern (No Server)
If the agent is Python-based, it can import the audit logic directly without running any background process:
```python
from claudecode.github_action_audit import LLMClientRunner
from claudecode.claude_api_client import get_llm_client

# Agent initializes the engine
client = get_llm_client(provider='openai', api_key='...', model='gpt-4o')
runner = LLMClientRunner(client)

# Agent runs audit natively
success, error, findings = runner.run_security_audit(Path("./code_to_scan"), prompt)
```

**Cloud Agents**: For agents running in the cloud, use the **Docker** or **One-Click Cloud** methods (Section 5 & 7) to host a remote security endpoint.

---

## ⚙️ Configuration (Web & CLI)

| Feature | Description |
|---------|-------------|
| **Smart Selection** | Automatically ignores `.git`, `node_modules`, `tests`, and `assets` to save context. |
| **Model Fallbacks** | Automatically detects context window limits for 4k, 8k, and 128k+ token models. |
| **File Logic** | Prioritizes `.py, .js, .go, .rs, .java` over documentation and text files. |

---

## 🚀 Hosting your own Dashboard

The web interface (`server.py`) is built with **FastAPI**. You can deploy it as a private security tool for your team:

1. **Self-Host**: Deploy to any VPS or internal server.
2. **OpenRouter Integration**: Use the OpenAI provider type with base URL `https://openrouter.ai/api/v1` to access **Llama 3**, **Grok**, or **DeepSeek**.

---

## 📝 License
MIT License. Created with ❤️ by the Advanced Agentic Coding team.

---
*Note: This tool is designed for security professionals. Always verify findings manually before deployment.*
