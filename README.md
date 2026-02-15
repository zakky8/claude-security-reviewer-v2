# 🛡️ CLAUDE SECURITY REVIEWER v3.0
> **Enterprise-Grade AI-Powered Security Guard**

A lightweight and powerful **Hybrid Security Analysis System** that extends **Claude Code** for professional-grade repository protection. Audit your code for vulnerabilities with the speed of static analysis and the depth of an agentic AI expert.

![Terminal Demo](assets/terminal_demo.svg)

---

## 💡 Why I Built This

> "I'm a solo developer. I move fast, I 'vibecode,' and I trust AI to write my logic. But I also know that one simple mistake — an unescaped `eval` or a leaked API key — can ruin everything."

Standard security tools are built for 500-person enterprise companies. They are slow, full of false positives, and frankly, boring to use. I wanted something that felt like **Claude Code**: fast, smart, and designed for the creative developer who just wants to "Get Shit Done" without getting hacked.

So I built this. A system that doesn't just look for generic patterns, but actually *understands* the context of your code using agentic reasoning.
— **ZAKKY8**

---

## 🚀 Getting Started

### 1. Prerequisites
This tool is built on **Claude Code**. You must have it installed:
- **Windows**: `irm https://claude.ai/install.ps1 | iex`
- **MacOS/Linux**: `curl -fsSL https://claude.ai/install.sh | bash`

### 2. Installation & Run

#### The "Get Shit Done" One-Liner (NO CLONE REQUIRED)
You can run this tool directly from GitHub without even cloning it:
```powershell
npx github:zakky8/claude-code-security-reviewer-v2
```

---

#### Other Options

**From Inside Project Folder**
If you have already cloned the repo:
```powershell
npx get-shit-done-cc
```

**Local Script (Offline)**
```powershell
.\install.ps1
```
If you already have this repository cloned, just run the installer directly:
```powershell
.\install.ps1
```

**Fresh Setup (For new machines)**
Clone the repository first, then run the installer:
```powershell
git clone https://github.com/zakky8/claude-code-security-reviewer-v2.git
cd claude-code-security-reviewer-v2
.\install.ps1
```


**Verify with:**
Open your browser to [http://localhost:8089](http://localhost:8089)

---

## 🛠️ How It Works

1.  **Initialize**: Select your provider (Claude, OpenAI, or DeepSeek) and enter your API key.
2.  **Multi-Source Feed**: Paste a snippet, upload a whole folder, or drop a GitHub link. The system consumes them all simultaneously.
3.  **Hybrid Scan**: The engine runs two layers of defense:
    *   **Tier 1: Static Layer**: Instant regex-based detection of dangerous hooks (RCE, Injection).
    *   **Tier 2: AI Layer**: Deep semantic reasoning to find logical flaws and architectural risks using **Claude 3.5 Sonnet**.
4.  **Results & Remediation**: Get a prioritized list of findings with severity ratings and specific recommendations on how to fix them.

---

## 🔥 v3.0 Enterprise Features

- **Hybrid Intelligence**: Combining fixed security rules with LLM reasoning for **Zero False Negatives**.
- **Modern Terminal (NEW)**: A premium CLI experience with splash screens, status indicators, and beautiful findings tables. 
- **GitHub Action Integration**: Automatically audit every Pull Request.
- **Circuit-Breaker Resilience**: Gracefully degrades to **Static-Only Scan** if API limits are hit.
- **Privacy First**: Local processing in isolated directories. No code is stored.

---

## 💻 Usage Modes

### 🌐 Web Dashboard
Access the full visual experience at `http://localhost:8089`.

### 📟 CLI (Modern Terminal)
Run the audit directly from your terminal:
```powershell
python claudecode/github_action_audit.py
```
*Note: Detection is automatic. In interactive terminals, it shows the styled experience; in CI, it outputs structured JSON.*

### 🧪 SAST Evaluator
Evaluate specific PRs for accuracy:
```powershell
python -m claudecode.evals.run_eval owner/repo#123 --verbose
```

---

## 🤖 GitHub Action Integration
Add this tool to your CI pipeline:
```yaml
- name: Claude Security Review
  uses: zakky8/claude-code-security-review-v2@v3
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 🛡️ Security & Privacy
*   **Isolated Processing**: Files are processed in temporary worktrees and wiped immediately.
*   **No Data Retention**: Your code is sent only to your chosen providers for analysis. We do not store or train on your data.

---

## 👥 Community
Join the conversation and get support:
- **[Claude Developers Discord](https://anthropic.com/discord)**

---
**Build cool things. Stay secure.** 🚀
