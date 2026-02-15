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

### 1. Ready to "Get Shit Done"? (NO CLONE REQUIRED)
Run this from any terminal on any machine:
```powershell
npx github:zakky8/claude-security-reviewer-v2
```

**Verify arrival:**
Open your browser to [http://localhost:8089](http://localhost:8089)

### 2. Local Installation & Uninstalling
If you cloned the repo or ran `install.bat`:

**To usage:**
```powershell
venv\Scripts\activate
python server.py
```

**To uninstall (cleanup venv & cache):**
```powershell
# Windows
.\uninstall.bat

# Mac/Linux
./uninstall.sh
```

---

## 🛠️ How It Works

1.  **Initialize**: Select your provider (Claude, OpenAI, or DeepSeek) and enter your API key.
2.  **Multi-Source Feed**: Paste a snippet, upload a whole folder, or drop a GitHub link. The system consumes them all simultaneously.
3.  **Hybrid Scan**: The engine runs two layers of defense:
    *   **Tier 1: Static Layer**: Instant regex-based detection of dangerous hooks (RCE, Injection).
    *   **Tier 2: AI Layer**: Deep semantic reasoning to find logical flaws and architectural risks using **Claude 3.5 Sonnet**.
4.  **Results & Remediation**: Get a prioritized list of findings with severity ratings and specific recommendations on how to fix them.

---

## 🔥 Features
- **Hybrid Intelligence**: Combining fixed security rules with LLM reasoning.
- **Modern Terminal**: Premium CLI with beautiful findings tables. 
- **GitHub Action**: Audit every Pull Request automatically.

---

## 🤖 GitHub Action
```yaml
- name: Claude Security Review
  uses: zakky8/claude-security-reviewer-v2@v3
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## 🛡️ Security & Privacy
- **Isolated Processing**: Files are processed in temporary folders and wiped.
- **No Data Retention**: Your code is never stored or used for training.

---

## 👥 Community
Join the conversation and get support:
- **[Claude Developers Discord](https://anthropic.com/discord)**

---
**Build cool things. Stay secure.** 🚀
