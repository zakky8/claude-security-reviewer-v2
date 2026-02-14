
from fastapi import FastAPI, Request, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import tempfile
import shutil
import asyncio
import zipfile
import subprocess
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, List

# Import our scanner logic
from claudecode.github_action_audit import (
    initialize_clients,
    get_llm_client,
    LLMClientRunner,
    get_security_audit_prompt,
    parse_json_with_fallbacks
)
from claudecode import claude_api_client

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

class ScanRequest(BaseModel):
    code_content: Optional[str] = None
    file_name: str = "snippet.py"
    provider: str = "openai"
    api_key: str
    model: str = "gpt-4o"
    api_base: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan")
async def scan_code(
    request: Request,
    files: List[UploadFile] = File(default=None),
    code_content: Optional[str] = Form(None),
    github_url: Optional[str] = Form(None),
    file_name: str = Form("snippet.py"),
    provider: str = Form("openai"),
    api_key: str = Form(...),
    model: str = Form("gpt-4o"),
    api_base: Optional[str] = Form(None)
):
    print(f"DEBUG: Request - Files: {len(files) if files else 0}, Code: {bool(code_content)}, GitHub: {github_url}")
    
    try:
        # Determine content source
        has_files = files and len(files) > 0 and files[0].filename
        
        if not has_files and not code_content and not github_url:
             return JSONResponse(status_code=400, content={"error": "No content provided (Upload files, Paste code, or GitHub URL)"})

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            prompt = ""
            
            # Define core logic extensions
            CORE_EXTS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.c', '.cpp', '.h', '.rs', '.php', '.rb', '.cs', '.sh'}
            DATA_EXTS = {'.json', '.yaml', '.yml', '.toml', '.env', '.dockerfile', '.sql'}
            VALID_EXTS = CORE_EXTS.union(DATA_EXTS)

            if has_files or github_url:
                candidates = []
                extract_path = temp_path / "extracted"
                os.makedirs(extract_path, exist_ok=True)

                if github_url:
                    # Clean GitHub URL (handle tree/blob links)
                    if 'github.com' in github_url:
                        parts = github_url.split('/')
                        if 'tree' in parts or 'blob' in parts:
                             github_url = "/".join(parts[:5])
                    
                    print(f"DEBUG: Cloning {github_url} into {extract_path}")
                    try:
                        subprocess.run(["git", "clone", "--depth", "1", github_url, str(extract_path)], 
                                       check=True, timeout=60, capture_output=True)
                    except Exception as e:
                        return JSONResponse(status_code=400, content={"error": f"Git clone failed: {str(e)}"})
                    
                elif len(files) == 1 and files[0].filename.endswith('.zip'):
                    content_bytes = await files[0].read()
                    zip_path = temp_path / "upload.zip"
                    with open(zip_path, "wb") as f: f.write(content_bytes)
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref: zip_ref.extractall(extract_path)
                
                # TRAVERSAL
                if github_url or (len(files) == 1 and files[0].filename.endswith('.zip')):
                    for root, dirs, fs in os.walk(extract_path):
                        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['test', 'tests', 'node_modules', 'venv', 'env', '__pycache__', '.git', 'docs', 'assets']]
                        for f in fs:
                            p = Path(root) / f
                            if p.suffix.lower() in VALID_EXTS:
                                try:
                                    rel_path = p.relative_to(extract_path)
                                    with open(p, 'r', encoding='utf-8', errors='ignore') as code_file:
                                        c = code_file.read()
                                        if c.strip(): candidates.append({"name": str(rel_path), "content": c})
                                except Exception: continue
                else:
                    for file in files:
                        if not file.filename: continue
                        if Path(file.filename).suffix.lower() in VALID_EXTS:
                             content_bytes = await file.read()
                             c = content_bytes.decode('utf-8', errors='ignore')
                             if c.strip(): candidates.append({"name": file.filename, "content": c})

                # PRIORITIZE
                def get_score(f):
                    n = f['name'].lower()
                    score = 1
                    if any(x in n for x in ['auth', 'login', 'security', 'password', 'secret', 'key', 'token']): score += 20
                    if any(x in n for x in ['api', 'route', 'controller', 'handler', 'server', 'db', 'database', 'query']): score += 15
                    if any(x in n for x in ['main', 'app', 'config', 'settings', 'env']): score += 10
                    if Path(n).suffix in CORE_EXTS: score += 5
                    return score

                candidates.sort(key=get_score, reverse=True)
                print(f"DEBUG: Found {len(candidates)} files. Top file: {candidates[0]['name'] if candidates else 'NONE'}")

                # DYNAMIC PACKING & RESPONSE LIMITS
                model_lower = model.lower()
                is_large_model = any(x in model_lower for x in ['claude', 'gpt-4', 'o1'])
                limit = 200000 if is_large_model else 15000
                safe_max_tokens = 4096 if is_large_model else 1024
                
                aggregated = []
                curr_size = 0
                for cand in candidates:
                    # Truncate overly large files to ensure we get at least part of them
                    content = cand['content']
                    if len(content) > (15000 if is_large_model else 5000): 
                        content = content[:(15000 if is_large_model else 5000)] + "\n... [TRUNCATED]"
                    
                    entry = f"File: {cand['name']}\n```\n{content}\n```\n"
                    if curr_size + len(entry) > limit: break
                    aggregated.append(entry)
                    curr_size += len(entry)

                if not aggregated:
                    return JSONResponse(status_code=400, content={"error": "No valid source code found."})
            
                context = "\n".join(aggregated)
                prompt = f"""You are a senior security engineer. Analyze these {len(aggregated)} files for security vulnerabilities.
Focus on: SQLi, XSS, Auth Bypass, RCE, and Secrets.

Files:
{context}

Return ONLY a JSON object:
{{
  "findings": [
    {{
      "title": "Title",
      "severity": "HIGH|MEDIUM|LOW",
      "description": "...",
      "file": "path",
      "line": 1,
      "exploit_scenario": "...",
      "recommendation": "..."
    }}
  ],
  "analysis_summary": {{ "files_reviewed": {len(aggregated)}, "high_severity": 0, "medium_severity": 0, "low_severity": 0 }}
}}
"""
            else:
                prompt = f"""Analyze this code ({file_name}) for security vulnerabilities.
Code:
```
{code_content}
```
Return JSON matching the schema previously described.
"""
                safe_max_tokens = 4096 if any(x in model.lower() for x in ['claude', 'gpt-4', 'o1']) else 1024

            # EXECUTE
            client = get_llm_client(provider='openai' if provider=='openrouter' else provider, 
                                    api_key=api_key, model=model, api_base=api_base)
            success, error, results = LLMClientRunner(client).run_security_audit(temp_path, prompt, max_tokens=safe_max_tokens)
            
            if not success: return JSONResponse(status_code=500, content={"error": f"Audit Failed: {error}"})
            return results

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
