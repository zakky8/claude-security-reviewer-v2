
from fastapi import FastAPI, Request, File, UploadFile, Form # type: ignore
from fastapi.responses import HTMLResponse, JSONResponse # type: ignore
from fastapi.staticfiles import StaticFiles # type: ignore
from fastapi.templating import Jinja2Templates # type: ignore
import os
import tempfile
import shutil
import asyncio
import zipfile
import subprocess
from pathlib import Path
from pydantic import BaseModel # type: ignore
from typing import Optional, List

# Import our scanner logic
from claudecode.github_action_audit import ( # type: ignore
    initialize_clients,
    get_llm_client,
    LLMClientRunner,
    get_security_audit_prompt,
    parse_json_with_fallbacks
)
from claudecode import claude_api_client # type: ignore
from api.static_analysis import run_static_analysis

app = FastAPI()

# Mount static files
# Mount static files
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Ensure directories exist
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

class ScanRequest(BaseModel):
    code_content: Optional[str] = None
    file_name: str = "snippet.py"
    provider: str = "openai"
    api_key: str
    model: str = "gpt-4o"
    scan_type: str = "security" # security or review
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
    scan_type: str = Form("security"),
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

            candidates = []
            source_errors = []

            # 1. Collect from Uploaded Files
            if has_files:
                for file in files:
                    if not file.filename: continue
                    if Path(file.filename).suffix.lower() in VALID_EXTS:
                         content_bytes = await file.read()
                         c = content_bytes.decode('utf-8', errors='ignore')
                         if c.strip(): candidates.append({"name": file.filename, "content": c})

            # 2. Collect from GitHub
            if github_url:
                extract_path = temp_path / "extracted"
                os.makedirs(extract_path, exist_ok=True)
                
                # Clean GitHub URL (handle tree/blob links)
                clean_url = github_url.strip().rstrip('/')
                if 'github.com' in clean_url:
                    parts = clean_url.split('/')
                    # parts might be ['https:', '', 'github.com', 'owner', 'repo', ...]
                    if len(parts) < 5:
                         return JSONResponse(status_code=400, content={"error": f"Invalid GitHub URL: '{github_url}'. Please provide a specific repository, not just an organization. Example: 'https://github.com/anthropics/anthropic-sdk-python'"})
                    
                    if 'tree' in parts or 'blob' in parts:
                        clean_url = f"{parts[0]}//{parts[2]}/{parts[3]}/{parts[4]}"
                    else:
                        clean_url = f"{parts[0]}//{parts[2]}/{parts[3]}/{parts[4]}"
                
                print(f"DEBUG: Attempting to clone {clean_url} into {extract_path}")
                try:
                    subprocess.run(["git", "clone", "--depth", "1", clean_url, str(extract_path)], 
                                   check=True, timeout=60, capture_output=True)
                    
                    for root, dirs, fs in os.walk(extract_path):
                        valid_dirs = [d for d in dirs if not d.startswith('.') and d not in ['test', 'tests', 'node_modules', 'venv', 'env', '__pycache__', '.git', 'docs', 'assets']]
                        dirs.clear(); dirs.extend(valid_dirs)
                        for f in fs:
                            p = Path(root) / f
                            if p.suffix.lower() in VALID_EXTS:
                                try:
                                    rel_path = p.relative_to(extract_path)
                                    with open(p, 'r', encoding='utf-8', errors='ignore') as code_file:
                                        c = code_file.read()
                                        if c.strip(): candidates.append({"name": str(rel_path), "content": c})
                                except Exception: continue
                except Exception as e:
                    source_errors.append(f"GitHub Clone Failed: {str(e)}")

            # 3. Collect from Paste
            if code_content and code_content.strip():
                candidates.append({"name": file_name or "snippet.py", "content": code_content})

            if not candidates:
                error_msg = "No valid source code found."
                if source_errors:
                    error_msg += " " + ". ".join(source_errors)
                return JSONResponse(status_code=400, content={"error": error_msg})

            # RUN STATIC ANALYSIS
            static_findings = []
            for cand in candidates:
                static_findings.extend(run_static_analysis(cand['name'], cand['content']))

            # PRIORITIZE & PACK
            def get_score(f):
                n = f['name'].lower()
                score = 1
                if any(x in n for x in ['auth', 'login', 'security', 'password', 'secret', 'key', 'token']): score += 20
                if any(x in n for x in ['api', 'route', 'controller', 'handler', 'server', 'db', 'database', 'query']): score += 15
                if any(x in n for x in ['main', 'app', 'config', 'settings', 'env']): score += 10
                if Path(n).suffix in CORE_EXTS: score += 5
                return score

            candidates.sort(key=get_score, reverse=True)
            
            # DYNAMIC PACKING
            model_lower = model.lower()
            is_large_model = any(x in model_lower for x in ['claude', 'gpt-4', 'o1'])
            packing_limit = 200000 if is_large_model else 15000
            item_limit = 15000 if is_large_model else 5000
            
            aggregated: List[str] = []
            bytes_accumulated: int = 0
            
            for cand in candidates:
                raw_text = str(cand['content'])
                limit_int = int(item_limit)
                content = raw_text if len(raw_text) <= limit_int else raw_text[:limit_int] + "\n... [TRUNCATED]" # type: ignore
                entry = f"File: {cand['name']}\n```\n{content}\n```\n"
                entry_len = len(entry)
                if (int(bytes_accumulated) + entry_len) > int(packing_limit): # type: ignore
                    break
                aggregated.append(entry)
                bytes_accumulated = int(bytes_accumulated) + entry_len # type: ignore

            context = "\n".join(aggregated)
            scan_type_str = scan_type # Use the Form variable
            
            if scan_type_str == "review":
                prompt = f"""You are a senior softare engineer performing a code review.
Review these {len(aggregated)} files for bugs, style, and best practices.
Files:
{context}
Return ONLY a JSON object with "findings" and "analysis_summary" keys."""
            else:
                prompt = f"""You are a senior security engineer. Analyze these {len(aggregated)} files for security vulnerabilities.
Files:
{context}
Return ONLY a JSON object with "findings" and "analysis_summary" keys."""

            safe_max_tokens = 4096 if is_large_model else 1024

            # EXECUTE LLM
            client = get_llm_client(provider='openai' if provider=='openrouter' else provider, 
                                    api_key=api_key, model=model, api_base=api_base)
            success, error, results = LLMClientRunner(client).run_security_audit(temp_path, prompt, max_tokens=safe_max_tokens)
            
            if not success:
                # Fallback to static results
                files_count = len(aggregated)
                return {
                    "findings": static_findings,
                    "analysis_summary": {
                        "files_reviewed": files_count,
                        "high_severity": sum(1 for f in static_findings if f['severity'] in ['CRITICAL', 'HIGH']),
                        "medium_severity": sum(1 for f in static_findings if f['severity'] == 'MEDIUM'),
                        "low_severity": sum(1 for f in static_findings if f['severity'] == 'LOW'),
                    },
                    "error": f"LLM Analysis Failed: {error}. Showing Static Analysis results only."
                }
            
            # MERGE RESULTS
            results["findings"] = static_findings + results.get("findings", [])
            # Also include any source errors as metadata
            if source_errors:
                results["error"] = "Note: Some sources failed to load. " + ". ".join(source_errors)
            
            return results

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn # type: ignore
    
    BANNER = """
    \033[36m██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
    ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
    ██║     ██║     ███████║██║   ██║██║  ██║█████╗  
    ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  
    ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗
     ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝\033[0m
    \033[35mSECURITY REVIEWER v3.0\033[0m | \033[32mHybrid Analysis Engine\033[0m
    --------------------------------------------------
    \033[33m⚡ Initializing Multi-Agent Context...
    🚀 System Ready: http://localhost:8089\033[0m
    --------------------------------------------------
    """
    print(BANNER)
    uvicorn.run(app, host="0.0.0.0", port=8089, log_level="info")
