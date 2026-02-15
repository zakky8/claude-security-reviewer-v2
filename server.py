
from fastapi import FastAPI, Request, File, UploadFile, Form, Depends, HTTPException, status # type: ignore
from fastapi.responses import HTMLResponse, JSONResponse, Response # type: ignore
from fastapi.staticfiles import StaticFiles # type: ignore
from fastapi.middleware.trustedhost import TrustedHostMiddleware # type: ignore
from fastapi.middleware.cors import CORSMiddleware # type: ignore
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates # type: ignore
import os
import tempfile
import shutil
import asyncio
import zipfile
import subprocess
import urllib.parse
import logging
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Claude Security Reviewer", version="2.1.0")

# SECURITY: Only allow access from localhost
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "::1"] + [h for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h]
)

# SECURITY: Configure CORS properly
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8095", "http://127.0.0.1:8095"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# SECURITY: HTTP Bearer authentication
security = HTTPBearer()

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

# ============================================================================
# SECURITY: Authentication & Input Validation
# ============================================================================

def verify_api_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> str:
    """Verify API token from Authorization header.
    
    If API_TOKEN env var is not set, authentication is disabled (local dev mode).
    In production, API_TOKEN must be set.
    """
    api_token = os.environ.get("API_TOKEN")
    
    # Disable auth if not configured (development mode only)
    if not api_token:
        logger.warning("API_TOKEN not set - authentication disabled (development mode)")
        return "dev-mode"
    
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    
    # DEBUG: Log token mismatch (careful not to log full token in production)
    if credentials.credentials != api_token:
        logger.warning(f"Token mismatch. Expected: ...{api_token[-5:]}, Got: ...{credentials.credentials[-5:] if credentials.credentials else 'None'}")
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    return credentials.credentials


def validate_github_url(url: str) -> bool:
    """Validate that URL is a legitimate GitHub repository.
    
    SECURITY: Prevents SSRF and arbitrary git clone attacks.
    """
    if not url or len(url) > 2000:
        return False
    
    try:
        parsed = urllib.parse.urlparse(url.strip())
        
        # Check scheme - only HTTPS or HTTP allowed
        if parsed.scheme not in ('https', 'http'):
            logger.warning(f"Invalid URL scheme: {parsed.scheme}")
            return False
        
        # Check netloc is exactly github.com (no subdomains except github enterprise)
        netloc = parsed.netloc.lower()
        if netloc != 'github.com' and not netloc.endswith('.github.com'):
            logger.warning(f"Invalid netloc: {netloc}")
            return False
        
        # Check path has owner/repo format
        path_parts = [p for p in parsed.path.strip('/').split('/') if p]
        if len(path_parts) < 2:
            logger.warning(f"Invalid GitHub path: {parsed.path}")
            return False
        
        # Validate owner and repo names (alphanumeric, -, _)
        for part in path_parts[:2]: # type: ignore
            if not all(c.isalnum() or c in '-_.' for c in part):
                logger.warning(f"Invalid path component: {part}")
                return False
        
        return True
    except Exception as e:
        logger.warning(f"URL validation error: {e}")
        return False


def validate_filename(filename: str, max_length: int = 255) -> str:
    """Sanitize filename and prevent path traversal attacks.
    
    SECURITY: Prevents directory traversal and null byte injection.
    """
    if not filename or len(filename) > max_length:
        raise ValueError(f"Invalid filename length: {len(filename) if filename else 0}")
    
    # Remove path separators and null bytes
    filename = filename.replace('\x00', '')
    filename = os.path.basename(filename)
    
    # Reject suspicious patterns
    if '..' in filename or filename.startswith('/') or filename.startswith('~'):
        raise ValueError(f"Filename contains dangerous patterns: {filename}")
    
    # Whitelist allowed characters: alphanumeric, dot, dash, underscore
    if not all(c.isalnum() or c in '._-' for c in filename):
        raise ValueError(f"Filename contains invalid characters: {filename}")
    
    return filename


class ScanRequest(BaseModel):
    code_content: Optional[str] = None
    file_name: str = "snippet.py"
    provider: str = "openai"
    api_key: str
    model: str = "gpt-4o"
    scan_type: str = "security"  # security or review
    api_base: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/favicon.ico")
async def favicon():
    return Response(content='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>', media_type="image/svg+xml")

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
    api_base: Optional[str] = Form(None),
    token: str = Depends(verify_api_token)  # SECURITY: Require authentication
):
    """Main security scanning endpoint with input validation and authentication."""
    
    try:
        # SECURITY: Validate input size limits
        MAX_CODE_SIZE = 1_000_000  # 1MB
        MAX_FILES_COUNT = 50
        
        if code_content and len(code_content) > MAX_CODE_SIZE:
            return JSONResponse(status_code=400, content={"error": f"Code content exceeds {MAX_CODE_SIZE} bytes"})
        
        if files and len(files) > MAX_FILES_COUNT:
            return JSONResponse(status_code=400, content={"error": f"Too many files (max {MAX_FILES_COUNT})"})
        
        # SECURITY: Validate GitHub URL before attempting clone
        if github_url:
            if not validate_github_url(github_url):
                logger.warning(f"Invalid GitHub URL provided: {str(github_url)[:100]}") # type: ignore
                return JSONResponse(
                    status_code=400, 
                    content={"error": "Invalid GitHub URL. Must be a valid github.com repository."}
                )
        
        # Determine content source
        has_files = files and len(files) > 0 and files[0].filename
        
        if not has_files and not code_content and not github_url:
            return JSONResponse(status_code=400, content={
                "error": "No content provided (Upload files, Paste code, or GitHub URL)"
            })

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            prompt = ""
            
            # Define core logic extensions
            CORE_EXTS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.c', '.cpp', '.h', '.rs', '.php', '.rb', '.cs', '.sh'}
            DATA_EXTS = {'.json', '.yaml', '.yml', '.toml', '.env', '.dockerfile', '.sql'}
            VALID_EXTS = CORE_EXTS.union(DATA_EXTS)

            candidates = []
            source_errors = []

            # 1. Collect from Uploaded Files (with SECURITY validation)
            if has_files:
                total_file_size: int = 0
                for file in files:
                    if not file.filename: 
                        continue
                    
                    # SECURITY: Validate filename
                    try:
                        safe_filename = validate_filename(file.filename)
                    except ValueError as e:
                        logger.warning(f"Invalid filename rejected: {e}")
                        source_errors.append(f"File rejected due to invalid name: {str(file.filename)[:50]}")
                        continue
                    
                    if Path(safe_filename).suffix.lower() in VALID_EXTS:
                        try:
                            content_bytes: bytes = await file.read()
                            
                            # SECURITY: Check file size
                            if len(content_bytes) > MAX_CODE_SIZE:
                                source_errors.append(f"File {safe_filename} exceeds size limit")
                                continue
                            
                            total_file_size += len(content_bytes)
                            if total_file_size > MAX_CODE_SIZE * 5:  # 5MB total
                                source_errors.append("Total file size exceeds limit")
                                break
                            
                            c = content_bytes.decode('utf-8', errors='ignore')
                            if c.strip():
                                candidates.append({"name": safe_filename, "content": c})
                        except Exception as e:
                            logger.warning(f"Error reading file {safe_filename}: {e}")
                            source_errors.append(f"Error reading {safe_filename}")

            # 2. Collect from GitHub (with SECURITY validation)
            if github_url:
                extract_path = temp_path / "extracted"
                os.makedirs(extract_path, exist_ok=True)
                
                try:
                    # SECURITY: Use list for git command (prevents shell injection)
                    # SECURITY: Timeout of 60 seconds prevents hanging
                    logger.info(f"Cloning GitHub repository: {str(github_url)[:50]}...") # type: ignore
                    result = subprocess.run(
                        ["git", "clone", "--depth", "1", github_url, str(extract_path)],
                        check=True,
                        timeout=60,
                        capture_output=True,
                        text=True
                    )
                    
                    for root, dirs, fs in os.walk(extract_path):
                        # Filter out unwanted directories
                        valid_dirs = [d for d in dirs 
                                    if not d.startswith('.') and d not in 
                                    ['test', 'tests', 'node_modules', 'venv', 'env', '__pycache__', '.git', 'docs', 'assets']]
                        dirs.clear()
                        dirs.extend(valid_dirs)
                        
                        for f in fs:
                            p = Path(root) / f
                            if p.suffix.lower() in VALID_EXTS:
                                try:
                                    rel_path = p.relative_to(extract_path)
                                    with open(p, 'r', encoding='utf-8', errors='ignore') as code_file:
                                        c = code_file.read()
                                        if c.strip() and len(c) <= MAX_CODE_SIZE:
                                            candidates.append({"name": str(rel_path), "content": c})
                                except Exception as e:
                                    logger.debug(f"Error reading {p}: {e}")
                                    continue
                except subprocess.TimeoutExpired:
                    source_errors.append("Git clone timed out (>60 seconds)")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Git clone failed: {e.stderr}")
                    source_errors.append(f"Git clone failed: {e.stderr[:100]}")
                except Exception as e:
                    logger.warning(f"GitHub processing failed: {e}")
                    source_errors.append(f"GitHub processing error: {str(e)[:100]}") # type: ignore

            # 3. Collect from Paste (with size validation)
            if code_content and code_content.strip():
                if len(code_content) <= MAX_CODE_SIZE:
                    try:
                        safe_filename = validate_filename(file_name)
                        candidates.append({"name": safe_filename, "content": code_content})
                    except ValueError as e:
                        source_errors.append(f"Invalid filename for paste: {e}")
                else:
                    source_errors.append(f"Pasted code exceeds {MAX_CODE_SIZE} bytes")

            if not candidates:
                error_msg = "No valid source code found."
                if source_errors:
                    error_msg += " " + ". ".join(source_errors[:3])  # type: ignore  Limit error messages
                return JSONResponse(status_code=400, content={"error": error_msg})

            # RUN STATIC ANALYSIS
            static_findings = []
            for cand in candidates:
                try:
                    static_findings.extend(run_static_analysis(cand['name'], cand['content']))
                except Exception as e:
                    logger.warning(f"Static analysis failed for {cand['name']}: {e}")

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
                content = raw_text if len(raw_text) <= limit_int else raw_text[:limit_int] + "\n... [TRUNCATED]"
                entry = f"File: {cand['name']}\n```\n{content}\n```\n"
                entry_len = len(entry)
                if (bytes_accumulated + entry_len) > packing_limit:
                    break
                aggregated.append(entry)
                bytes_accumulated += entry_len # type: ignore

            context = "\n".join(aggregated)
            scan_type_str = scan_type
            
            if scan_type_str == "review":
                prompt = f"""You are a senior software engineer performing a code review.
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
            try:
                client = get_llm_client(
                    provider='openai' if provider=='openrouter' else provider,
                    api_key=api_key,
                    model=model,
                    api_base=api_base
                )
                success, error, results = LLMClientRunner(client).run_security_audit(temp_path, prompt, max_tokens=safe_max_tokens)
            except Exception as e:
                logger.error(f"LLM initialization failed: {e}")
                success = False
                error = str(e)
            
            if not success:
                # Fallback to static results
                files_count = len(aggregated)
                return {
                    "findings": static_findings,
                    "analysis_summary": {
                        "files_reviewed": files_count,
                        "high_severity": sum(1 for f in static_findings if f.get('severity') in ['CRITICAL', 'HIGH']),
                        "medium_severity": sum(1 for f in static_findings if f.get('severity') == 'MEDIUM'),
                        "low_severity": sum(1 for f in static_findings if f.get('severity') == 'LOW'),
                    },
                    "error": f"LLM Analysis Failed: {error}. Showing Static Analysis results only."
                }
            
            # MERGE RESULTS
            results["findings"] = static_findings + results.get("findings", [])
            if source_errors:
                results["warning"] = "Some sources had issues: " + "; ".join(source_errors[:3])
            
            return results

    except Exception as e:
        logger.exception(f"Scan endpoint error: {e}")
        # Return generic error to prevent information leakage
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error. Check logs for details."}
        )

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    try:
        return {"status": "healthy", "service": "claude-security-reviewer"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )


if __name__ == "__main__":
    import uvicorn # type: ignore
    
    BANNER = """
    Claude Security Reviewer v2.1.0 | Secure Analysis Engine
    --------------------------------------------------
    Initializing Secure Multi-Agent Context...
    System Ready: http://localhost:8095
    --------------------------------------------------
    """
    print(BANNER)
    
    # Get configuration from environment
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8095"))
    reload = os.environ.get("RELOAD", "false").lower() == "true"
    
    logger.info(f"Starting server on {host}:{port}")
    if os.environ.get("API_TOKEN"):
        logger.info("Authentication enabled")
    else:
        logger.warning("Authentication disabled (development mode)")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        reload=reload
    )
