#!/usr/bin/env python3
"""
Replit to GitHub Pipeline (2026)

This script:
1. Cleans a Replit-exported project (removes lock-in, replaces hardcoded refs, generates missing configs).
2. Prepares the project for local/Android/Ubuntu builds.
3. Pushes the cleaned project to GitHub (supports SSH/token, handles repo creation, and merges if needed).
4. Logs all actions and adapts to non-critical errors to ensure completion.
"""

import os
import sys
import shutil
import re
import zipfile
import tempfile
import subprocess
import getpass
import json
import urllib.request
import urllib.error
import ssl
import socket
from pathlib import Path

# --- Constants ---
GITHUB_API = "https://api.github.com"
GITHUB_IP = "140.82.112.5"

# Replit lock-in files/folders (2026 research)
REPLIT_LOCKIN = [
    ".replit", "replit.nix", "CLAUDE.md", "AGENT.md", "replit.md",
    "entrypoint.sh", "nixpacks.toml", "replit.db", ".pythonlibs", ".upm",
    ".cache", "__pycache__", ".vscode", ".idea", "Thumbs.db", "desktop.ini",
]

# Files that may contain hardcoded Replit references
CONFIG_FILES = [
    ".env", "package.json", "Dockerfile", "docker-compose.yml",
    "main.py", "app.js", "index.html", "config.js", "config.py",
    "android/app/src/main/AndroidManifest.xml",
]

# Android build configs to generate if missing
ANDROID_CONFS = {
    "local.properties": "sdk.dir=/path/to/android/sdk\n",
    "gradle.properties": (
        "# Project-wide Gradle settings.\n"
        "org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8\n"
        "android.useAndroidX=true\n"
        "android.enableJetifier=true\n"
        "# Signing configs (replace with your own)\n"
        "MYAPP_RELEASE_STORE_FILE=my-release-key.jks\n"
        "MYAPP_RELEASE_KEY_ALIAS=my-key-alias\n"
        "MYAPP_RELEASE_STORE_PASSWORD=your_password\n"
        "MYAPP_RELEASE_KEY_PASSWORD=your_password\n"
    ),
}

# Hardcoded Replit patterns to replace
REPLIT_PATTERNS = {
    r"https://[a-zA-Z0-9-]+\.([a-zA-Z0-9-]+)\.repl\.co": "http://localhost:3000",
    r"REPLIT_DB_URL": "sqlite:///local.db",
    r"REPLIT_USER": "local_user",
    r"REPLIT_REPL_ID": "local_project",
}

# GitHub-related constants
DELETE_PATTERNS = [
    ".replit", "replit.nix", ".pythonlibs", ".upm", "node_modules",
    "__pycache__", "dist", "build", "target", ".cache", ".DS_Store",
    ".env", ".venv", "venv", "env", "*.pyc", "*.pyo", "*.pyd",
    "*.egg-info", "*.egg", "*.log", "*.swp", "*.swo", "*.bak",
    "Thumbs.db", "desktop.ini", ".vscode", ".idea", ".git"
]
PRESERVE_PATTERNS = [
    "sae_logo_pack.html", "sae_logo.svg", "brand/"
]
GITIGNORE_CONTENT = """# Build artifacts
/dist/
/build/
/target/
/node_modules/
/__pycache__/
/.cache/
/*.py[cod]
/*.log
/.env
/.venv/
/venv/
/env/
/*.swp
/*.swo
/*.bak
/Thumbs.db
/desktop.ini
/.DS_Store

# IDE
.vscode/
.idea/

# Replit
.replit
replit.nix
.pythonlibs
.upm
"""

# --- Logging ---
def log(msg, error=False):
    tag = "ERROR" if error else "INFO"
    print(f"[{tag}] {msg}", file=sys.stderr if error else sys.stdout)

# --- Cleanup & Prep Functions ---
def remove_lockin_files(root):
    """Remove Replit lock-in files and folders."""
    for item in REPLIT_LOCKIN:
        path = os.path.join(root, item)
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                    log(f"Removed directory: {item}")
                else:
                    os.remove(path)
                    log(f"Removed file: {item}")
            except Exception as e:
                log(f"Failed to remove {item}: {e}", error=True)

def replace_hardcoded_refs(root):
    """Replace hardcoded Replit references in config files."""
    for config in CONFIG_FILES:
        path = os.path.join(root, config)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r+") as f:
                content = f.read()
                changed = False
                for pattern, replacement in REPLIT_PATTERNS.items():
                    if re.search(pattern, content):
                        content = re.sub(pattern, replacement, content)
                        changed = True
                if changed:
                    f.seek(0)
                    f.write(content)
                    f.truncate()
                    log(f"Updated hardcoded refs in: {config}")
        except Exception as e:
            log(f"Failed to update {config}: {e}", error=True)

def generate_android_configs(root):
    """Generate missing Android build configs."""
    android_dir = os.path.join(root, "android")
    if not os.path.exists(android_dir):
        return
    for conf, content in ANDROID_CONFS.items():
        path = os.path.join(android_dir, conf)
        if not os.path.exists(path):
            try:
                with open(path, "w") as f:
                    f.write(content)
                log(f"Generated missing Android config: {conf}")
            except Exception as e:
                log(f"Failed to generate {conf}: {e}", error=True)

def generate_node_configs(root):
    """Generate missing Node.js configs (e.g., package-lock.json)."""
    if os.path.exists(os.path.join(root, "package.json")):
        try:
            log("Running 'npm install' to generate lockfile...")
            os.system(f"cd {root} && npm install")
        except Exception as e:
            log(f"Failed to generate Node.js lockfile: {e}", error=True)

def generate_python_configs(root):
    """Generate missing Python configs (e.g., virtualenv)."""
    if os.path.exists(os.path.join(root, "requirements.txt")):
        try:
            log("Running 'pip install -r requirements.txt'...")
            os.system(f"cd {root} && pip install -r requirements.txt")
        except Exception as e:
            log(f"Failed to install Python requirements: {e}", error=True)

def prepare_project(root):
    """Prepare a Replit-exported project for local/Android/Ubuntu builds."""
    log(f"Preparing project at: {root}")
    remove_lockin_files(root)
    replace_hardcoded_refs(root)
    generate_android_configs(root)
    generate_node_configs(root)
    generate_python_configs(root)
    log("Project preparation complete. Ready for local/Android/Ubuntu builds.")

# --- GitHub Functions ---
def run_cmd(cmd, cwd=None, env=None, critical=True):
    """Run a shell command, optionally in a directory, with input."""
    log(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, cwd=cwd, env=env, check=critical)
        return True
    except subprocess.CalledProcessError as e:
        if critical:
            log(f"Command failed: {e}", error=True)
            return False
        else:
            log(f"Non-critical command failed: {e}", error=True)
            return True

def github_api_request(url, token, method="GET", data=None, dns=False):
    """Make a GitHub API request, with optional DNS patch."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    if dns:
        try:
            ctx = ssl.create_default_context()
            sock = socket.create_connection((GITHUB_IP, 443))
            ssock = ctx.wrap_socket(sock, server_hostname="api.github.com")
            parsed = urllib.parse.urlparse(url)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            req = f"{method} {path} HTTP/1.1\r\nHost: api.github.com\r\n"
            for k, v in headers.items():
                req += f"{k}: {v}\r\n"
            req += "Connection: close\r\n\r\n"
            ssock.sendall(req.encode())
            if data:
                ssock.sendall(json.dumps(data).encode())
            resp = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            ssock.close()
            header_body = resp.split(b"\r\n\r\n", 1)
            if len(header_body) != 2:
                raise RuntimeError("Malformed HTTP response")
            status = int(resp.split(b" ")[1])
            return json.loads(header_body[1].decode()), status
        except Exception as e:
            log(f"GitHub API (DNS) error: {e}", error=True)
            return None, None
    else:
        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            if data:
                req.data = json.dumps(data).encode()
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read().decode()), r.status
        except urllib.error.URLError as e:
            log(f"GitHub API error: {e}", error=True)
            return None, None

def repo_exists(owner, repo, token, dns=False):
    """Check if a GitHub repo exists."""
    _, status = github_api_request(f"{GITHUB_API}/repos/{owner}/{repo}", token, dns=dns)
    return status == 200

def create_repo(owner, repo, token, private=False, dns=False):
    """Create a new GitHub repo."""
    data, status = github_api_request(
        f"{GITHUB_API}/user/repos",
        token,
        method="POST",
        data={"name": repo, "private": private},
        dns=dns
    )
    if status not in (200, 201):
        log(f"Repo creation failed (status: {status})", error=True)
        return False
    return True

def git_setup(root):
    """Initialize git repo, add files, and commit."""
    if not run_cmd(["git", "init"], cwd=root):
        return False
    if not run_cmd(["git", "add", "."], cwd=root):
        return False
    run_cmd(["git", "commit", "-m", "initial commit"], cwd=root, critical=False)
    run_cmd(["git", "branch", "-M", "main"], cwd=root, critical=False)
    return True

def git_push(root, owner, repo, method, token, dns=False):
    """Push to GitHub, handling both SSH and token auth."""
    env = os.environ.copy()
    if method == "token":
        try:
            fd, path = tempfile.mkstemp()
            with os.fdopen(fd, "w") as f:
                f.write(f"#!/bin/sh\necho '{token}'\n")
            os.chmod(path, 0o700)
            env["GIT_ASKPASS"] = path
        except Exception as e:
            log(f"Failed to set up GIT_ASKPASS: {e}", error=True)
            return False

    remote = (
        f"git@github.com:{owner}/{repo}.git"
        if method == "ssh"
        else f"https://github.com/{owner}/{repo}.git"
    )

    if not run_cmd(["git", "remote", "add", "origin", remote], cwd=root, env=env):
        run_cmd(["git", "remote", "set-url", "origin", remote], cwd=root, env=env, critical=False)

    run_cmd(["git", "config", "core.compression", "9"], cwd=root, critical=False)
    run_cmd(["git", "config", "pack.window", "100"], cwd=root, critical=False)
    run_cmd(["git", "config", "pack.depth", "100"], cwd=root, critical=False)
    run_cmd(["git", "config", "http.lowSpeedLimit", "0"], cwd=root, critical=False)
    run_cmd(["git", "config", "http.lowSpeedTime", "999999"], cwd=root, critical=False)
    run_cmd(["git", "config", "http.postBuffer", "524288000"], cwd=root, critical=False)

    run_cmd(["git", "gc", "--aggressive", "--prune=now"], cwd=root, critical=False)
    run_cmd(["git", "fetch", "origin"], cwd=root, env=env, critical=False)
    run_cmd(["git", "pull", "origin", "main", "--allow-unrelated-histories"], cwd=root, env=env, critical=False)

    if not run_cmd(["git", "push", "-u", "origin", "main"], cwd=root, env=env):
        if run_cmd(["git", "push", "-u", "origin", "main", "--force"], cwd=root, env=env):
            return True
        return False
    return True

# --- Main Workflow ---
def main():
    print("=== Replit to GitHub Pipeline (2026) ===")

    # User input
    zip_path = input("ZIP file path: ").strip()
    owner = input("GitHub username/org: ").strip()
    repo = input("Repository name: ").strip()
    token = getpass.getpass("GitHub token: ")
    method = input("Push method (ssh/token): ").strip().lower()
    dns = input("Enable DNS patch? (y/n): ").lower() == "y"

    # Extract ZIP
    if not os.path.exists(zip_path):
        log(f"ZIP file not found: {zip_path}", error=True)
        return
    tmp = tempfile.mkdtemp(prefix="repo_")
    try:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(tmp)
    except Exception as e:
        log(f"Failed to extract ZIP: {e}", error=True)
        return

    # Find project root
    root = tmp
    try:
        items = os.listdir(tmp)
        if len(items) == 1 and os.path.isdir(os.path.join(tmp, items[0])):
            root = os.path.join(tmp, items[0])
    except Exception as e:
        log(f"Failed to find project root: {e}", error=True)

    log(f"Project root: {root}")

    # Prepare project
    prepare_project(root)

    # GitHub workflow
    if not repo_exists(owner, repo, token, dns):
        if input("Repo does not exist. Create? (y/n): ").lower() != "y":
            return
        private = input("Private repo? (y/n): ").lower() == "y"
        create_repo(owner, repo, token, private, dns)

    if not git_setup(root):
        log("Git setup failed, but continuing...", error=True)

    if git_push(root, owner, repo, method, token, dns):
        log("SUCCESS: Project pushed to GitHub")
    else:
        log("FAILED: Could not push to GitHub", error=True)

if __name__ == "__main__":
    main()
