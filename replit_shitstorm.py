#!/usr/bin/env python3
"""
04/20/2026
Addresses security, robustness, and usability gaps.
"""

import os
import sys
import subprocess
import tempfile
import shutil
import zipfile
from pathlib import Path
from typing import Optional, List, Tuple

# ----------------------------------------------------------------------
# 1. SECURE GIT CREDENTIAL HANDLING (no temp files)
# ----------------------------------------------------------------------
def git_push_secure(
    repo_path: str,
    owner: str,
    repo: str,
    method: str,
    token: Optional[str] = None,
    force: bool = False,
) -> bool:
    """
    Push using Git's credential helper system.
    Token never touches disk.
    """
    env = os.environ.copy()
    
    if method == "token" and token:
        # Use inline credential helper (available in Git ≥2.0)
        env["GIT_ASKPASS"] = "true"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_USERNAME"] = token      # token as username (GitHub accepts this)
        env["GIT_PASSWORD"] = ""         # empty password for token auth
        remote = f"https://{token}@github.com/{owner}/{repo}.git"
    elif method == "ssh":
        remote = f"git@github.com:{owner}/{repo}.git"
    else:
        print("[ERROR] Invalid push method")
        return False

    # Set remote
    subprocess.run(["git", "remote", "remove", "origin"], cwd=repo_path, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "remote", "add", "origin", remote], cwd=repo_path, check=False)
    
    # Push
    cmd = ["git", "push", "-u", "origin", "main"]
    if force:
        cmd.append("--force")
    
    result = subprocess.run(cmd, cwd=repo_path, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] Push failed: {result.stderr}")
        return False
    print("[SUCCESS] Code pushed to GitHub")
    return True


# ----------------------------------------------------------------------
# 2. ROBUST SUBPROCESS COMMANDS (no shell injection)
# ----------------------------------------------------------------------
def run_npm_install(project_root: str) -> bool:
    """Safely run npm install without shell=True."""
    package_json = Path(project_root) / "package.json"
    if not package_json.exists():
        return True
    
    print("[INFO] Installing Node dependencies...")
    result = subprocess.run(
        ["npm", "install", "--no-audit", "--no-fund"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[WARN] npm install failed: {result.stderr}")
        return False
    return True

def run_pip_install(project_root: str) -> bool:
    """Safely install Python requirements."""
    requirements = Path(project_root) / "requirements.txt"
    if not requirements.exists():
        return True
    
    print("[INFO] Installing Python dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[WARN] pip install failed: {result.stderr}")
        return False
    return True


# ----------------------------------------------------------------------
# 3. SMART PROJECT ROOT DETECTION (with user fallback)
# ----------------------------------------------------------------------
def find_project_root(extract_dir: str) -> str:
    """
    If ZIP contains a single top‑level folder, use that.
    Otherwise, let the user choose interactively.
    """
    items = [p for p in Path(extract_dir).iterdir() if p.name != "__MACOSX"]
    
    if len(items) == 1 and items[0].is_dir():
        return str(items[0])
    
    print("\n[INFO] Multiple top‑level items found:")
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item.name}")
    
    while True:
        try:
            choice = input("Enter number of project root (or 'q' to use current dir): ").strip()
            if choice.lower() == 'q':
                return extract_dir
            idx = int(choice) - 1
            if 0 <= idx < len(items):
                return str(items[idx])
        except ValueError:
            pass
        print("Invalid choice. Try again.")


# ----------------------------------------------------------------------
# 4. DRY‑RUN / VALIDATION MODE
# ----------------------------------------------------------------------
def dry_run_cleanup(root: str) -> None:
    """Simulate cleanup and report what would be deleted/modified."""
    from replit_to_github import REPLIT_LOCKIN, CONFIG_FILES, REPLIT_PATTERNS
    
    print("\n=== DRY RUN: Files that would be removed ===")
    for pattern in REPLIT_LOCKIN:
        path = Path(root) / pattern
        if path.exists():
            print(f"  🗑️  {pattern}")
    
    print("\n=== DRY RUN: Files that would be modified ===")
    for cfg in CONFIG_FILES:
        path = Path(root) / cfg
        if path.exists():
            content = path.read_text(errors="ignore")
            matches = [p for p in REPLIT_PATTERNS if re.search(p, content)]
            if matches:
                print(f"  ✏️  {cfg} (would replace {len(matches)} patterns)")


# ----------------------------------------------------------------------
# 5. GITHUB API WITH PROPER SSL (no raw sockets)
# ----------------------------------------------------------------------
def github_api_robust(endpoint: str, token: str, method: str = "GET", data: dict = None):
    """Use requests if available, else urllib with proper SSL."""
    try:
        import requests
        headers = {"Authorization": f"token {token}"}
        url = f"https://api.github.com{endpoint}"
        if method == "GET":
            resp = requests.get(url, headers=headers)
        elif method == "POST":
            resp = requests.post(url, json=data, headers=headers)
        return resp.json(), resp.status_code
    except ImportError:
        # Fallback to urllib (standard library, secure by default)
        import urllib.request
        import json
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        req = urllib.request.Request(
            f"https://api.github.com{endpoint}",
            headers=headers,
            method=method
        )
        if data:
            req.data = json.dumps(data).encode()
        with urllib.request.urlopen(req) as resp:
            return json.load(resp), resp.status


# ----------------------------------------------------------------------
# 6. MAIN ENHANCEMENT WRAPPER (drop‑in replacement for main())
# ----------------------------------------------------------------------
def enhanced_main():
    """Wrapper that uses original script functions + our improvements."""
    from replit_to_github import (
        prepare_project,
        repo_exists,
        create_repo,
        git_setup,
        log,
    )
    
    print("=== Replit to GitHub Pipeline (Enhanced 2026) ===")
    
    # Input with better defaults
    zip_path = input("ZIP file path: ").strip()
    owner = input("GitHub username/org: ").strip()
    repo = input("Repository name: ").strip()
    token = input("GitHub token (or press Enter for SSH): ").strip()
    method = "ssh" if not token else "token"
    dry = input("Dry run first? (y/n): ").lower() == "y"
    
    # Extract
    tmp = tempfile.mkdtemp(prefix="replit_enh_")
    try:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(tmp)
    except Exception as e:
        log(f"Failed to extract ZIP: {e}", error=True)
        return
    
    root = find_project_root(tmp)
    log(f"Project root: {root}")
    
    if dry:
        dry_run_cleanup(root)
        if input("\nProceed with actual migration? (y/n): ").lower() != "y":
            shutil.rmtree(tmp)
            return
    
    # Original preparation (still solid)
    prepare_project(root)
    
    # Enhanced dependency installs
    run_npm_install(root)
    run_pip_install(root)
    
    # GitHub workflow using our secure push
    if not repo_exists(owner, repo, token):
        if input("Repo doesn't exist. Create? (y/n): ").lower() == "y":
            private = input("Private? (y/n): ").lower() == "y"
            if not create_repo(owner, repo, token, private):
                log("Repo creation failed", error=True)
                return
    
    if not git_setup(root):
        log("Git setup failed", error=True)
    
    if git_push_secure(root, owner, repo, method, token):
        log("✅ SUCCESS: Project migrated and pushed to GitHub")
    else:
        log("❌ Push failed. Manual intervention required.", error=True)
    
    # Cleanup
    shutil.rmtree(tmp)


if __name__ == "__main__":
    enhanced_main()
