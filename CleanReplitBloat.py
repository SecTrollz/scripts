 #!/usr/bin/env python3
"""
Replit Bloat Cleaner with DeepSeek AI assistance.
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Set

import requests
from send2trash import send2trash

DEFAULT_BLOAT_PATTERNS = [
    # Directories
    "attached_assets",
    "node_modules",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "env",
    "target",          # Rust
    "bin", "obj",      # .NET
    # Files
    "*.log",
    "*.tmp",
    "*.temp",
    "*.swp",
    "*.bak",
    "*.pyc",
    "*.pyo",
    "*.DS_Store",
    "thumbs.db",
    "*.lock",          # package-lock.json, etc. (careful)
    "*.tsbuildinfo",
]

# Maximum bytes to read from a file for analysis
MAX_SAMPLE_SIZE = 4096

# DeepSeek API endpoint
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
def get_api_key() -> str:
    """Get DeepSeek API key from environment or user input."""
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        key = input("Enter your DeepSeek API key: ").strip()
        if not key:
            print(" API key is required. Exiting.")
            sys.exit(1)
        # Optionally save to env for this session
        os.environ["DEEPSEEK_API_KEY"] = key
    return key


def should_scan_file(file_path: Path, patterns: List[str]) -> bool:
    """Return True if file matches any bloat pattern."""
    path_str = str(file_path)
    # Directories are handled by walk, but we check full path for patterns like "attached_assets"
    for pat in patterns:
        if pat.endswith("/") or pat.endswith("\\"):  # directory pattern
            if pat.rstrip("/\\") in path_str.split(os.sep):
                return True
        else:
            # Glob-like matching
            if pat.startswith("*."):
                if file_path.suffix == pat[1:]:
                    return True
            elif pat in path_str:
                return True
    return False


def read_sample(file_path: Path) -> str:
    """Read first few KB of a file, safely handle binary."""
    try:
        with open(file_path, "rb") as f:
            raw = f.read(MAX_SAMPLE_SIZE)
        # Try to decode as UTF-8, replace errors
        return raw.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[Error reading file: {e}]"


def group_files(files: List[Path]) -> List[List[Path]]:
    """
    Group files to reduce API calls.
    Strategy: group by (parent directory, extension) but keep size reasonable.
    Returns list of groups, each group is a list of file paths.
    """
    groups = {}
    for fp in files:
        key = (fp.parent, fp.suffix)  # group by folder + extension
        groups.setdefault(key, []).append(fp)
    # Further split groups that are too large (e.g., >10 files) to avoid huge prompts
    final_groups = []
    for group in groups.values():
        if len(group) <= 10:
            final_groups.append(group)
        else:
            # split into chunks of 10
            for i in range(0, len(group), 10):
                final_groups.append(group[i:i+10])
    return final_groups


def explain_file_group(file_group: List[Path], api_key: str) -> str:
    """
    Send file names + content samples to DeepSeek API.
    Returns a concise explanation and recommendation.
    """
    # Prepare prompt
    files_info = []
    for fp in file_group:
        sample = read_sample(fp)
        # Truncate sample further if too long
        if len(sample) > 1000:
            sample = sample[:1000] + "\n...[truncated]"
        files_info.append(f"File: {fp}\nContent sample:\n{sample}\n---")
    combined_info = "\n".join(files_info)
    
    prompt = f"""You are an assistant that helps identify unnecessary or "bloat" files in a software project.
Below are one or more files from a Replit environment (often includes temporary assets, logs, build artifacts).
For each file (or the group as a whole), please:
1. Explain what the file likely is and its purpose.
2. State whether it is safe to delete.
3. If the file's functionality could be implemented as a simple function elsewhere in the codebase, suggest where and how.

Be concise but specific. Here are the file details:
{combined_info}
"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 800
    }
    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[API Error: {e}]"


def interactive_decision(file_group: List[Path], explanation: str, dry_run: bool) -> Tuple[Set[Path], Dict]:
    """
    Show explanation to user and ask which files to delete.
    Returns (set_of_files_to_delete, notes_dict).
    """
    print("\n" + "="*70)
    print(f" Group of {len(file_group)} file(s):")
    for fp in file_group:
        print(f"   • {fp}")
    print("\n DeepSeek Analysis:")
    print(explanation)
    print("\n Options:")
    print("   [d] Delete all files in this group")
    print("   [s] Select specific files to delete (by number)")
    print("   [k] Keep all (do nothing)")
    print("   [v] View detailed content of a file")
    choice = input("Your choice [d/s/k/v]: ").strip().lower()
    
    to_delete = set()
    notes = {}
    if choice == "d":
        to_delete = set(file_group)
        notes["action"] = "deleted all"
        notes["reason"] = "user chose delete all"
    elif choice == "s":
        print("\nSelect files by number (comma-separated, e.g. 1,3,5):")
        for i, fp in enumerate(file_group, 1):
            print(f"  {i}: {fp}")
        sel = input("Numbers: ").strip()
        if sel:
            indices = [int(x.strip())-1 for x in sel.split(",") if x.strip().isdigit()]
            to_delete = {file_group[i] for i in indices if 0 <= i < len(file_group)}
            notes["action"] = f"deleted selected ({len(to_delete)} files)"
            notes["reason"] = "user selected specific files"
        else:
            notes["action"] = "none selected"
    elif choice == "v":
        # Show content of a specific file
        print("\nSelect a file to view content:")
        for i, fp in enumerate(file_group, 1):
            print(f"  {i}: {fp}")
        idx = input("Number: ").strip()
        if idx.isdigit():
            fp = file_group[int(idx)-1]
            sample = read_sample(fp)
            print(f"\n--- Content of {fp} (first {MAX_SAMPLE_SIZE} bytes) ---")
            print(sample)
            print("--- End of content ---")
        # After viewing, re-enter decision recursively
        return interactive_decision(file_group, explanation, dry_run)
    else:
        notes["action"] = "kept"
        notes["reason"] = "user chose keep"
    
    if dry_run and to_delete:
        print(f" DRY RUN: Would delete {len(to_delete)} file(s).")
        to_delete.clear()
    elif to_delete:
        print(f" Deleting {len(to_delete)} file(s)...")
        for fp in to_delete:
            try:
                send2trash(str(fp))
                print(f"   Moved to trash: {fp}")
            except Exception as e:
                print(f"    Failed to delete {fp}: {e}")
    return to_delete, notes


def main():
    parser = argparse.ArgumentParser(description="Remove bloat files from Replit projects with AI assistance.")
    parser.add_argument("directory", nargs="?", default=".", help="Root directory to scan (default: current dir)")
    parser.add_argument("--patterns", nargs="+", help="Additional glob patterns or directory names to treat as bloat")
    parser.add_argument("--dry-run", action="store_true", help="Only show what would be deleted, no actual deletion")
    parser.add_argument("--log", default=f"bloat_cleanup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log", help="Log file path")
    args = parser.parse_args()
    
    # Combine patterns
    patterns = DEFAULT_BLOAT_PATTERNS.copy()
    if args.patterns:
        patterns.extend(args.patterns)
    
    root = Path(args.directory).resolve()
    if not root.is_dir():
        print(f" Directory not found: {root}")
        sys.exit(1)
    
    print(f"🔍 Scanning {root} for bloat files...")
    bloat_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip hidden directories like .git? We'll include but patterns may catch.
        for filename in filenames:
            full_path = Path(dirpath) / filename
            if should_scan_file(full_path, patterns):
                bloat_files.append(full_path)
    
    if not bloat_files:
        print(" No bloat files found.")
        return
    
    print(f" Found {len(bloat_files)} potential bloat files.")
    print("Grouping similar files for efficient analysis...")
    groups = group_files(bloat_files)
    print(f" Grouped into {len(groups)} groups.")
    
    api_key = get_api_key()
    
    total_deleted = 0
    log_entries = []
    
    for idx, group in enumerate(groups, 1):
        print(f"\n--- Processing group {idx}/{len(groups)} ---")
        explanation = explain_file_group(group, api_key)
        to_delete, notes = interactive_decision(group, explanation, args.dry_run)
        total_deleted += len(to_delete)
        # Log details
        for fp in group:
            log_entries.append({
                "file": str(fp),
                "deleted": fp in to_delete,
                "notes": notes if len(group) == 1 else {**notes, "group_explanation": explanation}
            })
        # Small delay to avoid rate limits
        time.sleep(1)
    
    # Write log
    with open(args.log, "w", encoding="utf-8") as f:
        json.dump(log_entries, f, indent=2)
    print(f"\n Log written to {args.log}")
    print(f" Done. {total_deleted} files deleted (or would be deleted in dry-run).")

if __name__ == "__main__":
    main()
