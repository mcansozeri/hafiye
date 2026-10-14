#!/usr/bin/env python3
"""
Hafiye - secret detection with detect-secrets, CodeBERT and LLM verification
"""

import os
import sys
os.environ["TOKENIZERS_PARALLELISM"] = "false"
import subprocess
import json
import tempfile
import shutil
import argparse
import platform
import uuid
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
import re
import git
import configparser

from benchmark import get_groundtruth_lines


def parse_llm_json(text):
    """Parse the JSON answer of the LLM. The 'reason' field may itself contain braces or quotes,
    so the full answer is tried first and a field-level regular expression is used as fallback."""
    if not text:
        return None
    for cand in (text, re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M),
                 text[text.find("{"): text.rfind("}") + 1] if "{" in text and "}" in text else ""):
        try:
            d = json.loads(cand)
            if isinstance(d, dict) and "is_false_positive" in d:
                return d
        except Exception:
            pass
    m_fp = re.search(r'"is_false_positive"\s*:\s*(true|false)', text, re.I)
    if not m_fp:
        return None
    m_conf = re.search(r'"confidence"\s*:\s*"(high|medium|low)"', text, re.I)
    m_reason = re.search(r'"reason"\s*:\s*"(.*)', text, re.S)
    return {"is_false_positive": m_fp.group(1).lower() == "true",
            "confidence": (m_conf.group(1).lower() if m_conf else "low"),
            "reason": (m_reason.group(1).strip().rstrip('"}\n ') if m_reason else "")}


def print_header():
    """Print colorful project header with information"""
    # ANSI color codes
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    print(f"\n{CYAN}{'='*80}{RESET}")
    print(f"{BOLD}{YELLOW}Hafiye{RESET}")
    print(f"{BOLD}{MAGENTA}Hybrid Approach for Sensitive Information Detection in Source Code{RESET}")
    print(f"{BOLD}{MAGENTA}Using Rule-Based, Vector-Based, and LLM-Assisted Filtering{RESET}")
    print(f"{CYAN}{'='*80}{RESET}\n")
    
    print(f"{YELLOW}Authors:{RESET}")
    print(f"{GREEN}  • Cagla Nur Yuva{RESET} (c.yuva2020@gtu.edu.tr)")
    print(f"{GREEN}  • Mahmut Can Sozeri{RESET} (mahmutsozeri@gtu.edu.tr)")
    print(f"{GREEN}  • Salih Sarp{RESET}")
    print(f"\n{BLUE}Department of Computer Engineering{RESET}")
    print(f"{BLUE}Gebze Technical University{RESET}")
    print(f"{BLUE}Gebze, Kocaeli, Türkiye{RESET}\n")
    print(f"{CYAN}{'='*80}{RESET}\n")


class SecretScanner:
    def __init__(self, target_path, is_repo=False, similarity_threshold=0.85, 
                 llm_provider='gemini', context_lines=3, use_llm=True, no_llm=False, benchmark=False,
                 detect_secrets_variant='patched'):
        self.target_path = target_path
        self.is_repo = is_repo
        self.work_dir = None
        self.detect_secrets_dir = None
        self.system = platform.system().lower()
        self.similarity_threshold = similarity_threshold
        self.llm_provider = llm_provider.lower()
        self.context_lines = context_lines
        self.use_llm = use_llm
        self.no_llm = no_llm
        self.benchmark = benchmark
        self.detect_secrets_variant = detect_secrets_variant
        if no_llm:
            self.use_llm = False
        
        # Generate unique GUID for this scan
        self.scan_guid = str(uuid.uuid4())
        
        # Create project directories
        self.base_dir = os.getcwd()
        self.scan_files_dir = os.path.join(self.base_dir, 'scanfiles')
        self.tools_dir = os.path.join(self.base_dir, 'tools')
        self.results_dir = os.path.join(self.base_dir, 'results', self.scan_guid)
        self.upgrade_dir = os.path.join(self.base_dir, 'upgrade')
        
        # Create directories if they don't exist
        os.makedirs(self.scan_files_dir, exist_ok=True)
        os.makedirs(self.tools_dir, exist_ok=True)
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Load and validate API keys if LLM is enabled
        if self.use_llm and not self.no_llm:
            self.api_keys = self.load_api_keys()
            if not self.validate_api_key():
                print(f"\n{'='*80}")
                print(f"ERROR: LLM analysis requested but API key not configured!")
                print(f"{'='*80}")
                print(f"Please edit config.ini and add your {self.llm_provider.upper()} API key.")
                print(f"Then run the scan again, or use --no-llm to skip LLM analysis.")
                print(f"{'='*80}\n")
                sys.exit(1)
        else:
            self.api_keys = {}
        
        print(f"\n[*] Scan GUID: {self.scan_guid}")
        print(f"[*] Similarity Threshold: {self.similarity_threshold}")
        if self.use_llm:
            print(f"[*] LLM Provider: {self.llm_provider}")
            print(f"[*] Context Lines: {self.context_lines}")
        else:
            print(f"[*] LLM Analysis: Disabled")
    
    def benchmark_repo_id(self):
        """CredData repo id = name of the scanned folder (e.g. benchmark/CredData/data/602d34f9)"""
        return os.path.basename(os.path.normpath(self.target_path))

    def validate_api_key(self):
        """Validate that the required API key is configured"""
        if self.llm_provider == 'gemini':
            key = self.api_keys.get('gemini', '')
            return key and key != 'YOUR_GEMINI_API_KEY_HERE' and len(key) > 10
        elif self.llm_provider == 'openai':
            key = self.api_keys.get('openai', '')
            return key and key != 'YOUR_OPENAI_API_KEY_HERE' and len(key) > 10
        return False
    
    def load_api_keys(self):
        """Load API keys from config.ini file"""
        config_file = os.path.join(self.base_dir, 'config.ini')
        
        if not os.path.exists(config_file):
            print(f"[!] config.ini not found. Creating template...")
            self.create_config_template(config_file)
            print(f"[!] Please edit config.ini with your API keys")
        
        config = configparser.ConfigParser()
        config.read(config_file)
        
        api_keys = {}
        if config.has_section('API_KEYS'):
            api_keys['gemini'] = config.get('API_KEYS', 'gemini_api_key', fallback='')
            api_keys['openai'] = config.get('API_KEYS', 'openai_api_key', fallback='')
        
        return api_keys
    
    def create_config_template(self, config_file):
        """Create a template config.ini file"""
        config = configparser.ConfigParser()
        config['API_KEYS'] = {
            'gemini_api_key': 'YOUR_GEMINI_API_KEY_HERE',
            'openai_api_key': 'YOUR_OPENAI_API_KEY_HERE'
        }
        
        with open(config_file, 'w') as f:
            config.write(f)
        
        print(f"[+] Template config.ini created at: {config_file}")
    
    def apply_upgrades(self):
        """Apply any upgrades from upgrade directory to tools directory"""
        print("\n[*] Checking for upgrades...")
        
        if not os.path.exists(self.upgrade_dir):
            print("[*] No upgrade directory found, skipping...")
            return
        
        # Check if upgrade directory has any content
        upgrade_contents = os.listdir(self.upgrade_dir)
        if not upgrade_contents:
            print("[*] Upgrade directory is empty, skipping...")
            return
        
        print(f"[*] Found upgrade directory with content, applying updates...")
        
        upgraded_files = 0
        
        # Walk through upgrade directory
        for root, dirs, files in os.walk(self.upgrade_dir):
            # Get relative path from upgrade directory
            rel_path = os.path.relpath(root, self.upgrade_dir)
            
            # Construct target path directly under base directory
            # This ensures we don't create nested tools directories
            if rel_path == '.':
                # Skip root level, we need at least one subdirectory
                continue
            
            # Target should be base_dir/rel_path (e.g., base_dir/tools/detect-secrets/...)
            target_root = os.path.join(self.base_dir, rel_path)
            
            # Process each file
            for file in files:
                # Skip hidden files and .DS_Store
                if file.startswith('.'):
                    continue
                
                source_file = os.path.join(root, file)
                target_file = os.path.join(target_root, file)
                
                try:
                    # Create target directory if it doesn't exist
                    os.makedirs(target_root, exist_ok=True)
                    
                    # Copy and replace the file
                    shutil.copy2(source_file, target_file)
                    
                    # Get relative path for display
                    display_path = os.path.relpath(target_file, self.base_dir)
                    print(f"[+] Updated: {display_path}")
                    upgraded_files += 1
                    
                except Exception as e:
                    print(f"[-] Failed to update {file}: {e}")
        
        if upgraded_files > 0:
            print(f"[+] Successfully applied {upgraded_files} upgrade(s)")
        else:
            print("[*] No files were upgraded")
        
        print()
    
    def load_denylist_from_keyword_plugin(self):
        """Load DENYLIST and DENYLIST2 from keyword.py plugin"""
        keyword_file = os.path.join(
            self.tools_dir,
            'detect-secrets',
            'detect_secrets',
            'plugins',
            'keyword.py'
        )
        
        # Check upgrade directory first
        upgrade_keyword_file = os.path.join(
            self.upgrade_dir,
            'tools',
            'detect-secrets',
            'detect_secrets',
            'plugins',
            'keyword.py'
        )
        
        target_file = upgrade_keyword_file if os.path.exists(upgrade_keyword_file) else keyword_file
        
        if not os.path.exists(target_file):
            print(f"[!] keyword.py not found, using default patterns")
            return [
                'api_key', 'password', 'secret', 'token', 'auth',
                'private_key', 'client_secret', 'access_token'
            ]
        
        try:
            with open(target_file, 'r', encoding='utf-8') as f:
                content = f.read()                  
            
            # Extract DENYLIST tuples using regex
            denylist1_match = re.search(
                r'DENYLIST\s*=\s*\((.*?)\)',
                content,
                re.DOTALL
            )
            denylist2_match = re.search(
                r'DENYLIST2\s*=\s*\((.*?)\)',
                content,
                re.DOTALL
            )
            
            patterns = set()
            
            if denylist1_match:
                entries = re.findall(r"'([^']+)'", denylist1_match.group(1))
                patterns.update(entries)
                print(f"[+] Loaded {len(entries)} patterns from DENYLIST")
            
            if denylist2_match:
                entries = re.findall(r"'([^']+)'", denylist2_match.group(1))
                patterns.update(entries)
                print(f"[+] Loaded {len(entries)} patterns from DENYLIST2")
            
            # Clean patterns (remove regex special characters for basic matching)
            cleaned_patterns = []
            for pattern in patterns:
                # Remove regex ? characters for basic text matching
                cleaned = pattern.replace('_?', '_').replace('?', '')
                # Also keep patterns with special chars for regex matching
                cleaned_patterns.append(pattern)
                if cleaned != pattern:
                    cleaned_patterns.append(cleaned)
            
            return list(set(cleaned_patterns))
            
        except Exception as e:
            print(f"[-] Error loading keyword.py: {e}")
            return [
                'api_key', 'password', 'secret', 'token', 'auth',
                'private_key', 'client_secret', 'access_token'
            ]
    def load_ignorelist_from_heuristic_filter(self):        
        # Check upgrade directory first
        heuristic_file = os.path.join(
            self.upgrade_dir,
            'tools',
            'detect-secrets',
            'detect_secrets',
            'filters',
            'heuristic.py'
        ) 
        
        try:
            import ast
            with open(heuristic_file, 'r', encoding='utf-8') as f:
                content_heuristic = ast.parse(f.read())

            for node in content_heuristic.body:
                if isinstance(node, ast.Assign):
                    if any(getattr(t, "id", None) == "IGNORED_FILE_EXTENSIONS" for t in node.targets):
                        call = node.value              # set(...)
                        tuple_node = call.args[0]      # ('.7z', '.bin', ...)
                        extensions = list(ast.literal_eval(tuple_node))
                       
            return extensions
            
        except Exception as e:
            print(f"[-] Error loading heuristic.py: {e}")
            return [
            ]
    
    def check_git_lfs(self):
        """Check if git-lfs is installed"""
        try:
            result = subprocess.run(
                ['git', 'lfs', 'version'],
                capture_output=True,
                text=True,
                check=False
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def install_git_lfs(self):
        """Install git-lfs based on operating system"""
        print(f"[*] git-lfs not found, attempting to install...")
        
        try:
            if self.system == 'darwin':  # macOS
                print(f"[*] Detected macOS, installing via Homebrew...")
                # Check if brew is installed
                brew_check = subprocess.run(['which', 'brew'], capture_output=True)
                if brew_check.returncode != 0:
                    print(f"[-] Homebrew not found. Please install Homebrew first:")
                    print(f"    /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
                    return False
                
                subprocess.run(['brew', 'install', 'git-lfs'], check=True)
                subprocess.run(['git', 'lfs', 'install'], check=True)
                print(f"[+] git-lfs installed successfully on macOS")
                return True
                
            elif self.system == 'linux':
                print(f"[*] Detected Linux, installing via package manager...")
                
                # Try apt (Debian/Ubuntu)
                apt_check = subprocess.run(['which', 'apt-get'], capture_output=True)
                if apt_check.returncode == 0:
                    print(f"[*] Using apt-get...")
                    subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                    subprocess.run(['sudo', 'apt-get', 'install', '-y', 'git-lfs'], check=True)
                    subprocess.run(['git', 'lfs', 'install'], check=True)
                    print(f"[+] git-lfs installed successfully on Linux (apt)")
                    return True
                
                # Try yum (RHEL/CentOS/Fedora)
                yum_check = subprocess.run(['which', 'yum'], capture_output=True)
                if yum_check.returncode == 0:
                    print(f"[*] Using yum...")
                    subprocess.run(['sudo', 'yum', 'install', '-y', 'git-lfs'], check=True)
                    subprocess.run(['git', 'lfs', 'install'], check=True)
                    print(f"[+] git-lfs installed successfully on Linux (yum)")
                    return True
                
                # Try dnf (Fedora)
                dnf_check = subprocess.run(['which', 'dnf'], capture_output=True)
                if dnf_check.returncode == 0:
                    print(f"[*] Using dnf...")
                    subprocess.run(['sudo', 'dnf', 'install', '-y', 'git-lfs'], check=True)
                    subprocess.run(['git', 'lfs', 'install'], check=True)
                    print(f"[+] git-lfs installed successfully on Linux (dnf)")
                    return True
                
                print(f"[-] Could not find a suitable package manager")
                print(f"[!] Please install git-lfs manually: https://git-lfs.github.com/")
                return False
                
            elif self.system == 'windows':
                print(f"[*] Detected Windows, installing via Chocolatey or manual download...")
                
                # Try chocolatey
                choco_check = subprocess.run(['where', 'choco'], capture_output=True, shell=True)
                if choco_check.returncode == 0:
                    print(f"[*] Using Chocolatey...")
                    subprocess.run(['choco', 'install', 'git-lfs', '-y'], shell=True, check=True)
                    subprocess.run(['git', 'lfs', 'install'], check=True)
                    print(f"[+] git-lfs installed successfully on Windows")
                    return True
                else:
                    print(f"[-] Chocolatey not found")
                    print(f"[!] Please install git-lfs manually:")
                    print(f"    1. Download from: https://git-lfs.github.com/")
                    print(f"    2. Or install Chocolatey first: https://chocolatey.org/install")
                    print(f"    3. Then run: choco install git-lfs")
                    return False
            else:
                print(f"[-] Unsupported operating system: {self.system}")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"[-] Installation failed: {e}")
            return False
        except Exception as e:
            print(f"[-] Unexpected error during installation: {e}")
            return False
    
    def setup_environment(self):
        """Prepare working environment"""
        # First, setup detect-secrets
        self.setup_detect_secrets()
        
        if self.is_repo:
            # Check and install git-lfs if needed
            if not self.check_git_lfs():
                print(f"[!] git-lfs is required for this repository")
                if not self.install_git_lfs():
                    print(f"[!] Continuing without git-lfs (some large files may be missing)...")
            
            # Use GUID as directory name
            self.work_dir = os.path.join(self.scan_files_dir, self.scan_guid)
            
            # Clone GitHub repository
            print(f"\n[*] Cloning GitHub repository: {self.target_path}")
            print(f"[*] Target directory: {self.work_dir}")
            
            try:
                # Try simple clone first (works if git-lfs is installed or not needed)
                git.Repo.clone_from(
                    self.target_path, 
                    self.work_dir,
                    depth=1
                )
                print(f"[+] Repository successfully cloned: {self.work_dir}")
                
            except git.exc.GitCommandError as e:
                # If failed, try without LFS
                print(f"[!] Standard clone failed, trying without LFS...")
                try:
                    # Remove the failed directory if exists
                    if os.path.exists(self.work_dir):
                        shutil.rmtree(self.work_dir)
                    
                    # Set environment to skip LFS
                    env = os.environ.copy()
                    env['GIT_LFS_SKIP_SMUDGE'] = '1'
                    
                    # Clone with depth=1 and skip LFS
                    subprocess.run(
                        ['git', 'clone', '--depth', '1', self.target_path, self.work_dir],
                        env=env,
                        check=True,
                        capture_output=True
                    )
                    print(f"[+] Repository successfully cloned (LFS files skipped): {self.work_dir}")
                    
                except Exception as e2:
                    print(f"[-] Repository cloning error: {e2}")
                    if os.path.exists(self.work_dir):
                        shutil.rmtree(self.work_dir)
                    sys.exit(1)
                    
            except Exception as e:
                print(f"[-] Repository cloning error: {e}")
                if os.path.exists(self.work_dir):
                    shutil.rmtree(self.work_dir)
                sys.exit(1)
        else:
            # For local path, copy to scanfiles directory with GUID
            if not os.path.exists(self.target_path):
                print(f"[-] Path not found: {self.target_path}")
                sys.exit(1)
            
            # Use GUID as directory name
            self.work_dir = os.path.join(self.scan_files_dir, self.scan_guid)
            
            print(f"[*] Copying local directory to: {self.work_dir}")
            
            try:
                shutil.copytree(self.target_path, self.work_dir, 
                              ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc', 'node_modules'))
                print(f"[+] Local directory copied successfully")
            except Exception as e:
                print(f"[-] Error copying directory: {e}")
                sys.exit(1)
    
    def setup_detect_secrets(self):
        """Make sure detect-secrets (1.5.0) is installed"""
        print(f"\n[*] Setting up detect-secrets...")
        result = subprocess.run(
            [sys.executable, '-m', 'detect_secrets', '--version'],
            capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            print(f"[+] detect-secrets installed: {result.stdout.strip()}")
            return
        print(f"[*] detect-secrets not found, installing detect-secrets==1.5.0 ...")
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', 'detect-secrets==1.5.0'],
                check=True, capture_output=True
            )
            print(f"[+] detect-secrets installed")
        except Exception as e:
            print(f"[-] Failed to install detect-secrets: {e}")
            print(f"[!] Please install manually: pip install detect-secrets==1.5.0")

    def run_detect_secrets(self):
        """Run detect-secrets tool"""
        print("\n[*] Starting detect-secrets scan...")

        env = os.environ.copy()
        patched_dir = os.path.join(self.tools_dir, 'detect-secrets-patched')
        use_patched = self.detect_secrets_variant == 'patched' and \
            os.path.exists(os.path.join(patched_dir, 'detect_secrets', '__init__.py'))
        if use_patched:
            env['PYTHONPATH'] = patched_dir + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
            print(f"[*] Using customised detect-secrets: {patched_dir}")
        else:
            if self.detect_secrets_variant == 'patched':
                print("[!] tools/detect-secrets-patched not found (run setup_patched_tools.py); using stock detect-secrets")
            print("[*] Using stock detect-secrets")

        try:
            if not os.path.exists(self.work_dir):
                raise RuntimeError(f"Target path ({self.work_dir}) does not exist")
            # Execute detect-secrets scan command with --all-files
            result = subprocess.run(
                [sys.executable, '-m', 'detect_secrets', 'scan', '--all-files', self.work_dir],
                capture_output=True,
                text=True,
                check=False,
                env=env
            )

            #print("STDOUT:", result.stdout)
            #print("STDERR:", result.stderr)
            
            if result.returncode == 0 or result.stdout:
                try:
                    secrets_data = json.loads(result.stdout)
                    findings = []
                    gtLines = None
                    
                    # Parse the results
                    results = secrets_data.get('results', {})
                    
                    if not results:
                        print(f"[+] detect-secrets: No findings detected")
                        return []
                    
                    for file_path, secrets in results.items():
                        # Get relative path - CRITICAL: normalize the path
                        relative_path = file_path
                        
                        # Try multiple methods to get clean relative path
                        if file_path.startswith(self.work_dir):
                            relative_path = os.path.relpath(file_path, self.work_dir)
                        elif 'scanfiles' in file_path:
                            # Extract path after scanfiles/guid/
                            parts = file_path.split(os.sep)
                            try:
                                scanfiles_idx = parts.index('scanfiles')
                                # Skip scanfiles and guid, get rest
                                relative_path = os.path.join(*parts[scanfiles_idx + 2:])
                            except (ValueError, IndexError):
                                relative_path = os.path.basename(file_path)
                        
                        # Normalize path separators
                        relative_path = relative_path.replace('\\', '/')
                        
                        # Read file content once for all secrets in this file
                        file_lines = []
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                file_lines = f.readlines()
                        except Exception as e:
                            print(f"[!] Could not read file for snippet: {relative_path}")
                        
                        if self.benchmark is True and gtLines is None:
                            gtLines = get_groundtruth_lines(self.benchmark_repo_id())

                        for secret in secrets:
                            line_number = secret.get('line_number', 0)

                            tmpGTLines = []
                            if self.benchmark is True:
                                tmpFilename = os.path.splitext(os.path.basename(secret.get('filename')))[0]
                                if tmpFilename in gtLines:
                                    tmpGTLines = gtLines[tmpFilename]
                                    if not line_number in tmpGTLines:
                                        continue
                            
                            # Get the line snippet
                            snippet = ""
                            if file_lines and 0 < line_number <= len(file_lines):
                                snippet = file_lines[line_number - 1].strip()[:100]
                            
                            findings.append({
                                'file': relative_path,
                                'type': secret.get('type', 'unknown'),
                                'line': line_number,
                                'tool': 'detect-secrets',
                                'snippet': snippet
                            })
                    
                    print(f"[+] detect-secrets: {len(findings)} findings detected")
                    return findings
                    
                except json.JSONDecodeError as e:
                    print(f"[-] JSON parse error: {e}")
                    print(f"[!] Raw output: {result.stdout[:200]}")
                    return []
            else:
                print(f"[-] detect-secrets error: {result.stderr}")
                return []
                
        except FileNotFoundError:
            print("[-] detect-secrets is not installed. Install with: pip install detect-secrets")
            return []
        except Exception as e:
            print(f"[-] detect-secrets execution error: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def run_codebert_scan(self):
        """Perform code scanning with CodeBERT using vector similarity"""
        print("\n[*] Starting CodeBERT vector-based scan...")
        
        try:
            from transformers import AutoTokenizer, AutoModel
            import torch
            import torch.nn.functional as F
            
            # Load CodeBERT model
            print(f"[*] Loading CodeBERT model...")
            model_name = os.environ.get("CODEBERT_MODEL", "microsoft/codebert-base")
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)
            model.eval()
            print(f"[+] CodeBERT model loaded successfully")
            
            # Load DENYLIST patterns from keyword.py
            denylist_patterns = self.load_denylist_from_keyword_plugin()
            ignore_extensions = self.load_ignorelist_from_heuristic_filter()
            print(f"[*] Using {len(denylist_patterns)} keyword patterns for analysis")
            
            findings = []
            
            # File extensions to scan
            extensions = ['.py', '.js', '.java', '.go', '.rb', '.php', '.ts', '.jsx', '.tsx', 
                         '.c', '.cpp', '.h', '.cs', '.swift', '.kt', '.scala', '.rs',
                         '.yml', '.yaml', '.json', '.xml', '.properties', '.env', '.config', '.md']
            
            # Assignment operators to detect
            assignment_patterns = [
                r'=',           # Simple assignment
                r':',           # YAML/JSON style
                r'=>',          # Arrow function style
                r'<-',          # Go style
                r':=',          # Go/Pascal style
            ]
            
            files_scanned = 0
            lines_analyzed = 0
            gt_all = None
            
            # Pre-compute embeddings for denylist keywords
            print(f"[*] Computing embeddings for {len(denylist_patterns)} keywords...")
            keyword_embeddings = {}
            
            with torch.no_grad():
                for keyword in denylist_patterns:
                    try:
                        # Tokenize the keyword
                        inputs = tokenizer(keyword, return_tensors='pt', padding=True, truncation=True, max_length=512)
                        outputs = model(**inputs)
                        # Use mean pooling of last hidden state
                        embedding = outputs.last_hidden_state.mean(dim=1)
                        keyword_embeddings[keyword] = embedding
                    except Exception as e:
                        continue
            
            print(f"[+] Computed embeddings for {len(keyword_embeddings)} keywords")
            
            for root, dirs, files in os.walk(self.work_dir):
                # Skip common directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build']]
                
                
                for file in files:
                    if any(file.endswith(ext) for ext in ignore_extensions):
                        continue
                    #if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    files_scanned += 1

                    if self.benchmark is True:
                        if gt_all is None:
                            gt_all = get_groundtruth_lines(self.benchmark_repo_id())
                        gtLines = gt_all
                        if len(gtLines) == 0:
                            continue
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                        
                        relative_path = os.path.relpath(file_path, self.work_dir)
                        
                        for line_num, line in enumerate(lines, 1):
                            line_stripped = line.strip()
                            
                            # Skip empty lines, comments, and imports
                            if not line_stripped or \
                                line_stripped.startswith(('#', '//', '/*', '*', '<!--', 'import ', 'from ', 'using ')):
                                continue
                            
                            # Check if line contains assignment or definition
                            has_assignment = any(op in line for op in assignment_patterns)
                            
                            if not has_assignment:
                                continue
                            
                            # Extract value after assignment operator
                            value_after_assignment = None
                            for op in assignment_patterns:
                                if op in line:
                                    parts = line.split(op, 1)
                                    if len(parts) > 1:
                                        value_after_assignment = parts[1].strip()
                                        break
                            
                            # Skip if no value after assignment or value is empty/whitespace
                            if not value_after_assignment:
                                continue
                            
                            # Skip if value is only quotes with whitespace: "", '', ``, "  ", '  ', etc.
                            stripped_value = value_after_assignment.strip('"\'` \t\n\r;,')
                            if not stripped_value:
                                continue
                            
                            # Skip if value is just null, undefined, None, nil, etc.
                            if stripped_value.lower() in ['null', 'undefined', 'none', 'nil', 'nan', 'false', 'true']:
                                continue
                            
                            # Check if value is in quotes (string literal) or is numeric
                            has_quotes = any(q in value_after_assignment for q in ['"', "'", '`'])
                            
                            # Check if it's a numeric value
                            is_numeric = False
                            try:
                                # Try to parse as number (int or float)
                                float(stripped_value.rstrip(';,'))
                                is_numeric = True
                            except (ValueError, AttributeError):
                                pass
                            
                            # Skip if value is not in quotes and not numeric
                            # (e.g., variable references, function calls, etc.)
                            if not has_quotes and not is_numeric:
                                continue
                            
                            lines_analyzed += 1
                            
                            # Tokenize and get embedding for the line
                            try:
                                with torch.no_grad():
                                    inputs = tokenizer(
                                        line_stripped,
                                        return_tensors='pt',
                                        padding=True,
                                        truncation=True,
                                        max_length=512
                                    )
                                    outputs = model(**inputs)
                                    line_embedding = outputs.last_hidden_state.mean(dim=1)
                                
                                # Score of the line = maximum similarity over all keywords
                                best_keyword, similarity = None, -1.0
                                for keyword, keyword_embedding in keyword_embeddings.items():
                                    sim = F.cosine_similarity(line_embedding, keyword_embedding).item()
                                    if sim > similarity:
                                        best_keyword, similarity = keyword, sim

                                if best_keyword is not None and similarity >= self.similarity_threshold:
                                    if self.benchmark is True:
                                        tmpFilename = os.path.splitext(os.path.basename(relative_path))[0]
                                        if tmpFilename in gtLines and line_num not in gtLines[tmpFilename]:
                                            continue

                                    findings.append({
                                        'file': relative_path,
                                        'type': f'vector_match_{best_keyword}',
                                        'line': line_num,
                                        'tool': 'codebert',
                                        'similarity': round(similarity, 4),
                                        'matched_keyword': best_keyword,
                                        'snippet': line_stripped[:100]
                                    })

                            except Exception as e:
                                continue
                                
                    except Exception as e:
                        continue
            
            print(f"[+] CodeBERT: Scanned {files_scanned} files, analyzed {lines_analyzed} lines with assignments")
            print(f"[+] CodeBERT: {len(findings)} findings detected")
            return findings
            
        except ImportError:
            print("[-] transformers or torch not installed.")
            print("    Install with: pip install transformers torch")
            return []
        except Exception as e:
            print(f"[-] CodeBERT execution error: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_code_context(self, file_path, line_number, context_lines):
        """Get code context around a specific line"""
        try:
            full_path = os.path.join(self.work_dir, file_path)
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            context = []
            if context_lines == 0:
                #print(lines[line_number - 1].rstrip() + "\n")
                #marker = ">>> "
                #context.append(f"{marker}{line_number}: {lines[line_number - 1].rstrip()}")
                context.append(f"{lines[line_number - 1].rstrip()}")
                return "\n".join(context)
            
            # Calculate start and end indices
            start_idx = max(0, line_number - context_lines - 1)
            end_idx = min(len(lines), line_number + context_lines)
            
            # Get context lines with line numbers            
            for i in range(start_idx, end_idx):
                line_num = i + 1
                marker = ">>> " if line_num == line_number else "    "
                context.append(f"{marker}{line_num}: {lines[i].rstrip()}")
            
            return "\n".join(context)
        except Exception as e:
            return f"Error reading file: {e}"
    
    def query_llm(self, finding, context):
        """Query LLM to determine if finding is a false positive"""
        prompt = f"""You are a senior security expert analyzing potential secrets in source code.

CODE CONTEXT:
The following content is raw source code.
It is NOT JSON and may contain syntax that is invalid in JSON.
Do NOT attempt to parse it as JSON.
Analyze it only as code text.

{context}

TASK:
Determine whether the detected item represents a real secret/credential that should be flagged, or a false positive.

MANDATORY DECISION RULES:
- A secret MUST contain sensitive secret material (e.g. tokens, passwords, keys).
- Configuration or metadata values are NOT secrets.
- Numeric values alone (e.g. lengths, sizes, iteration counts) are NEVER secrets.
- Fields describing cryptographic parameters are NOT secrets, including but not limited to:
  keyLength, keySize, saltLength, iterations, rounds, costFactor, algorithm, cipher, hash.

SEMANTIC CONTEXT RULES:
- Do NOT flag items that describe HOW a secret is generated or used.
- ONLY flag items that contain the secret value itself.

OBFUSCATION & ENTROPY:
- Entropy analysis applies ONLY if an actual value is present.
- High entropy heuristics MUST NOT be applied to numeric or configuration-only fields.

QUESTION:
Is this a real secret/credential that should be flagged, or is it a false positive?

Respond in JSON format:
{{
  "is_false_positive": true/false,
  "confidence": "high/medium/low",
  "reason": "Brief explanation"
}}"""

        try:
            if self.llm_provider == 'gemini':
                return self.query_gemini(prompt)
            elif self.llm_provider == 'openai':
                return self.query_openai(prompt)
            else:
                return {
                    "is_false_positive": False,
                    "confidence": "low",
                    "reason": "Unknown LLM provider"
                }
        except Exception as e:
            print(f"[-] LLM query error: {e}")
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": f"LLM error: {str(e)}"
            }
    
    def query_gemini(self, prompt):
        """Query Google Gemini API"""
        try:
            from google import genai
            
            api_key = self.api_keys.get('gemini', '')
            if not api_key or api_key == 'YOUR_GEMINI_API_KEY_HERE':
                return {
                    "is_false_positive": False,
                    "confidence": "low",
                    "reason": "Gemini API key not configured"
                }
            
            client = genai.Client(api_key=api_key)
            #gemini-1.5-flash
            response = client.models.generate_content(
            model="gemini-2.0-flash-001",
            contents=prompt
            )
            response_text = response.text
            
            parsed = parse_llm_json(response_text)
            if parsed:
                return parsed
            
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": "Could not parse Gemini response"
            }
        except ImportError:
            print("[-] google-generativeai not installed. Install with: pip install google-generativeai")
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": "Gemini SDK not installed"
            }
        except Exception as e:
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": f"Gemini error: {str(e)}"
            }
    
    def query_openai(self, prompt):
        """Query OpenAI ChatGPT API"""
        try:
            from openai import OpenAI
            
            api_key = self.api_keys.get('openai', '')
            if not api_key or api_key == 'YOUR_OPENAI_API_KEY_HERE':
                return {
                    "is_false_positive": False,
                    "confidence": "low",
                    "reason": "OpenAI API key not configured"
                }
            
            client = OpenAI(api_key=api_key)
            #gpt-4
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing code for secrets."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            
            response_text = response.choices[0].message.content
            
            parsed = parse_llm_json(response_text)
            if parsed:
                return parsed
            
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": "Could not parse OpenAI response"
            }
        except ImportError:
            print("[-] openai not installed. Install with: pip install openai")
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": "OpenAI SDK not installed"
            }
        except Exception as e:
            return {
                "is_false_positive": False,
                "confidence": "low",
                "reason": f"OpenAI error: {str(e)}"
            }
    
    def analyze_with_llm(self, merged_results, detect_secrets_results):
        """Analyze merged results with LLM"""
        print(f"\n[*] Analyzing findings with {self.llm_provider.upper()}...")
        
        llm_analyzed_results = []
        false_positives = 0
        detect_secrets_fp = 0
        
        # Track which detect-secrets findings are marked as FP
        detect_secrets_lines = {(r['file'], r['line']) for r in detect_secrets_results}
        
        for i, finding in enumerate(merged_results, 1):
            print(f"[*] Analyzing {i}/{len(merged_results)}: {finding['file']}:{finding['line']}")
            
            # Get code context
            context = self.get_code_context(
                finding['file'],
                finding['line'],
                self.context_lines
            )

            """print("-"*20)
            print(context)
            print("-"*20)"""
            
            # Query LLM
            llm_result = self.query_llm(finding, context)
            
            # Add LLM analysis to finding
            analyzed_finding = {
                **finding,
                'llm_analysis': {
                    'provider': self.llm_provider,
                    'is_false_positive': llm_result.get('is_false_positive', False),
                    'confidence': llm_result.get('confidence', 'low'),
                    'reason': llm_result.get('reason', ''),
                    'context_used': context
                }
            }
            
            llm_analyzed_results.append(analyzed_finding)
            
            is_fp = llm_result.get('is_false_positive', False)
            if is_fp:
                false_positives += 1
                # Check if this was also found by detect-secrets
                key = (finding['file'], finding['line'])
                if key in detect_secrets_lines:
                    detect_secrets_fp += 1
        
        print(f"[+] LLM Analysis complete: {false_positives}/{len(merged_results)} flagged as false positives")
        
        return llm_analyzed_results, false_positives, detect_secrets_fp
    
    def merge_results(self, detect_secrets_results, codebert_results):
        """Merge results from both scans and remove duplicates"""
        print("\n[*] Merging results...")
        
        # Normalize all file paths first
        def normalize_path(path):
            """Normalize path to use forward slashes"""
            return path.replace('\\', '/')
        
        # Use dictionary to merge by (normalized_file, line)
        merged_dict = {}
        
        # Process detect-secrets results
        for result in detect_secrets_results:
            # Normalize the file path
            normalized_file = normalize_path(result['file'])
            key = (normalized_file, result['line'])
            
            if key not in merged_dict:
                merged_dict[key] = {
                    'file': normalized_file,
                    'line': result['line'],
                    'tools': ['detect-secrets'],
                    'types': {
                        'detect-secrets': result['type']
                    },
                    'snippet': result.get('snippet', ''),
                    'details': {
                        'detect-secrets': {
                            'type': result['type']
                        }
                    }
                }
            else:
                # Duplicate in detect-secrets (shouldn't happen)
                print(f"[!] Duplicate in detect-secrets: {normalized_file}:{result['line']}")
        
        # Process CodeBERT results
        for result in codebert_results:
            # Normalize the file path
            normalized_file = normalize_path(result['file'])
            key = (normalized_file, result['line'])
            
            if key in merged_dict:
                # Both tools found the same line - merge them
                if 'codebert' not in merged_dict[key]['tools']:
                    merged_dict[key]['tools'].append('codebert')
                merged_dict[key]['types']['codebert'] = result['type']
                merged_dict[key]['details']['codebert'] = {
                    'type': result['type'],
                    'similarity': result.get('similarity', 0),
                    'matched_keyword': result.get('matched_keyword', '')
                }
                # Update snippet if detect-secrets snippet was empty
                if not merged_dict[key]['snippet'] and result.get('snippet'):
                    merged_dict[key]['snippet'] = result.get('snippet', '')
            else:
                # Only CodeBERT found this
                merged_dict[key] = {
                    'file': normalized_file,
                    'line': result['line'],
                    'tools': ['codebert'],
                    'types': {
                        'codebert': result['type']
                    },
                    'snippet': result.get('snippet', ''),
                    'details': {
                        'codebert': {
                            'type': result['type'],
                            'similarity': result.get('similarity', 0),
                            'matched_keyword': result.get('matched_keyword', '')
                        }
                    }
                }
        
        # Convert to list and sort
        all_results = list(merged_dict.values())
        all_results.sort(key=lambda x: (x['file'], x['line']))
        
        # Count by tool combination
        both_tools = sum(1 for r in all_results if len(r['tools']) > 1)
        only_detect_secrets = sum(1 for r in all_results if len(r['tools']) == 1 and 'detect-secrets' in r['tools'])
        only_codebert = sum(1 for r in all_results if len(r['tools']) == 1 and 'codebert' in r['tools'])
        
        print(f"[+] Total {len(all_results)} unique findings detected")
        print(f"    - Found by both tools: {both_tools}")
        print(f"    - Found only by detect-secrets: {only_detect_secrets}")
        print(f"    - Found only by CodeBERT: {only_codebert}")
        
        return all_results
    
    def log(self, message, file_handle) -> None:
        print(message)
        file_handle.write(message + "\n")

    
    def save_results(self, detect_secrets_results, codebert_results, merged_results, llm_analyzed_results, stats):
        """Save results to separate JSON files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Metadata for all reports
        metadata = {
            'scan_guid': self.scan_guid,
            'scan_target': self.target_path,
            'scan_directory': self.work_dir,
            'timestamp': timestamp,
            'is_repository': self.is_repo,
            'llm_enabled': self.use_llm
        }
        
        if self.use_llm:
            metadata['llm_provider'] = self.llm_provider
            metadata['context_lines'] = self.context_lines
        
        # Save detect-secrets results
        detect_secrets_file = os.path.join(self.results_dir, 'detect-secrets.json')
        detect_secrets_report = {
            **metadata,
            'tool': 'detect-secrets',
            'total_findings': len(detect_secrets_results),
            'findings': detect_secrets_results
        }
        
        with open(detect_secrets_file, 'w', encoding='utf-8') as f:
            json.dump(detect_secrets_report, f, indent=2, ensure_ascii=False)
        print(f"\n[+] detect-secrets results saved: {detect_secrets_file}")
        
        # Save CodeBERT results
        codebert_file = os.path.join(self.results_dir, 'codebert.json')
        codebert_report = {
            **metadata,
            'tool': 'codebert',
            'total_findings': len(codebert_results),
            'findings': codebert_results
        }
        
        with open(codebert_file, 'w', encoding='utf-8') as f:
            json.dump(codebert_report, f, indent=2, ensure_ascii=False)
        print(f"[+] CodeBERT results saved: {codebert_file}")
        
        # Save merged results
        merged_file = os.path.join(self.results_dir, 'merged.json')
        merged_report = {
            **metadata,
            'tool': 'merged (detect-secrets + codebert)',
            'total_findings': len(merged_results),
            'detect_secrets_count': len(detect_secrets_results),
            'codebert_count': len(codebert_results),
            'findings': merged_results
        }
        
        with open(merged_file, 'w', encoding='utf-8') as f:
            json.dump(merged_report, f, indent=2, ensure_ascii=False)
        print(f"[+] Merged results saved: {merged_file}")
        
        # Only save LLM-related files if LLM was used
        if self.use_llm and not self.no_llm and llm_analyzed_results:
            # Filter only true positives for final output
            true_positive_findings = [
                f for f in llm_analyzed_results 
                if not f['llm_analysis']['is_false_positive']
            ]
            
            # Save final true positives
            final_file = os.path.join(self.results_dir, 'final-true-positives.json')
            final_report = {
                **metadata,
                'tool': f'final-verified-by-{self.llm_provider}',
                'total_findings': len(true_positive_findings),
                'findings': true_positive_findings
            }
            
            with open(final_file, 'w', encoding='utf-8') as f:
                json.dump(final_report, f, indent=2, ensure_ascii=False)
            print(f"[+] Final true positives saved: {final_file}")
            
            # Save LLM analyzed results (all findings with LLM analysis)
            llm_file = os.path.join(self.results_dir, 'llm-analyzed-all.json')
            llm_report = {
                **metadata,
                'tool': f'llm-analyzed-all ({self.llm_provider})',
                'total_findings': len(llm_analyzed_results),
                'findings': llm_analyzed_results
            }
            
            with open(llm_file, 'w', encoding='utf-8') as f:
                json.dump(llm_report, f, indent=2, ensure_ascii=False)
            print(f"[+] LLM analyzed (all) results saved: {llm_file}")
        
        # Save statistics report
        stats_file = os.path.join(self.results_dir, 'statistics.json')
        stats_report = {
            **metadata,
            'statistics': stats
        }
        
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats_report, f, indent=2, ensure_ascii=False)
        print(f"[+] Statistics saved: {stats_file}")

        summary_file_path = os.path.join(self.results_dir, "scan_summary.txt")

        with open(summary_file_path, "a", encoding="utf-8") as f:        
            # Print summary to console
            self.log("\n" + "="*80, f)
            self.log("SCAN RESULTS SUMMARY", f)
            self.log("="*80, f)
            self.log(f"Scan GUID: {self.scan_guid}", f)
            self.log(f"Target: {self.target_path}", f)
            #self.log(f"Scan Directory: {self.work_dir}", f)

            # 1. Initial detection results
            self.log(f"\n1. Initial Detection Results:", f)
            self.log(f"   - detect-secrets found: {stats['detect_secrets_findings']} findings", f)
            self.log(f"   - CodeBERT found: {stats['codebert_findings']} findings", f)

            # 2. Merged results showing overlap
            self.log(f"\n2. Merged Results (Overlap Analysis):", f)
            self.log(f"   - Total unique findings: {stats['total_merged_findings']}", f)
            self.log(f"   - Found by BOTH tools: {stats['found_by_both']} findings", f)
            self.log(f"   - Found ONLY by detect-secrets: {stats['found_by_detect_secrets_only']} findings", f)
            self.log(f"   - Found ONLY by CodeBERT: {stats['found_by_codebert_only']} findings", f)
            
            if self.use_llm and not self.no_llm:
                self.log(f"\n3. LLM Analysis Results ({self.llm_provider.upper()}):", f)
                self.log(f"   - Total False Positives: {stats['llm_total_false_positives']} findings ({stats['llm_overall_fp_rate']}%)", f)
                self.log(f"   - Total True Positives: {stats['llm_total_true_positives']} findings", f)
                
                self.log(f"\n4. LLM False Positive Breakdown by Tool:", f)
                self.log(f"   - detect-secrets findings marked as FP: {stats['llm_detect_secrets_fp']}/{stats['detect_secrets_findings']} ({stats['llm_detect_secrets_fp_rate']}%)", f)
                self.log(f"   - CodeBERT findings marked as FP: {stats['llm_codebert_fp']}/{stats['codebert_findings']} ({stats['llm_codebert_fp_rate']}%)", f)
            
            self.log(f"\n" + "="*80, f)
    
    def cleanup(self):
        """Clean up temporary files"""
        # Note: We keep scanfiles for inspection, only clean if explicitly needed
        print(f"\n[*] Scan files preserved at: {self.work_dir}")
        print(f"[!] To clean up, manually delete the 'scanfiles' directory")
    
    def scan(self):
        """Main scanning function"""
        try:
            # 1. Setup environment
            self.setup_environment()
            
            # 2. detect-secrets scan
            detect_secrets_results = self.run_detect_secrets()
            
            # 3. CodeBERT scan
            codebert_results = self.run_codebert_scan()
            
            # 4. Merge results
            merged_results = self.merge_results(detect_secrets_results, codebert_results)
            
            # Calculate merge statistics - identify overlap between tools
            both_tools = sum(1 for r in merged_results if len(r['tools']) > 1)
            only_detect_secrets = sum(1 for r in merged_results if len(r['tools']) == 1 and 'detect-secrets' in r['tools'])
            only_codebert = sum(1 for r in merged_results if len(r['tools']) == 1 and 'codebert' in r['tools'])
            
            # 5. Analyze with LLM (if enabled)
            llm_analyzed_results = []
            total_fp = 0
            total_tp = 0
            detect_secrets_fp = 0
            codebert_fp = 0
            
            if not self.no_llm:
                # Run LLM analysis
                llm_analyzed_results, total_fp, detect_secrets_fp = self.analyze_with_llm(
                    merged_results, 
                    detect_secrets_results
                )
                
                # Calculate CodeBERT false positives
                # Create set of CodeBERT findings for lookup
                codebert_lines = {(r['file'], r['line']) for r in codebert_results}
                for finding in llm_analyzed_results:
                    key = (finding['file'], finding['line'])
                    # If this finding is flagged as FP by LLM and was found by CodeBERT
                    if finding['llm_analysis']['is_false_positive'] and key in codebert_lines:
                        codebert_fp += 1
                
                # Calculate true positives (total - false positives)
                total_tp = len(merged_results) - total_fp
            else:
                # No LLM analysis - all findings considered as potential true positives
                total_tp = len(merged_results)
            
            # 6. Calculate comprehensive statistics with rates
            # False positive rates for each tool
            detect_secrets_fp_rate = (detect_secrets_fp / len(detect_secrets_results) * 100) if len(detect_secrets_results) > 0 else 0
            codebert_fp_rate = (codebert_fp / len(codebert_results) * 100) if len(codebert_results) > 0 else 0
            overall_fp_rate = (total_fp / len(merged_results) * 100) if len(merged_results) > 0 else 0
            
            stats = {
                # Initial detection counts
                'detect_secrets_findings': len(detect_secrets_results),
                'codebert_findings': len(codebert_results),
                
                # Overlap analysis
                'found_by_both': both_tools,
                'found_by_detect_secrets_only': only_detect_secrets,
                'found_by_codebert_only': only_codebert,
                'total_merged_findings': len(merged_results),
                
                # LLM analysis results
                'llm_total_false_positives': total_fp,
                'llm_total_true_positives': total_tp,
                
                # Tool-specific false positives with rates
                'llm_detect_secrets_fp': detect_secrets_fp,
                'llm_detect_secrets_fp_rate': round(detect_secrets_fp_rate, 2),
                'llm_codebert_fp': codebert_fp,
                'llm_codebert_fp_rate': round(codebert_fp_rate, 2),
                
                # Overall false positive rate
                'llm_overall_fp_rate': round(overall_fp_rate, 2)
            }
            
            # 7. Save all results
            self.save_results(detect_secrets_results, codebert_results, merged_results, 
                            llm_analyzed_results, stats)
            
        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description='Hafiye - secret detection with detect-secrets, CodeBERT and LLM verification'
    )
    parser.add_argument(
        'target',
        help='Local directory path or GitHub repository URL to scan'
    )
    parser.add_argument(
        '--similarity-threshold',
        type=float,
        default=0.85,
        help='Similarity threshold for CodeBERT vector matching (default: 0.85)'
    )
    parser.add_argument(
        '--llm-provider',
        choices=['gemini', 'openai'],
        default='openai',
        help='LLM provider for false positive analysis (default: openai)'
    )
    parser.add_argument(
        '--no-llm', 
        action='store_true',
        default=False,
        help='Disable LLM-based false positive analysis'
    )
    parser.add_argument(
        '--benchmark', 
        action='store_true',
        default=False,
        help='Test benchmark for Samsung/CredData for GroundTruth is T Lines.'
    )
    parser.add_argument(
        '--detect-secrets',
        choices=['patched', 'stock'],
        default='patched',
        help='detect-secrets variant: customised (built by setup_patched_tools.py) or stock (default: patched)'
    )
    parser.add_argument(
        '--context-lines',
        type=int,
        default=0,
        help='Number of context lines before/after findings (default: 0)'
    )
    
    args = parser.parse_args()
    
    # Print project header
    print_header()
    
    # Check if it's a GitHub repo or local path
    is_repo = args.target.startswith('http://') or args.target.startswith('https://')
    
    print("="*60)
    print("STARTING SCAN")
    print("="*60)
    
    scanner = SecretScanner(
        args.target,
        is_repo=is_repo,
        similarity_threshold=args.similarity_threshold,
        llm_provider=args.llm_provider,
        context_lines=args.context_lines,
        no_llm=args.no_llm,
        benchmark=args.benchmark,
        detect_secrets_variant=args.detect_secrets
    )
    scanner.scan()
    
    print("\n[+] Scan completed!")
    print(f"[*] Scan GUID: {scanner.scan_guid}")
    print(f"[*] Results directory: {scanner.results_dir}")
    print(f"[*] Scan files directory: {scanner.work_dir}")


if __name__ == '__main__':
    main()