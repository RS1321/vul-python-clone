"""
Security Fix Pipeline

Orchestrates the complete vulnerability fixing workflow:
1. Load filtered findings
2. Create branch
3. For each finding:
   - Generate fix with LLM
   - Apply fix with AST
   - Commit
   - Validate (pylint + pytest)
   - Retry if validation fails
4. Push branch to GitHub
5. Trigger SAST scan and validate fixes
"""

import json
import subprocess
import sys
import tempfile
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import os
import shutil
import importlib

from llm_client import create_llm_client
from getFindingContext import get_findings_metadata_only, refresh_finding_code
from codePatcherAST import CodePatcher
from validators.linter import PylintValidator
from validators.tests import PytestValidator
# Note: prompts module will be dynamically imported based on config
from github_integration import GitHubIntegration, compare_sarif_findings
from metrics import MetricsCollector
from summary_generator import SummaryGenerator
from evaluation import PipelineEvaluator
from minimality_validator import validate_fix_minimality, generate_minimality_retry_instruction, calculate_churn_reduction_ratio
from code_repair import repair_code
from conversation_logger import ConversationLogger
from console_logger import ConsoleLogger


class PylintScoreTracker:
    """Track pylint scores throughout the pipeline"""
    
    def __init__(self, branch_name: str):
        """Initialize score tracker"""
        self.branch_name = branch_name
        self.scores = []  # List of (fix_number, score, description)
        
        # Create reports directory
        reports_dir = Path(__file__).parent.parent / 'reports' / branch_name
        reports_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = reports_dir
        self.json_file = reports_dir / 'pylint_scores.json'
        self.csv_file = reports_dir / 'pylint_scores.csv'
    
    def record_baseline(self, score: float):
        """Record baseline score before any fixes"""
        self.scores.append({
            'fix_number': 0,
            'score': score,
            'finding_id': 'Baseline',
            'description': 'Baseline (before fixes)'
        })
        print(f"    📊 Baseline pylint score: {score:.2f}/10.00")
    
    def record_fix(self, fix_number: int, score: float, finding_id: str):
        """Record score after a fix"""
        self.scores.append({
            'fix_number': fix_number,
            'score': score,
            'finding_id': finding_id,
            'description': f'Fix applied ({finding_id})'
        })
        print(f"    📊 Pylint score after fix {fix_number}: {score:.2f}/10.00")
    
    def finalize(self):
        """Save scores to JSON and CSV formats"""
        if len(self.scores) < 2:
            return
        
        # Save JSON format
        self._save_json()
        
        # Save CSV format
        self._save_csv()
        
        print(f"    ✓ Pylint scores saved: TXT, JSON, CSV")
    
    def _save_json(self):
        """Save scores to JSON format"""
        if not self.scores:
            return
        
        data = {
            'branch_name': self.branch_name,
            'baseline_score': self.scores[0]['score'],
            'final_score': self.scores[-1]['score'],
            'score_change': self.scores[-1]['score'] - self.scores[0]['score'],
            'total_fixes': len(self.scores) - 1,
            'scores': self.scores
        }
        
        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def _save_csv(self):
        """Save scores to CSV format"""
        if not self.scores:
            return
        
        with open(self.csv_file, 'w', encoding='utf-8', newline='') as f:
            f.write("fix_number,score,finding_id,description\n")
            for entry in self.scores:
                f.write(f"{entry['fix_number']},{entry['score']:.2f},{entry['finding_id']},{entry['description']}\n")


class CoverageTracker:
    """Tracks pytest coverage % across finding fixes (mirrors PylintScoreTracker)"""

    def __init__(self, branch_name: str):
        report_dir = Path(__file__).parent / 'reports' / branch_name
        report_dir.mkdir(parents=True, exist_ok=True)
        self.branch_name = branch_name
        self.json_file = report_dir / 'coverage_scores.json'
        self.csv_file = report_dir / 'coverage_scores.csv'
        self.scores: list = []

    def record_baseline(self, coverage_percent: float):
        self.scores.append({
            'fix_number': 0, 'score': coverage_percent,
            'finding_id': 'baseline', 'description': 'Baseline coverage'
        })

    def record_fix(self, fix_number: int, coverage_percent: float,
                   finding_id: str = '', description: str = ''):
        self.scores.append({
            'fix_number': fix_number, 'score': coverage_percent,
            'finding_id': finding_id,
            'description': description or f'Fix {fix_number}'
        })

    def finalize(self):
        if not self.scores:
            return
        self._save_json()
        self._save_csv()
        print(f"    \u2713 Coverage scores saved: JSON, CSV")

    def _save_json(self):
        if not self.scores:
            return
        data = {
            'branch_name': self.branch_name,
            'baseline_score': self.scores[0]['score'],
            'final_score': self.scores[-1]['score'],
            'score_change': self.scores[-1]['score'] - self.scores[0]['score'],
            'total_fixes': len(self.scores) - 1,
            'scores': self.scores
        }
        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def _save_csv(self):
        if not self.scores:
            return
        with open(self.csv_file, 'w', encoding='utf-8', newline='') as f:
            f.write("fix_number,score,finding_id,description\n")
            for entry in self.scores:
                f.write(f"{entry['fix_number']},{entry['score']:.2f},{entry['finding_id']},{entry['description']}\n")


class FixPipeline:
    """Main pipeline for fixing vulnerabilities"""
    
    def __init__(self, config_path: str = "config.json", finding_ids: Optional[list] = None, create_pr: bool = True, run_sast: bool = True, run_dast: bool = True):
        """
        Initialize pipeline
        
        Args:
            config_path: Path to configuration file
            finding_ids: Optional list of specific finding IDs to process
            create_pr: Whether to create pull request (default: True)
        """
        # Load configuration
        script_dir = Path(__file__).parent
        with open(script_dir / config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        # Dynamically import prompts module based on config
        prompts_module_name = self.config.get('pipeline', {}).get('prompts_module', 'prompts')
        if prompts_module_name != 'factorial_prompts':
            raise ValueError('This revision requires prompts_module=factorial_prompts; use the pinned upstream commit to reproduce older prompt variants')
        print(f"📦 Loading prompts module: {prompts_module_name}")
        try:
            prompts_module = importlib.import_module(prompts_module_name)
            self.build_initial_fix_prompt = prompts_module.build_initial_fix_prompt
            self.build_refinement_prompt = prompts_module.build_refinement_prompt
            self.SYSTEM_PROMPT = prompts_module.SYSTEM_PROMPT
            print(f"   ✓ Successfully loaded prompts from '{prompts_module_name}'")
        except ImportError as e:
            print(f"   ⚠ Failed to import '{prompts_module_name}': {e}")
            print(f"   ⚠ Falling back to default 'prompts' module")
            import prompts as prompts_module
            self.build_initial_fix_prompt = prompts_module.build_initial_fix_prompt
            self.build_refinement_prompt = prompts_module.build_refinement_prompt
            self.SYSTEM_PROMPT = prompts_module.SYSTEM_PROMPT
        
        # Store flags
        self.create_pr = create_pr
        self.run_sast = run_sast
        self.run_dast = run_dast
        
        # Loggers and trackers will be initialized after branch creation
        self.conversation_logger = None
        self.console_logger = None
        self.pylint_tracker = None
        self.coverage_tracker = None
        
        # Initialize LLM client (will be recreated with logger after branch creation)
        self.llm_client = create_llm_client(self.config)
        self.repo_path = Path(script_dir / self.config['repository']['local_path']).resolve()
        
        # Ensure repository exists (clone if needed) before initializing CodePatcher
        self._ensure_repo_exists()
        
        self.code_patcher = CodePatcher(str(self.repo_path))
        self.pylint_validator = PylintValidator(self.config['pipeline']['min_pylint_score'])
        self.pytest_validator = PytestValidator()
        
        # Pipeline settings
        self.max_findings = self.config['pipeline']['max_findings_to_fix']
        self.max_attempts = self.config['pipeline']['max_fix_attempts']
        
        # Statistics
        self.stats = {
            'total_findings': 0,
            'fixed_successfully': 0,
            'failed': 0,
            'skipped': 0,
            'validated_by_sast': 0,
            'failed_sast_validation': 0,
            'minimality_retries': 0,
            'minimality_retry_rate': 0.0,
            'avg_initial_churn': 0.0,
            'avg_final_churn': 0.0,
            'by_cwe': {}  # CWE-specific minimality stats
        }
        
        # Store SARIF comparison for evaluator
        self.sarif_comparison = None
        
        # GitHub integration
        github_repo = os.getenv('GITHUB_REPO')
        self.github = GitHubIntegration(github_repo) if github_repo else None
        
        # Store fixed findings for validation with metadata
        self.fixed_findings = []  # List of finding dicts
        self.finding_metadata = {}  # Map finding_id -> (finding_number, metrics)
        self.all_attempts_logs = []  # Store all attempts for minimality analysis
        self.fixed_functions = set()  # Track (file_path, function_name) tuples for deduplication
        
        # Metrics tracking
        self.branch_name: Optional[str] = None
        self.metrics_collector: Optional[MetricsCollector] = None
        self.summary_generator: Optional[SummaryGenerator] = None
        
        # Optional finding ID filter
        self.finding_ids = finding_ids
    
    def _ensure_repo_exists(self):
        """
        Ensure repository exists, cloning if necessary.
        Called during initialization before CodePatcher is created.
        """
        if self.repo_path.exists():
            return  # Repository already exists
        
        repo_url = self.config['repository'].get('url')
        if not repo_url:
            print(f"\n❌ Repository does not exist at {self.repo_path} and no URL configured!")
            print(f"   Please add 'url' field to repository config or clone manually.")
            sys.exit(1)
        
        print(f"\n📦 Repository not found. Cloning from {repo_url}...")
        try:
            # Create parent directory if needed
            self.repo_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Clone repository
            subprocess.run(['git', 'clone', repo_url, str(self.repo_path)],
                          check=True, capture_output=True, text=True)
            print(f"  ✅ Repository cloned successfully to {self.repo_path}\n")
            
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Failed to clone repository: {e}")
            if e.stderr:
                print(f"     {e.stderr}")
            sys.exit(1)
    
    def _ensure_clean_repo(self):
        """Require a clean local checkout without discarding or fetching changes."""
        main_branch = self.config['repository']['main_branch']
        status = subprocess.run(['git', 'status', '--porcelain'], cwd=self.repo_path,
                                check=True, capture_output=True, text=True)
        if status.stdout.strip():
            raise RuntimeError('Target checkout has local changes; use a fresh disposable clone')
        subprocess.run(['git', 'checkout', main_branch], cwd=self.repo_path,
                       check=True, capture_output=True)
    
    def create_branch(self) -> str:
        """
        Create new branch for fixes
        
        Returns:
            Branch name
        """
        provider = self.llm_client.get_provider_name()
        model = self.llm_client.get_model_name()
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        branch_name = f"{provider}-{model}-{timestamp}"
        
        # Store branch name and initialize metrics collector
        self.branch_name = branch_name
        
        # Initialize loggers and trackers now that we have branch name
        self.conversation_logger = ConversationLogger(branch_name)
        print(f"✓ Conversation logging enabled: reports/{branch_name}/conversation.log")
        
        self.console_logger = ConsoleLogger(branch_name)
        print(f"✓ Console logging enabled: reports/{branch_name}/console.log")
        
        self.pylint_tracker = PylintScoreTracker(branch_name)
        print(f"✓ Pylint score tracking enabled: reports/{branch_name}/pylint_scores.json|csv")
        
        self.coverage_tracker = CoverageTracker(branch_name)
        print(f"✓ Coverage tracking enabled: reports/{branch_name}/coverage_scores.json|csv")
        
        # Copy artifacts to run folder for record keeping
        self._copy_artifacts_to_run_folder(branch_name)
        
        # Recreate LLM client with conversation logger
        self.llm_client = create_llm_client(self.config, self.conversation_logger)
        
        self.metrics_collector = MetricsCollector(branch_name)
        self.summary_generator = SummaryGenerator(self.llm_client, branch_name)
        
        print(f"\n🌿 Creating branch: {branch_name}")
        
        try:
            # CRITICAL: Ensure repo is completely clean before starting
            self._ensure_clean_repo()
            
            # Main branch is already checked out and clean from _ensure_clean_repo()
            main_branch = self.config['repository']['main_branch']
            
            # Create and checkout new branch
            subprocess.run(['git', 'checkout', '-b', branch_name], 
                          cwd=self.repo_path, check=True, capture_output=True)
            
            print(f"✅ Branch created: {branch_name} (clean state from {main_branch})")
            return branch_name
        
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to create branch: {e}")
            sys.exit(1)
    
    def _copy_artifacts_to_run_folder(self, branch_name: str):
        """
        Copy artifacts (filtered context, SARIF, DAST) to run folder for record keeping
        
        Args:
            branch_name: Branch name for organizing files
        """
        artifacts_dir = Path(__file__).parent.parent / 'artifacts'
        run_dir = Path(__file__).parent.parent / 'reports' / branch_name
        
        print(f"\n📋 Copying artifacts to run folder...")
        
        # Copy filtered context
        filtered_context_src = artifacts_dir / 'filtered_context.json'
        if filtered_context_src.exists():
            shutil.copy2(filtered_context_src, run_dir / 'filtered_context.json')
            print(f"  ✓ Copied filtered_context.json")
        else:
            print(f"  ⚠ Warning: filtered_context.json not found in artifacts")
        
        # Copy SARIF file (try branch-named first, then python-results.sarif)
        main_branch = self.config['repository']['main_branch']
        sarif_src = artifacts_dir / f"{main_branch}.sarif"
        if not sarif_src.exists():
            sarif_src = artifacts_dir / "python-results.sarif"
        
        if sarif_src.exists():
            shutil.copy2(sarif_src, run_dir / sarif_src.name)
            print(f"  ✓ Copied {sarif_src.name}")
        else:
            print(f"  ⚠ Warning: SARIF file not found in artifacts")
        
        # Copy DAST file
        dast_src = artifacts_dir / 'full-scan-report.json'
        if dast_src.exists():
            shutil.copy2(dast_src, run_dir / 'full-scan-report.json')
            print(f"  ✓ Copied full-scan-report.json")
        else:
            print(f"  ⚠ Warning: full-scan-report.json not found in artifacts")
        
        print(f"  ✓ Artifacts copied to reports/{branch_name}/")
    
    def _capture_baseline_pylint_score(self):
        """Capture baseline pylint score for the entire codebase"""
        print(f"\n📊 Capturing baseline pylint score...")
        
        try:
            # Run pylint on vulnerable_app.py only
            target_file = self.repo_path / 'vulnerable_app.py'
            result = subprocess.run(
                ['pylint', str(target_file), '--output-format=text'],
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=60
            )
            
            output = result.stdout + result.stderr
            
            # Extract score
            score_match = re.search(r'Your code has been rated at ([\-0-9.]+)/10', output)
            if score_match:
                score = float(score_match.group(1))
                self.pylint_tracker.record_baseline(score)
            else:
                print(f"  ⚠ Could not extract baseline pylint score")
        
        except subprocess.TimeoutExpired:
            print(f"  ⚠ Pylint baseline capture timed out")
        except Exception as e:
            print(f"  ⚠ Error capturing baseline: {e}")
    
    def _validate_security_fix(self, file_path: str, finding: Dict) -> tuple[bool, str]:
        """
        Validate that fixed file exists and is syntactically valid Python
        
        Security validation is delegated to:
        - Pylint (code quality)
        - Pytest (functionality)
        - SAST re-scanning (CodeQL)
        - DAST re-scanning (ZAP)
        
        Args:
            file_path: Path to fixed file (relative)
            finding: Finding dictionary with CWE info
        
        Returns:
            (passed: bool, message: str)
        """
        full_path = self.repo_path / file_path
        
        if not full_path.exists():
            return False, f"File not found: {file_path}"
        
        try:
            # Validate Python syntax
            with open(full_path, 'r', encoding='utf-8') as f:
                fixed_content = f.read()
            
            try:
                compile(fixed_content, str(full_path), 'exec')
            except SyntaxError as e:
                return False, f"Syntax error in fixed code: {e}"
            
            return True, "File syntax valid"
        
        except Exception as e:
            return False, f"Error during validation: {str(e)}"
    
    def commit_changes(self, finding_number: str, attempt: int, message: str) -> Optional[Dict[str, any]]:
        """
        Commit changes to git and return commit info
        
        Args:
            finding_number: Finding number (e.g., "001")
            attempt: Attempt number
            message: Additional commit message
        
        Returns:
            Dict with commit_sha, commit_message, lines_added, lines_removed, files_modified
        """
        commit_msg = f"{finding_number} - Attempt {attempt}: {message}"
        
        try:
            # Get diff stats before committing
            diff_result = subprocess.run(
                ['git', 'diff', '--numstat'],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            
            lines_added = 0
            lines_removed = 0
            files_modified = []
            
            for line in diff_result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        added = parts[0]
                        removed = parts[1]
                        filepath = parts[2]
                        
                        if added != '-':
                            lines_added += int(added)
                        if removed != '-':
                            lines_removed += int(removed)
                        files_modified.append(filepath)
            
            # Commit changes
            subprocess.run(['git', 'add', '-A'], cwd=self.repo_path, check=True, capture_output=True)
            subprocess.run(['git', 'commit', '-m', commit_msg], 
                          cwd=self.repo_path, check=True, capture_output=True)
            
            # Get commit SHA
            sha_result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            commit_sha = sha_result.stdout.strip()
            
            print(f"  ✓ Committed: {commit_msg}")
            
            return {
                'commit_sha': commit_sha,
                'commit_message': commit_msg,
                'lines_added': lines_added,
                'lines_removed': lines_removed,
                'files_modified': files_modified
            }
            
        except subprocess.CalledProcessError:
            print(f"  ⚠️  No changes to commit")
            return None
    
    def fix_finding(self, finding_details, finding_number):
        """Apply the same transactional engine used by local replication runs.

        Accepted patches remain distinct from security resolution, which requires
        a fresh scanner result. Every rejected candidate restores pre-finding bytes.
        """
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from review.runner import repair_one, test_run
        finding = finding_details['finding']
        location = finding['sast']['location']
        location['function'] = finding_details.get('function_name')
        if not location['function']:
            source = (self.repo_path / location['file_path']).read_text(encoding='utf-8')
            start, end = finding_details['start_line'], finding_details['end_line']
            finding['module_snapshot'] = '\n'.join(source.splitlines()[start - 1:end])
        validation = self.config['validation']
        test_policy = validation.get('test_policy', 'block')
        if test_policy not in ('monitor', 'block'):
            raise ValueError('test_policy must be monitor or block')
        enabled = [validation.get(k, True) for k in
                   ('run_pylint', 'run_pycompile', 'enforce_minimality')]
        if any(enabled) and not all(enabled):
            raise ValueError('Use an explicit condition: all three inline gates on, or all off')
        condition = dict(guidance=self.config['pipeline'].get('include_guidance', True),
                         examples=self.config['pipeline'].get('include_examples', True),
                         gates=all(enabled), attempts=self.max_attempts,
                         tests=test_policy)
        out = Path(__file__).resolve().parents[1] / 'review_results' / 'legacy' / str(time.time_ns())
        pytest_args = validation.get('pytest_args', ['tests', '-m', 'not network']) if validation.get('run_tests') else []
        if not isinstance(pytest_args, list) or any(not isinstance(arg, str) for arg in pytest_args):
            raise ValueError('pytest_args must be a list of project test arguments')
        baseline = test_run(self.repo_path, pytest_args, out / 'baseline-tests')
        library_path = Path(__file__).resolve().parent / self.config['pipeline'].get('guidance_library', 'guidance_library.review-2.json')
        prompt_library = json.loads(library_path.read_text(encoding='utf-8'))
        metrics = self.metrics_collector.start_finding(
            finding_number, finding.get('finding_id', ''),
            finding['sast'].get('rule_id', ''),
            finding.get('baseline_severity', 'unknown'), finding['sast'].get('cwe', ''))
        result = repair_one(self.repo_path, finding, condition, self.llm_client,
                            pytest_args, baseline, out, prompt_library=prompt_library)
        for attempt in result['attempts']:
            metrics.start_fix_attempt()
            response = attempt.get('response') or {}
            usage = response.get('usage') or {}
            if response:
                metrics.record_api_call(self.llm_client.provider, response.get('model', self.llm_client.model),
                                        usage.get('prompt_tokens', 0), usage.get('completion_tokens', 0),
                                        usage.get('total_tokens', 0), attempt.get('duration_seconds', 0)*1000,
                                        'initial_fix' if attempt['attempt'] == 1 else 'refinement')
            for gate, value in attempt.get('validation', {}).items():
                if isinstance(value, dict) and 'passed' in value:
                    metrics.record_validation(gate, value['passed'], value.get('score'), json.dumps(value))
        metrics.record_fix_details('audited_ast', 'function' if location['function'] else 'line',
                                  location['file_path'], str(location['start_line']),
                                  result['lines_added'], result['lines_removed'])
        self.all_attempts_logs.append({'finding_number':finding_number,
                                       'cwe':finding['sast'].get('cwe'), 'attempts':result['attempts']})
        if result['accepted']:
            commit = self.commit_changes(finding_number, len(result['attempts']), 'Accepted patch; security re-scan pending')
            if commit:
                metrics.record_commit_info(commit['commit_sha'], commit['commit_message'])
                metrics.mark_success()
            else:
                metrics.mark_failure('Local commit failed; security re-scan pending')
            self.metrics_collector.save_current()
            return bool(commit)
        metrics.mark_failure('No candidate accepted; see transactional attempt records')
        self.metrics_collector.save_current()
        return False

    def _generate_and_save_summary(self, finding_number: str, finding_id: str,
                                   vulnerability_name: str, severity: str, cwe: str,
                                   attempts_log: List[Dict], final_outcome: Dict, metrics):
        """Generate and save summary for a finding"""
        try:
            # Store attempts_log for minimality analysis
            self.all_attempts_logs.append({
                'finding_number': finding_number,
                'cwe': cwe,
                'attempts': attempts_log
            })
            
            # Get code changes and commit info from metrics
            metrics_dict = metrics.to_dict()
            code_changes = metrics_dict.get('code_changes', {})
            commit_info = metrics_dict.get('fix_details', {})
            
            # Add to summary generator
            self.summary_generator.add_finding_summary(
                finding_number=finding_number,
                finding_id=finding_id,
                vulnerability_name=vulnerability_name,
                severity=severity,
                cwe=cwe,
                attempts_log=attempts_log,
                final_outcome=final_outcome,
                code_changes=code_changes,
                commit_info={
                    'commit_sha': commit_info.get('commit_sha'),
                    'commit_message': commit_info.get('commit_message')
                }
            )
        except Exception as e:
            print(f"  ⚠️  Failed to generate summary: {e}")
    
    def run(self):
        """Run the complete fix pipeline"""
        self._ensure_clean_repo()
        print("\\n" + "="*70)
        print("🚀 SECURITY FIX PIPELINE")
        print("="*70)
                # Capture baseline coverage
        if self.config.get('coverage', {}).get('enabled', False):
            print(f"\n🧪 Capturing baseline test coverage...")
            self._capture_baseline_coverage()
                # Load findings metadata ONLY (no code extraction - we'll do that just-in-time)
        context_path = Path(__file__).parent / self.config['artifacts']['filtered_context']
        print(f"\\n📂 Loading findings from: {context_path}")
        
        findings_list = get_findings_metadata_only(
            str(context_path),
            max_findings=self.max_findings,
            finding_ids=self.finding_ids
        )
        
        self.stats['total_findings'] = len(findings_list)
        print(f"   Found {len(findings_list)} findings to fix")
        print(f"   📌 Using just-in-time code fetching to prevent stale context")
        
        for finding in findings_list:
            details = refresh_finding_code(finding, str(self.repo_path))
            if details:
                finding['sast']['location']['function'] = details.get('function_name')

        # Create branch
        branch_name = self.create_branch()
        
        # Capture baseline pylint score
        if self.config['validation'].get('run_pylint', False):
            self._capture_baseline_pylint_score()
        
        # Capture baseline coverage
        if self.coverage_tracker and self.config['validation'].get('run_tests', False):
            try:
                coverage_file = self.repo_path / 'coverage.json'
                if coverage_file.exists():
                    import json as _json
                    with open(coverage_file, 'r', encoding='utf-8') as _f:
                        _cov = _json.load(_f)
                    baseline_cov = _cov.get('totals', {}).get('percent_covered')
                    if baseline_cov is not None:
                        self.coverage_tracker.record_baseline(round(float(baseline_cov), 2))
            except Exception:
                pass
        
        # Fix each finding with JUST-IN-TIME code fetching
        for i, finding in enumerate(findings_list, 1):
            finding_number = finding.get('finding_number', f'FINDING {i:03d}')
            
            # 🔄 FETCH CURRENT CODE from working branch (not stale original)
            print(f"\\n{'='*70}")
            print(f"🔧 {finding_number}")
            print(f"{'='*70}")
            print(f"  📥 Fetching latest code from working branch...")
            details = refresh_finding_code(finding, str(self.repo_path))
            
            if not details:
                print(f"  ❌ Failed to extract finding details")
                self.stats['failed'] += 1
                continue
            
            try:
                success = self.fix_finding(details, finding_number)
                if success:
                    self.stats['fixed_successfully'] += 1
                    # Track successfully fixed findings for SAST validation
                    finding = details['finding']
                    self.fixed_findings.append(finding)
                    
                    # Store metadata for SAST validation update
                    finding_id = finding.get('finding_id', '')
                    if finding_id:
                        self.finding_metadata[finding_id] = {
                            'finding_number': finding_number,
                            'metrics': self.metrics_collector.get_current()
                        }
                else:
                    self.stats['failed'] += 1
            except KeyboardInterrupt:
                print("\\n\\n⚠️  Pipeline interrupted by user")
                # Cleanup loggers and trackers before exiting
                if hasattr(self, 'conversation_logger') and self.conversation_logger:
                    self.conversation_logger.close()
                if hasattr(self, 'console_logger') and self.console_logger:
                    self.console_logger.close()
                if hasattr(self, 'pylint_tracker') and self.pylint_tracker:
                    self.pylint_tracker.finalize()
                if hasattr(self, 'coverage_tracker') and self.coverage_tracker:
                    self.coverage_tracker.finalize()
                break
            except Exception as e:
                print(f"\\n  ❌ Unexpected error: {e}")
                self.stats['failed'] += 1
            
            # Add delay between findings to avoid rate limiting (skip after last finding)
            if i < len(findings_list):
                time.sleep(2)
        
        # Push branch to GitHub
        if self.stats['fixed_successfully'] > 0 and self.config['repository'].get('publish', False):
            print(f"\\n{'='*70}")
            print(f"📤 PUSHING BRANCH TO GITHUB")
            print(f"{'='*70}")
            
            try:
                subprocess.run(
                    ['git', 'push', '-u', 'origin', branch_name],
                    cwd=self.repo_path,
                    check=True,
                    capture_output=True
                )
                print(f"✓ Branch pushed: {branch_name}")
            except subprocess.CalledProcessError as e:
                print(f"✗ Failed to push branch: {e.stderr.decode()}")
                print(f"  Skipping SAST validation")
                self._print_summary(branch_name)
                return
            
            # Capture post-fix coverage
            if self.config.get('coverage', {}).get('enabled', False):
                print(f"\n🧪 Capturing post-fix test coverage...")
                self._capture_post_fix_coverage(branch_name)
            
            # Trigger SAST scan and validate if enabled and we have fixed findings
            if self.github and self.fixed_findings and self.run_sast:
                self._validate_with_sast(branch_name)
            elif not self.run_sast:
                print(f"\n⏭️  Skipping SAST validation (--no-sast flag)")
            
            # Trigger DAST scan if enabled
            if self.github and self.run_dast:
                self._run_and_save_dast(branch_name)
            elif not self.run_dast:
                print(f"\n⏭️  Skipping DAST scan (--no-dast flag)")
        
        # Finalize score tracking
        if self.pylint_tracker:
            self.pylint_tracker.finalize()
        if self.coverage_tracker:
            self.coverage_tracker.finalize()
        
        # Generate evaluation report
        if self.stats['fixed_successfully'] > 0:
            self._generate_evaluation(branch_name)
        
        # Calculate minimality stats before printing summary
        self._calculate_minimality_stats()
        
        # Print summary
        self._print_summary(branch_name)
    
    def _validate_with_sast(self, branch_name: str):
        """
        Trigger SAST scan and validate fixes
        
        Args:
            branch_name: Branch to scan
        """
        print(f"\\n{'='*70}")
        print(f"🔬 SAST VALIDATION")
        print(f"{'='*70}")
        
        # Create temporary directory for SARIF results
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Trigger SAST and download results
            new_sarif = self.github.trigger_and_wait_for_sast(
                branch=branch_name,
                download_dir=temp_path
            )
            
            if not new_sarif:
                print(f"\\n  ⚠️  Could not download SAST results, skipping validation")
                return
            
            # Get original SARIF path - check for branch-named file first
            main_branch = self.config['repository']['main_branch']
            artifacts_dir = Path(__file__).parent / "../artifacts"
            
            # Try branch-named SARIF first (new format)
            original_sarif = artifacts_dir / f"{main_branch}.sarif"
            if not original_sarif.exists():
                # Fall back to old naming convention
                original_sarif = artifacts_dir / "python-results.sarif"
            
            if not original_sarif.exists():
                print(f"\\n  ⚠️  Original SARIF not found (tried: {main_branch}.sarif, python-results.sarif)")
                print(f"      Skipping validation")
                return
            
            print(f"  ✓ Using baseline SARIF: {original_sarif.name}")
            
            # Compare results
            comparison = compare_sarif_findings(
                original_sarif=original_sarif.resolve(),
                new_sarif=new_sarif,
                fixed_findings=self.fixed_findings
            )
            
            # Store for evaluator
            self.sarif_comparison = comparison
            
            # Copy the new SARIF to run folder for record keeping
            reports_dir = Path(__file__).parent / f"../reports/{branch_name}"
            sarif_dest = reports_dir / f"{branch_name}.sarif"
            shutil.copy2(new_sarif, sarif_dest)
            print(f"  ✓ Saved post-fix SARIF: {sarif_dest.name}")
            
            # Save SARIF comparison for later analysis
            reports_dir.mkdir(parents=True, exist_ok=True)
            comparison_file = reports_dir / "sarif_comparison.json"
            with open(comparison_file, 'w', encoding='utf-8') as f:
                json.dump(comparison, f, indent=2)
            
            validation_results = comparison.get('validation_results', {})
            alert_counts = comparison.get('alert_counts', {})
            
            # Print results and update metrics
            print(f"\n  📊 Validation Results:")
            for finding_id, result in validation_results.items():
                if result['validated'] is True:
                    print(f"    ✅ {finding_id}: {result['reason']}")
                    self.stats['validated_by_sast'] += 1
                    validation_success = True
                elif result['validated'] is False:
                    print(f"    ❌ {finding_id}: {result['reason']}")
                    self.stats['failed_sast_validation'] += 1
                    validation_success = False
                else:
                    print(f"    ⚠️  {finding_id}: {result['reason']}")
                    validation_success = None
                
                # Update finding metrics with SAST validation result
                if finding_id in self.finding_metadata:
                    metadata = self.finding_metadata[finding_id]
                    metrics = metadata['metrics']
                    if metrics:
                        metrics.record_validation(
                            validation_type='sast',
                            success=validation_success if validation_success is not None else False,
                            details=result['reason']
                        )
                        # Save updated metrics
                        metrics.save_to_file(branch_name)
                    
                    # Update summary with SAST validation result (Pattern 5 fix)
                    self.summary_generator.update_finding_sast_validation(
                        finding_id=finding_id,
                        sast_result=result
                    )
            
            # Re-save summaries with SAST validation results (Pattern 5 fix)
            self.summary_generator.save_summaries()
            
            print(f"\n  💾 Metrics updated with SAST validation results")
            
            # Save summaries
            print(f"\n  📝 Generating summaries...")
            summaries_file = self.summary_generator.save_summaries()
            print(f"  ✓ Summaries saved to: {summaries_file}")
            
            # Create Pull Request (check flag)
            if self.github and self.create_pr and self.config['repository'].get('publish', False):
                print(f"\n  🔀 Creating pull request...")
                
                # Count SAST validation details for title
                validated_count = self.stats['validated_by_sast']
                attempted_count = self.stats['fixed_successfully'] + self.stats['failed']
                
                pr_title = f"🔒 Security Fixes - {validated_count}/{attempted_count} vulnerabilities confirmed fixed by SAST"
                pr_body = self.summary_generator.generate_pr_description(validation_results)
                
                main_branch = self.config['repository']['main_branch']
                pr_data = self.github.create_pull_request(
                    branch=branch_name,
                    title=pr_title,
                    body=pr_body,
                    base=main_branch
                )
                
                if pr_data:
                    print(f"  ✓ Pull request created successfully!")
                else:
                    print(f"  ⚠️  Could not create pull request (might already exist)")
            elif self.github and not self.create_pr:
                print(f"\n  ⚠️  Skipping pull request creation (--no-pr flag set)")
                print(f"  📤 Branch pushed: {branch_name}")
            elif not self.github:
                print(f"\n  ⚠️  GitHub integration not configured, skipping PR creation")
    
    def _capture_baseline_coverage(self):
        """Capture baseline test coverage from main branch"""
        coverage_config = self.config.get('coverage', {})
        repo_path = Path(__file__).parent / coverage_config.get('repo_path', '../context_builder/repo')
        baseline_file = Path(__file__).parent / coverage_config.get('baseline_file', '../artifacts/baseline_coverage.json')
        pytest_cmd = coverage_config.get('pytest_command', 'pytest --cov=. --cov-report=json')
        
        try:
            # Run pytest with coverage using uv to access pytest-cov
            result = subprocess.run(
                f'uv run {pytest_cmd}',
                shell=True,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Copy coverage.json to baseline location
            coverage_file = repo_path / 'coverage.json'
            if coverage_file.exists():
                baseline_file.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                shutil.copy(coverage_file, baseline_file)
                
                # Load and print summary
                with open(baseline_file, 'r') as f:
                    cov_data = json.load(f)
                    percent = cov_data.get('totals', {}).get('percent_covered', 0)
                    print(f"  ✓ Baseline coverage: {percent:.2f}%")
            else:
                print(f"  ⚠️  Coverage file not generated")
        
        except subprocess.TimeoutExpired:
            print(f"  ⚠️  Coverage capture timed out")
        except Exception as e:
            print(f"  ⚠️  Coverage capture failed: {e}")
    
    def _capture_post_fix_coverage(self, branch_name: str):
        """Capture test coverage after fixes are applied"""
        coverage_config = self.config.get('coverage', {})
        repo_path = Path(__file__).parent / coverage_config.get('repo_path', '../context_builder/repo')
        pytest_cmd = coverage_config.get('pytest_command', 'pytest --cov=. --cov-report=json')
        
        # Create branch reports directory
        reports_dir = Path(__file__).parent / f"../reports/{branch_name}"
        reports_dir.mkdir(parents=True, exist_ok=True)
        post_fix_file = reports_dir / "coverage_after_fixes.json"
        
        try:
            # Run pytest with coverage on fix branch using uv to access pytest-cov
            result = subprocess.run(
                f'uv run {pytest_cmd}',
                shell=True,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Copy coverage.json to post-fix location
            coverage_file = repo_path / 'coverage.json'
            if coverage_file.exists():
                import shutil
                shutil.copy(coverage_file, post_fix_file)
                
                # Load and print summary
                with open(post_fix_file, 'r') as f:
                    cov_data = json.load(f)
                    percent = cov_data.get('totals', {}).get('percent_covered', 0)
                    print(f"  ✓ Post-fix coverage: {percent:.2f}%")
            else:
                print(f"  ⚠️  Coverage file not generated")
        
        except subprocess.TimeoutExpired:
            print(f"  ⚠️  Coverage capture timed out")
        except Exception as e:
            print(f"  ⚠️  Coverage capture failed: {e}")
    
    def _generate_evaluation(self, branch_name: str):
        """Generate comprehensive evaluation report"""
        print(f"\n{'='*70}")
        print(f"📊 GENERATING EVALUATION REPORT")
        print(f"{'='*70}")
        
        try:
            reports_dir = Path(__file__).parent / "../reports"
            evaluator = PipelineEvaluator(reports_dir, branch_name)
            
            # Generate evaluation with SARIF comparison data
            evaluation = evaluator.generate_evaluation(self.sarif_comparison)
            
            # Save evaluation report
            eval_file = evaluator.save_evaluation()
            print(f"\n  ✓ Evaluation saved to: {eval_file}")
            
            # Print summary
            evaluator.print_summary(evaluation)
            
        except Exception as e:
            print(f"\n  ⚠️  Evaluation generation failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _calculate_minimality_stats(self):
        """Calculate minimality statistics from all attempts"""
        if not self.all_attempts_logs:
            return
        
        total_fixes = len(self.all_attempts_logs)
        retry_count = 0
        initial_churns = []
        final_churns = []
        by_cwe = {}
        
        for finding_log in self.all_attempts_logs:
            cwe = finding_log['cwe']
            attempts = finding_log['attempts']
            
            if not attempts:
                continue
            
            # Track CWE stats
            if cwe not in by_cwe:
                by_cwe[cwe] = {'fixes': 0, 'retries': 0, 'initial_churns': [], 'final_churns': []}
            by_cwe[cwe]['fixes'] += 1
            
            # Check if minimality retry was triggered
            had_retry = False
            initial_churn = None
            final_churn = None
            
            for attempt in attempts:
                minimality = attempt.get('minimality')
                if minimality:
                    churn = minimality.get('total_churn', 0)
                    
                    # First attempt with minimality data
                    if initial_churn is None:
                        initial_churn = churn
                    
                    # Last attempt is final
                    final_churn = churn
                    
                    # If churn decreased significantly, a retry happened
                    if initial_churn is not None and final_churn is not None and final_churn < initial_churn * 0.8:
                        had_retry = True
            
            if had_retry:
                retry_count += 1
                by_cwe[cwe]['retries'] += 1
            
            if initial_churn is not None:
                initial_churns.append(initial_churn)
                by_cwe[cwe]['initial_churns'].append(initial_churn)
            if final_churn is not None:
                final_churns.append(final_churn)
                by_cwe[cwe]['final_churns'].append(final_churn)
        
        # Calculate aggregates
        self.stats['minimality_retries'] = retry_count
        self.stats['minimality_retry_rate'] = (retry_count / total_fixes * 100) if total_fixes > 0 else 0.0
        self.stats['avg_initial_churn'] = sum(initial_churns) / len(initial_churns) if initial_churns else 0.0
        self.stats['avg_final_churn'] = sum(final_churns) / len(final_churns) if final_churns else 0.0
        
        # Calculate per-CWE stats
        for cwe, cwe_data in by_cwe.items():
            cwe_stats = {
                'fixes': cwe_data['fixes'],
                'retries': cwe_data['retries']
            }
            
            if cwe_data['initial_churns'] and cwe_data['final_churns']:
                avg_initial = sum(cwe_data['initial_churns']) / len(cwe_data['initial_churns'])
                avg_final = sum(cwe_data['final_churns']) / len(cwe_data['final_churns'])
                cwe_stats['churn_reduction_ratio'] = calculate_churn_reduction_ratio(int(avg_initial), int(avg_final))
            
            self.stats['by_cwe'][cwe] = cwe_stats
    
    def _run_and_save_dast(self, branch_name: str):
        """
        Trigger DAST scan and save results to run folder
        
        Args:
            branch_name: Branch to scan
        """
        print(f"\n{'='*70}")
        print(f"🕷️  DAST SCAN")
        print(f"{'='*70}")
        
        # Create temporary directory for DAST results
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            print(f"\n  🔍 Triggering DAST scan on branch '{branch_name}'...")
            
            # Trigger DAST workflow
            if not self.github.trigger_workflow('DAST Security Scan', branch_name):
                print(f"  ⚠️  Could not trigger DAST workflow")
                return
            
            # Wait a bit for the run to start
            time.sleep(5)
            
            # Wait for completion
            run = self.github.wait_for_workflow_completion(
                branch=branch_name,
                workflow_name='DAST Security Scan',
                timeout=900,  # 15 minutes for DAST
                poll_interval=20
            )
            
            if not run:
                print(f"  ⚠️  DAST workflow did not complete in time")
                return
            
            if run['conclusion'] != 'success':
                print(f"    ⚠️  DAST workflow completed with status: {run['conclusion']}")
            
            # Download artifacts
            print(f"\n  📥 Downloading DAST artifacts...")
            artifact_dir = self.github.download_workflow_artifacts(
                run_id=run['id'],
                artifact_name='dast-results',
                download_dir=temp_path
            )
            
            if not artifact_dir:
                print(f"  ⚠️  Could not download DAST artifacts")
                return
            
            # Find the DAST report - now named after branch (matching SAST pattern)
            # Try branch-specific name first
            branch_dast = artifact_dir / f"{branch_name}.json"
            if branch_dast.exists():
                dast_report = branch_dast
                print(f"    ✓ Found DAST report: {branch_name}.json")
            else:
                # Fall back to any *.json file
                dast_files = list(artifact_dir.glob('*.json'))
                if not dast_files:
                    print(f"  ⚠️  No DAST report found in artifacts")
                    print(f"      Expected: {branch_name}.json")
                    return
                dast_report = dast_files[0]
                print(f"    ✓ Found DAST report: {dast_report.name} (fallback)")
            
            # Copy to run folder with branch name (consistent with SAST naming)
            reports_dir = Path(__file__).parent / f"../reports/{branch_name}"
            dast_dest = reports_dir / f"{branch_name}-dast.json"
            shutil.copy2(dast_report, dast_dest)
            
            print(f"  ✓ Saved post-fix DAST report: {dast_dest.name}")
            print(f"  ✓ DAST scan completed successfully")
    
    def _print_summary(self, branch_name: str):
        """Print pipeline summary"""
        print("\\n" + "="*70)
        print("📊 PIPELINE SUMMARY")
        print("="*70)
        print(f"Branch: {branch_name}")
        print(f"Total findings: {self.stats['total_findings']}")
        print(f"✅ Fixed successfully: {self.stats['fixed_successfully']}")
        print(f"❌ Failed: {self.stats['failed']}")
        print(f"⏭️  Skipped: {self.stats['skipped']}")
        
        if self.stats.get('validated_by_sast', 0) > 0 or self.stats.get('failed_sast_validation', 0) > 0:
            print(f"\\n🔬 SAST Validation:")
            print(f"  ✅ Validated fixes: {self.stats.get('validated_by_sast', 0)}")
            print(f"  ❌ Still detected: {self.stats.get('failed_sast_validation', 0)}")
        
        # Display minimality stats if any retries occurred
        if self.stats.get('minimality_retries', 0) > 0:
            print(f"\\n📏 Minimality Validation:")
            print(f"  🔄 Retry triggered: {self.stats['minimality_retries']} times ({self.stats.get('minimality_retry_rate', 0):.1f}%)")
            print(f"  📉 Avg churn: {self.stats.get('avg_initial_churn', 0):.1f} lines → {self.stats.get('avg_final_churn', 0):.1f} lines after retry")
            
            # Show by-CWE breakdown if available
            by_cwe = self.stats.get('by_cwe', {})
            if by_cwe:
                print(f"  \\n  By CWE type:")
                for cwe, cwe_stats in sorted(by_cwe.items()):
                    if cwe_stats.get('retries', 0) > 0:
                        retry_rate = (cwe_stats['retries'] / cwe_stats['fixes']) * 100 if cwe_stats['fixes'] > 0 else 0
                        churn_reduction = cwe_stats.get('churn_reduction_ratio', 1.0)
                        print(f"    {cwe}: {cwe_stats['retries']}/{cwe_stats['fixes']} retries ({retry_rate:.0f}%) - {churn_reduction:.1f}x churn reduction")
        
        print("="*70)
        
        print(f"\\n💡 View branch: https://github.com/{os.getenv('GITHUB_REPO')}/tree/{branch_name}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Fix Pipeline')
    parser.add_argument('--finding-ids', nargs='+', help='Specific finding IDs to process')
    parser.add_argument('--from-sarif-comparison', type=str, help='Path to sarif_comparison.json to extract unsolved findings')
    parser.add_argument('--no-pr', action='store_true', help='Do not create pull request (only create and push branch)')
    parser.add_argument('--no-sast', action='store_true', help='Skip SAST validation')
    parser.add_argument('--no-dast', action='store_true', help='Skip DAST scan')
    args = parser.parse_args()
    
    finding_ids = None
    
    # Load unsolved findings from SARIF comparison if provided
    if args.from_sarif_comparison:
        print(f"\n📊 Loading unsolved findings from: {args.from_sarif_comparison}")
        try:
            with open(args.from_sarif_comparison, 'r') as f:
                comparison = json.load(f)
                validation_results = comparison.get('validation_results', {})
                finding_ids = [fid for fid, result in validation_results.items() if not result.get('validated', False)]
                print(f"   Found {len(finding_ids)} unsolved findings")
                for fid in finding_ids:
                    print(f"   - {fid}")
        except Exception as e:
            print(f"   ❌ Error loading SARIF comparison: {e}")
            sys.exit(1)
    elif args.finding_ids:
        finding_ids = args.finding_ids
        print(f"\n🎯 Processing {len(finding_ids)} specific findings")
        for fid in finding_ids:
            print(f"   - {fid}")
    
    pipeline = None
    try:
        pipeline = FixPipeline(
            finding_ids=finding_ids,
            create_pr=not args.no_pr,
            run_sast=not args.no_sast,
            run_dast=not args.no_dast
        )
        pipeline.run()
    except KeyboardInterrupt:
        print("\\n\\n⚠️  Pipeline interrupted by user")
        if pipeline and hasattr(pipeline, 'console_logger') and pipeline.console_logger:
            pipeline.console_logger.close()
        if pipeline and hasattr(pipeline, 'conversation_logger') and pipeline.conversation_logger:
            pipeline.conversation_logger.close()
        if pipeline and hasattr(pipeline, 'pylint_tracker') and pipeline.pylint_tracker:
            pipeline.pylint_tracker.finalize()
        if pipeline and hasattr(pipeline, 'coverage_tracker') and pipeline.coverage_tracker:
            pipeline.coverage_tracker.finalize()
        sys.exit(1)
    except Exception as e:
        print(f"\\n\\n❌ Pipeline error: {e}")
        if pipeline and hasattr(pipeline, 'console_logger') and pipeline.console_logger:
            pipeline.console_logger.close()
        if pipeline and hasattr(pipeline, 'conversation_logger') and pipeline.conversation_logger:
            pipeline.conversation_logger.close()
        if pipeline and hasattr(pipeline, 'pylint_tracker') and pipeline.pylint_tracker:
            pipeline.pylint_tracker.finalize()
        if pipeline and hasattr(pipeline, 'coverage_tracker') and pipeline.coverage_tracker:
            pipeline.coverage_tracker.finalize()
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
