"""Code fetcher for retrieving source code context."""

import ast
import difflib
from pathlib import Path
from typing import Optional, Tuple, List


class CodeFetcher:
    """Fetches code from local repository."""

    def __init__(self, repo_path: str):
        """
        Initialize code fetcher.

        Args:
            repo_path: Path to cloned repository
        """
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

    def get_code_context(
        self, file_path: str, line_number: int, config: dict
    ) -> Optional[str]:
        """
        Get code context around a specific line.

        Args:
            file_path: Relative path to file in repository
            line_number: Line number to center context around
            config: Configuration with 'context_lines_before' and 'context_lines_after'

        Returns:
            Code snippet as string or None if file not found
        """
        try:
            # Build full path
            full_path = self.repo_path / file_path
            if not full_path.exists():
                return None

            # Read file
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Calculate range
            lines_before = config.get("context_lines_before", 5)
            lines_after = config.get("context_lines_after", 5)

            start_line = max(0, line_number - lines_before - 1)
            end_line = min(len(lines), line_number + lines_after)

            # Extract context
            context_lines = lines[start_line:end_line]
            
            # Add line numbers
            numbered_lines = []
            for idx, line in enumerate(context_lines, start=start_line + 1):
                marker = "→ " if idx == line_number else "  "
                numbered_lines.append(f"{marker}{idx:4d} | {line.rstrip()}")

            return "\n".join(numbered_lines)

        except Exception as e:
            return None

    def file_exists(self, file_path: str) -> bool:
        """Check if file exists in repository."""
        full_path = self.repo_path / file_path
        return full_path.exists()

    def get_function_by_name(self, file_path, function_name):
        """Resolve a unique qualified function and AST decorator boundaries."""
        from parsers.ast_utils import locate, boundaries
        try:
            path = (self.repo_path / file_path).resolve()
            if not path.is_relative_to(self.repo_path.resolve()):
                return None
            content = path.read_text(encoding="utf-8")
            node = locate(ast.parse(content), function_name)
            start, end = boundaries(node)
            return start, end, "\n".join(content.splitlines()[start - 1:end])
        except (OSError, SyntaxError, ValueError):
            return None

    def find_code_by_fuzzy_match(self, file_path: str, target_snippet: str, threshold: float = 0.6) -> Optional[Tuple[int, int]]:
        """
        Find code location using fuzzy matching.
        Useful when line numbers are stale but we have the vulnerable code snippet.
        
        Args:
            file_path: Relative path to file in repository
            target_snippet: Code snippet to find
            threshold: Similarity threshold (0.0-1.0)
        
        Returns:
            Tuple of (start_line, end_line) or None if no good match found
        """
        try:
            full_path = self.repo_path / file_path
            if not full_path.exists():
                return None
            
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Clean target snippet (remove line numbers if present)
            target_lines = self._clean_code_snippet(target_snippet)
            if not target_lines:
                return None
            
            # Try to find best matching sequence
            best_match_ratio = 0.0
            best_match_start = None
            best_match_end = None
            
            window_size = len(target_lines)
            
            # Slide window through file
            for i in range(len(lines) - window_size + 1):
                window = lines[i:i + window_size]
                window_clean = [line.strip() for line in window]
                
                # Calculate similarity
                matcher = difflib.SequenceMatcher(None, target_lines, window_clean)
                ratio = matcher.ratio()
                
                if ratio > best_match_ratio:
                    best_match_ratio = ratio
                    best_match_start = i + 1  # 1-indexed
                    best_match_end = i + window_size
            
            # Return if above threshold
            if best_match_ratio >= threshold:
                return (best_match_start, best_match_end)
            
            return None
            
        except Exception:
            return None
    
    def _clean_code_snippet(self, snippet: str) -> List[str]:
        """
        Clean code snippet by removing line numbers and markers.
        
        Args:
            snippet: Raw code snippet with potential line numbers
        
        Returns:
            List of clean code lines
        """
        lines = snippet.split('\n')
        clean_lines = []
        
        for line in lines:
            # Remove line number prefix (e.g., "  102 | code" or "→ 102 | code")
            cleaned = line
            if '|' in line:
                parts = line.split('|', 1)
                if len(parts) == 2:
                    cleaned = parts[1]
            
            # Strip whitespace for comparison
            cleaned = cleaned.strip()
            if cleaned:  # Skip empty lines
                clean_lines.append(cleaned)
        
        return clean_lines
