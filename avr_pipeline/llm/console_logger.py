"""
Console Logger

Captures all console output to a log file
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class ConsoleLogger:
    """Capture all console output (print statements) to a file"""
    
    def __init__(self, branch_name: str):
        """
        Initialize console logger
        
        Args:
            branch_name: Branch name for organizing logs
        """
        self.branch_name = branch_name
        
        # Create reports directory structure
        reports_dir = Path(__file__).parent.parent / 'reports' / branch_name
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_file = reports_dir / 'console.log'
        
        # Store original stdout and stderr
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        
        # Open log file
        self.file_handle = open(self.log_file, 'w', encoding='utf-8')
        
        # Write header
        self.file_handle.write("="*80 + "\n")
        self.file_handle.write(f"CONSOLE LOG - Branch: {branch_name}\n")
        self.file_handle.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.file_handle.write("="*80 + "\n\n")
        self.file_handle.flush()
        
        # Redirect stdout and stderr to this logger
        sys.stdout = self
        sys.stderr = self
    
    def write(self, message: str):
        """Write to both console and log file"""
        # Write to original stdout (so user still sees output)
        self.original_stdout.write(message)
        self.original_stdout.flush()
        
        # Write to log file
        self.file_handle.write(message)
        self.file_handle.flush()
    
    def flush(self):
        """Flush both outputs"""
        self.original_stdout.flush()
        self.file_handle.flush()
    
    def close(self):
        """Restore original stdout/stderr and close log file"""
        # Write footer
        self.file_handle.write("\n" + "="*80 + "\n")
        self.file_handle.write(f"LOG ENDED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.file_handle.write("="*80 + "\n")
        
        # Restore original streams
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        
        # Close file
        self.file_handle.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
        return False
