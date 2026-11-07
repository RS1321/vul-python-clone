"""
Conversation Logger

Captures all LLM interactions (prompts and responses) to a log file
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List


class ConversationLogger:
    """Log all LLM conversations to a file"""
    
    def __init__(self, branch_name: str):
        """
        Initialize conversation logger
        
        Args:
            branch_name: Branch name for organizing logs
        """
        self.branch_name = branch_name
        
        # Create reports directory structure
        reports_dir = Path(__file__).parent.parent / 'reports' / branch_name
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_file = reports_dir / 'conversation.log'
        self.conversation_count = 0
        
        # Initialize log file with header
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"LLM CONVERSATION LOG - Branch: {branch_name}\n")
            f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
    
    def log_conversation(self, 
                        messages: List[Dict[str, str]], 
                        response: str,
                        model: str,
                        purpose: str = "chat",
                        finding_number: Optional[str] = None,
                        attempt_number: Optional[int] = None,
                        metadata: Optional[Dict] = None):
        """
        Log a complete LLM conversation (prompt + response)
        
        Args:
            messages: List of message dicts sent to LLM
            response: LLM response content
            model: Model name used
            purpose: Purpose of this conversation (e.g., "initial_fix", "refinement")
            finding_number: Optional finding number being processed
            attempt_number: Optional attempt number
            metadata: Optional additional metadata (tokens, duration, etc.)
        """
        self.conversation_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            # Write conversation header
            f.write("\n" + "="*80 + "\n")
            f.write(f"CONVERSATION #{self.conversation_count}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Model: {model}\n")
            f.write(f"Purpose: {purpose}\n")
            
            if finding_number:
                f.write(f"Finding: {finding_number}\n")
            if attempt_number:
                f.write(f"Attempt: {attempt_number}\n")
            
            if metadata:
                f.write(f"Metadata: {json.dumps(metadata, indent=2)}\n")
            
            f.write("="*80 + "\n\n")
            
            # Write messages sent to LLM
            f.write("--- PROMPT TO LLM ---\n\n")
            for i, msg in enumerate(messages, 1):
                role = msg.get('role', 'unknown').upper()
                content = msg.get('content', '')
                
                f.write(f"[{role} MESSAGE #{i}]\n")
                f.write("-" * 40 + "\n")
                f.write(content + "\n")
                f.write("-" * 40 + "\n\n")
            
            # Write LLM response
            f.write("--- LLM RESPONSE ---\n\n")
            f.write(response + "\n")
            f.write("\n" + "="*80 + "\n\n")
    
    def log_error(self, error_message: str, context: Optional[Dict] = None):
        """
        Log an error in LLM communication
        
        Args:
            error_message: Error message
            context: Optional context information
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "!"*80 + "\n")
            f.write(f"ERROR - {timestamp}\n")
            f.write("!"*80 + "\n\n")
            f.write(f"Error: {error_message}\n")
            
            if context:
                f.write(f"\nContext:\n{json.dumps(context, indent=2)}\n")
            
            f.write("\n" + "!"*80 + "\n\n")
    
    def close(self):
        """Close the log file with a footer"""
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*80 + "\n")
            f.write(f"LOG ENDED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Conversations: {self.conversation_count}\n")
            f.write("="*80 + "\n")
