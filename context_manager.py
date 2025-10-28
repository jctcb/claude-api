"""
Context Manager - Prevents AI degradation in long conversations
"""

import anthropic
from typing import List, Dict

class ContextManager:
    """Manages conversation context to prevent degradation"""
    
    def __init__(self, claude_client, max_messages_before_compress=80):
        self.claude_client = claude_client
        self.max_messages = max_messages_before_compress
    
    def should_compress(self, messages: List[Dict]) -> bool:
        """Check if context needs compression"""
        return len(messages) >= self.max_messages
    
    def compress_context(self, messages: List[Dict]) -> List[Dict]:
        """Compress old messages while preserving recent context"""
        if len(messages) <= self.max_messages:
            return messages
        
        # Keep recent messages (last 20)
        recent_messages = messages[-20:]
        
        # Summarize older messages
        old_messages = messages[:-20]
        
        # Create summary
        summary = f"[Previous conversation summary: {len(old_messages)} messages exchanged]"
        
        # Return compressed context
        return [
            {"role": "user", "content": summary}
        ] + recent_messages

class DegradationDetector:
    """Detects signs of AI degradation in responses"""
    
    @staticmethod
    def detect_degradation(response: str) -> bool:
        """Detect if response shows signs of degradation"""
        degradation_signs = [
            "as i mentioned",
            "as we discussed",
            "going in circles",
            "repeating myself"
        ]
        
        response_lower = response.lower()
        return any(sign in response_lower for sign in degradation_signs)

def inject_degradation_awareness(system_prompt: str) -> str:
    """Add degradation awareness to system prompt"""
    return system_prompt + "\n\nNote: If conversation becomes repetitive, suggest starting fresh."