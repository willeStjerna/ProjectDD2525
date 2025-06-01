#!/usr/bin/env python3
"""
Encoded Script Detection Tool for Supply Chain Security
Detects potentially malicious encoded scripts in Python packages
"""

import re
import base64
import binascii
import urllib.parse
import ast
import os
import sys
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Detection:
    """Represents a suspicious detection result"""
    file_path: str
    line_number: int
    encoding_type: str
    encoded_content: str
    decoded_content: str
    risk_score: int
    suspicious_patterns: List[str]

class EncodedScriptDetector:
    """Main detector class for finding encoded scripts"""
    
    def __init__(self):
        # Patterns for different encoding schemes
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        self.hex_pattern = re.compile(r'\\x[0-9a-fA-F]{2}|[0-9a-fA-F]{32,}')

        # REVISED: This pattern now looks for a string containing at least 4 instances of '%xx',
        # separated by any characters. This is more flexible.
        self.url_encoding_pattern = re.compile(r"'.*?(%[0-9a-fA-F]{2}.*?){4,}.*?'|\".*?(%[0-9a-fA-F]{2}.*?){4,}.*?\"")
        
        # Suspicious code patterns to look for in decoded content
        self.suspicious_patterns = {
            'system_calls': [
                r'os\.system\s*\(',
                r'subprocess\.',
                r'eval\s*\(',
                r'exec\s*\(',
                r'__import__\s*\(',
            ],
            'network_activity': [
                r'urllib\.request',
                r'requests\.',
                r'socket\.',
                r'http\.client',
                r'ftplib\.',
            ],
            'file_operations': [
                r'open\s*\(',
                r'file\s*\(',
                r'\.write\s*\(',
                r'\.read\s*\(',
                r'os\.remove',
                r'os\.unlink',
            ],
            'obfuscation': [
                r'compile\s*\(',
                r'\.decode\s*\(',
                r'base64\.',
                r'codecs\.',
                r'marshal\.',
            ]
        }
    
    def scan_directory(self, directory: str) -> List[Detection]:
        """Scan all Python files in a directory"""
        detections = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    detections.extend(self.scan_file(file_path))
        
        return detections
    
    def _check_comments_and_self_reading(self, file_path: str, content: str) -> List[Detection]:
        """Check for suspicious patterns in comments and for self-reading code."""
        detections = []
        lines = content.splitlines()

        # Heuristic 1: Analyze content within comments
        comment_content = ""
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#'):
                # Extract content from comment and analyze it
                comment_text = line.strip().lstrip('#').strip()
                # Simple check: does the comment look like encoded data or contain suspicious keywords?
                if self.base64_pattern.search(comment_text) or 'eval(' in comment_text or 'exec(' in comment_text:
                    detections.append(Detection(
                        file_path=file_path,
                        line_number=line_num,
                        encoding_type='Steganography (Comment)',
                        encoded_content=line[:80],
                        decoded_content='Suspicious content found inside a code comment.',
                        risk_score=30,
                        suspicious_patterns=['Code or encoded data hidden in comment']
                    ))

        # Heuristic 2: Check for self-reading code
        if "open(__file__)" in content:
            detections.append(Detection(
                file_path=file_path,
                line_number=0,  # Line number isn't as relevant for this file-wide check
                encoding_type='Suspicious Code Structure',
                encoded_content="open(__file__)",
                decoded_content='File reads its own source code, potentially to execute hidden content.',
                risk_score=20,
                suspicious_patterns=['Self-reading source file']
            ))
        
        return detections
    
    def scan_file(self, file_path: str) -> List[Detection]:
        """Scan a single Python file for encoded content"""
        detections = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return detections
        
        # NEW: Call the comment/steganography check
        detections.extend(self._check_comments_and_self_reading(file_path, content))
        
        # NEW: Add a check for suspicious `exec` call patterns using AST
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # Look for a call to exec()
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'exec':
                    if node.args:
                        # Check if the argument to exec is another function call (e.g., exec(decode(...)))
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.Call):
                            detections.append(Detection(
                                file_path=file_path,
                                line_number=node.lineno,
                                encoding_type='Suspicious Code Structure',
                                encoded_content=ast.unparse(node),
                                decoded_content='exec() called on the result of another function.',
                                risk_score=25,
                                suspicious_patterns=['High-risk pattern: exec(function())']
                            ))
        except Exception:
            pass # Ignore parsing errors in this check
        
        for line_num, line in enumerate(lines, 1):
            # Check for different encoding patterns
            detections.extend(self._check_base64(file_path, line_num, line))
            detections.extend(self._check_hex_encoding(file_path, line_num, line))
            detections.extend(self._check_url_encoding(file_path, line_num, line))
        
        return detections
    
    def _check_base64(self, file_path: str, line_num: int, line: str) -> List[Detection]:
        """Check for Base64 encoded content"""
        detections = []
        matches = self.base64_pattern.findall(line)
        
        for match in matches:
            try:
                # Attempt to decode Base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                
                # Skip if decoded content is too short or looks like random data
                if len(decoded) < 10 or not any(c.isalpha() for c in decoded):
                    continue
                
                risk_score, suspicious_patterns = self._analyze_decoded_content(decoded)
                
                if risk_score > 0:
                    detections.append(Detection(
                        file_path=file_path,
                        line_number=line_num,
                        encoding_type='Base64',
                        encoded_content=match[:50] + '...' if len(match) > 50 else match,
                        decoded_content=decoded[:100] + '...' if len(decoded) > 100 else decoded,
                        risk_score=risk_score,
                        suspicious_patterns=suspicious_patterns
                    ))
            except Exception:
                # If decoding fails, it might not be Base64 or might be binary
                continue
        
        return detections
    
    def _check_hex_encoding(self, file_path: str, line_num: int, line: str) -> List[Detection]:
        """Check for hex encoded content"""
        detections = []
        
        # Check for \x hex encoding
        hex_matches = re.findall(r'((?:\\x[0-9a-fA-F]{2})+)', line)
        for match in hex_matches:
            try:
                # Remove \x and decode
                hex_string = match.replace('\\x', '')
                decoded = bytes.fromhex(hex_string).decode('utf-8', errors='ignore')
                
                if len(decoded) < 5:
                    continue
                
                risk_score, suspicious_patterns = self._analyze_decoded_content(decoded)
                
                if risk_score > 0:
                    detections.append(Detection(
                        file_path=file_path,
                        line_number=line_num,
                        encoding_type='Hex (\\x)',
                        encoded_content=match[:50] + '...' if len(match) > 50 else match,
                        decoded_content=decoded[:100] + '...' if len(decoded) > 100 else decoded,
                        risk_score=risk_score,
                        suspicious_patterns=suspicious_patterns
                    ))
            except Exception:
                continue
        
        # Check for plain hex strings
        plain_hex_matches = re.findall(r'\b([0-9a-fA-F]{32,})\b', line)
        for match in plain_hex_matches:
            try:
                decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')
                
                if len(decoded) < 5:
                    continue
                
                risk_score, suspicious_patterns = self._analyze_decoded_content(decoded)
                
                if risk_score > 0:
                    detections.append(Detection(
                        file_path=file_path,
                        line_number=line_num,
                        encoding_type='Hex (plain)',
                        encoded_content=match[:50] + '...' if len(match) > 50 else match,
                        decoded_content=decoded[:100] + '...' if len(decoded) > 100 else decoded,
                        risk_score=risk_score,
                        suspicious_patterns=suspicious_patterns
                    ))
            except Exception:
                continue
        
        return detections
    
    def _check_url_encoding(self, file_path: str, line_num: int, line: str) -> List[Detection]:
        """Check for URL encoded content"""
        detections = []
        matches = self.url_encoding_pattern.findall(line)
        
        for match in matches:
            try:
                decoded = urllib.parse.unquote(match)
                
                if len(decoded) < 5:
                    continue
                
                risk_score, suspicious_patterns = self._analyze_decoded_content(decoded)
                
                if risk_score > 0:
                    detections.append(Detection(
                        file_path=file_path,
                        line_number=line_num,
                        encoding_type='URL Encoding',
                        encoded_content=match[:50] + '...' if len(match) > 50 else match,
                        decoded_content=decoded[:100] + '...' if len(decoded) > 100 else decoded,
                        risk_score=risk_score,
                        suspicious_patterns=suspicious_patterns
                    ))
            except Exception:
                continue
        
        return detections
    
    def _analyze_decoded_content(self, decoded: str) -> Tuple[int, List[str]]:
        """Analyze decoded content for suspicious patterns"""
        risk_score = 0
        found_patterns = []
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, decoded, re.IGNORECASE):
                    risk_score += 10
                    found_patterns.append(f"{category}: {pattern}")
        
        # Additional checks
        if 'import' in decoded.lower() and len(decoded) > 50:
            risk_score += 5
            found_patterns.append("Contains import statements")
        
        if any(keyword in decoded.lower() for keyword in ['download', 'upload', 'delete', 'remove']):
            risk_score += 5
            found_patterns.append("Contains potentially dangerous keywords")
        
        # REVISED: Check if it's executable Python code, not just a literal
        try:
            tree = ast.parse(decoded)
            # Walk the tree to see if it contains more than just data literals
            is_executable = False
            for node in ast.walk(tree):
                # Check for nodes that imply execution, like calls, imports, attribute access on a variable.
                # Exclude simple data structures (literals).
                if not isinstance(node, (ast.Module, ast.Expr, ast.Constant, 
                                        ast.Dict, ast.List, ast.Tuple, ast.Set)):
                    is_executable = True
                    break
            
            if is_executable:
                risk_score += 15
                found_patterns.append("Contains executable Python code")

        except Exception:
            # If parsing fails, it's not valid Python code
            pass
        
        return risk_score, found_patterns
    
    def generate_report(self, detections: List[Detection]) -> str:
        """Generate a human-readable report"""
        if not detections:
            return "No suspicious encoded content detected."
        
        report = f"Encoded Script Detection Report\n"
        report += f"================================\n\n"
        report += f"Total detections: {len(detections)}\n\n"
        
        # Sort by risk score (highest first)
        detections.sort(key=lambda x: x.risk_score, reverse=True)
        
        for i, detection in enumerate(detections, 1):
            report += f"Detection #{i}\n"
            report += f"File: {detection.file_path}\n"
            report += f"Line: {detection.line_number}\n"
            report += f"Encoding: {detection.encoding_type}\n"
            report += f"Risk Score: {detection.risk_score}\n"
            report += f"Encoded Content: {detection.encoded_content}\n"
            report += f"Decoded Content: {detection.decoded_content}\n"
            report += f"Suspicious Patterns:\n"
            for pattern in detection.suspicious_patterns:
                report += f"  - {pattern}\n"
            report += f"\n{'-'*50}\n\n"
        
        return report

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python detector.py <directory_or_file>")
        sys.exit(1)
    
    target = sys.argv[1]
    detector = EncodedScriptDetector()
    
    if os.path.isfile(target):
        detections = detector.scan_file(target)
    elif os.path.isdir(target):
        detections = detector.scan_directory(target)
    else:
        print(f"Error: {target} is not a valid file or directory")
        sys.exit(1)
    
    report = detector.generate_report(detections)
    print(report)
    


if __name__ == "__main__":
    main()