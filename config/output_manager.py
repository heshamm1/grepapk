#!/usr/bin/env python3
"""
Enhanced Output Manager for GrepAPK with Exploit Information
Manages and formats vulnerability findings output with separated REGEX and AI results.
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import click

from .vulnerability_patterns import get_exploit_for_vulnerability, get_comprehensive_exploit_payload

class OutputManager:
    """Enhanced output manager with exploit information and separated scan results."""
    
    def __init__(self, output_format: str = 'txt', output_file: Optional[str] = None):
        self.output_format = output_format.lower()
        self.output_file = output_file
        self.vulnerabilities = []
        self.regex_vulnerabilities = []
        self.ai_vulnerabilities = []
        
    def add_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Add vulnerabilities to the output manager (legacy support)."""
        self.vulnerabilities.extend(vulnerabilities)
    
    def add_regex_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Add regex-detected vulnerabilities."""
        self.regex_vulnerabilities.extend(vulnerabilities)
    
    def add_ai_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Add AI-detected vulnerabilities."""
        self.ai_vulnerabilities.extend(vulnerabilities)
    
    def generate_output(self) -> str:
        """Generate output in the specified format."""
        if self.output_format == 'json':
            return self._generate_json_output()
        else:
            return self._generate_txt_output()
    
    def _generate_txt_output(self) -> str:
        """Generate enhanced text output with exploit information and separated results."""
        output_lines = []
        output_lines.append("=" * 100)
        output_lines.append("🔒 GREPAPK ENHANCED VULNERABILITY SCAN REPORT")
        output_lines.append("=" * 100)
        output_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Use enhanced results if available, otherwise fall back to legacy
        if self.regex_vulnerabilities or self.ai_vulnerabilities:
            total_vulns = len(self.regex_vulnerabilities) + len(self.ai_vulnerabilities)
            output_lines.append(f"Total Vulnerabilities Found: {total_vulns}")
            output_lines.append(f"REGEX Scan Results: {len(self.regex_vulnerabilities)} vulnerabilities")
            output_lines.append(f"AI Scan Results: {len(self.ai_vulnerabilities)} vulnerabilities")
            
            # REGEX SCAN RESULTS
            if self.regex_vulnerabilities:
                output_lines.append("")
                output_lines.append("🔍 REGEX SCAN RESULTS")
                output_lines.append("=" * 80)
                output_lines.append(f"Total REGEX Vulnerabilities: {len(self.regex_vulnerabilities)}")
                output_lines.append("")
                
                # Group regex vulnerabilities by category
                regex_categories = self._group_vulnerabilities_by_category(self.regex_vulnerabilities)
                
                for category, vulns in regex_categories.items():
                    output_lines.append(f"📋 {category.upper().replace('_', ' ')} VULNERABILITIES (REGEX)")
                    output_lines.append("-" * 60)
                    
                    for i, vuln in enumerate(vulns, 1):
                        output_lines.append(f"\n{i}. DISCOVERED VULNERABILITY TITLE:")
                        output_lines.append(f"   {vuln.get('title', 'Unknown Vulnerability')}")
                        
                        output_lines.append(f"\n   DISCOVERED VULNERABLE CLASS AND LINE:")
                        file_path = vuln.get('file_path', 'Unknown')
                        line_number = vuln.get('line_number', 'Unknown')
                        output_lines.append(f"   File: {file_path}")
                        output_lines.append(f"   Line: {line_number}")
                        
                        output_lines.append(f"\n   SHORT ONE-LINER DESCRIPTION:")
                        description = vuln.get('description', 'No description available')
                        output_lines.append(f"   {description}")
                        
                        output_lines.append(f"\n   EXPLOIT METHOD:")
                        exploit_method = vuln.get('exploitation_method', 'Unknown')
                        output_lines.append(f"   {exploit_method}")
                        
                        # Generate enhanced exploit payload
                        exploit_info = self._generate_enhanced_exploit_payload(vuln)
                        if exploit_info:
                            output_lines.append(f"\n   🚀 EXPLOIT PAYLOAD:")
                            output_lines.append(f"   ADB Command: {exploit_info.get('adb_command', 'N/A')}")
                            output_lines.append(f"   External Tool: {exploit_info.get('external_tool', 'N/A')}")
                            output_lines.append(f"   Exploit Type: {exploit_info.get('exploit_type', 'N/A')}")
                            output_lines.append(f"   Severity: {exploit_info.get('severity', 'N/A')}")
                            
                            # Add multiple commands for ICC vulnerabilities
                            if 'multiple_commands' in exploit_info:
                                output_lines.append(f"   Multiple Commands:")
                                for cmd in exploit_info['multiple_commands']:
                                    output_lines.append(f"     • {cmd}")
                            
                            if 'mitigation' in exploit_info:
                                output_lines.append(f"   Mitigation: {exploit_info['mitigation']}")
                        
                        output_lines.append("\n" + "-" * 40)
                
                output_lines.append("")
            
            # AI SCAN RESULTS
            if self.ai_vulnerabilities:
                output_lines.append("🤖 AI SCAN RESULTS")
                output_lines.append("=" * 80)
                output_lines.append(f"Total AI Vulnerabilities: {len(self.ai_vulnerabilities)}")
                output_lines.append("")
                
                # Group AI vulnerabilities by category
                ai_categories = self._group_vulnerabilities_by_category(self.ai_vulnerabilities)
                
                for category, vulns in ai_categories.items():
                    output_lines.append(f"📋 {category.upper().replace('_', ' ')} VULNERABILITIES (AI)")
                    output_lines.append("-" * 60)
                    
                    for i, vuln in enumerate(vulns, 1):
                        output_lines.append(f"\n{i}. DISCOVERED VULNERABILITY TITLE:")
                        output_lines.append(f"   {vuln.get('discovered_vulnerability_title', 'Unknown Vulnerability')}")
                        
                        output_lines.append(f"\n   DISCOVERED VULNERABLE CLASS AND LINE:")
                        file_path = vuln.get('discovered_vulnerable_class_and_line', {}).get('file_path', 'Unknown')
                        line_number = vuln.get('discovered_vulnerable_class_and_line', {}).get('line_number', 'Unknown')
                        output_lines.append(f"   File: {file_path}")
                        output_lines.append(f"   Line: {line_number}")
                        
                        output_lines.append(f"\n   SHORT ONE-LINER DESCRIPTION:")
                        description = vuln.get('short_one_liner_description', 'No description available')
                        output_lines.append(f"   {description}")
                        
                        output_lines.append(f"\n   EXPLOIT METHOD:")
                        exploit_method = vuln.get('exploit_method', 'Unknown')
                        output_lines.append(f"   {exploit_method}")
                        
                        # Generate enhanced exploit payload for AI vulnerabilities
                        category = vuln.get('additional_info', {}).get('category', 'Unknown')
                        subcategory = vuln.get('additional_info', {}).get('subcategory', 'Unknown')
                        exploit_info = get_comprehensive_exploit_payload(category, subcategory)
                        
                        if exploit_info:
                            output_lines.append(f"\n   🚀 EXPLOIT PAYLOAD:")
                            output_lines.append(f"   ADB Command: {exploit_info.get('adb_command', 'N/A')}")
                            output_lines.append(f"   External Tool: {exploit_info.get('external_tool', 'N/A')}")
                            output_lines.append(f"   Exploit Type: {exploit_info.get('exploit_type', 'N/A')}")
                            output_lines.append(f"   Severity: {exploit_info.get('severity', 'N/A')}")
                            
                            # Add multiple commands for ICC vulnerabilities
                            if 'multiple_commands' in exploit_info:
                                output_lines.append(f"   Multiple Commands:")
                                for cmd in exploit_info['multiple_commands']:
                                    output_lines.append(f"     • {cmd}")
                            
                            if 'mitigation' in exploit_info:
                                output_lines.append(f"   Mitigation: {exploit_info['mitigation']}")
                        
                        # AI-specific information
                        ai_info = vuln.get('additional_info', {})
                        if ai_info:
                            output_lines.append(f"\n   🤖 AI ANALYSIS:")
                            output_lines.append(f"   Confidence Score: {ai_info.get('confidence_score', 'N/A')}")
                            output_lines.append(f"   Detection Method: {ai_info.get('detection_method', 'N/A')}")
                            if 'ai_analysis' in vuln:
                                output_lines.append(f"   AI Context: {vuln['ai_analysis']}")
                        
                        output_lines.append("\n" + "-" * 40)
                
                output_lines.append("")
            
            # Enhanced Summary
            output_lines.append("=" * 100)
            output_lines.append("📊 ENHANCED SCAN SUMMARY")
            output_lines.append("=" * 100)
            
            # Count by severity for both methods
            all_vulns = self.regex_vulnerabilities + self.ai_vulnerabilities
            severity_counts = {}
            method_counts = {}
            
            for vuln in all_vulns:
                # Handle both regex and AI vulnerability formats
                severity = None
                method = None
                
                if 'severity' in vuln:
                    severity = vuln['severity']
                    method = 'regex'
                elif 'additional_info' in vuln:
                    severity = vuln['additional_info'].get('severity', 'Unknown')
                    method = vuln['additional_info'].get('detection_method', 'ai')
                
                if severity:
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if method:
                    method_counts[method] = method_counts.get(method, 0) + 1
            
            # Severity breakdown
            output_lines.append("🚨 SEVERITY BREAKDOWN:")
            for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
                output_lines.append(f"   {severity}: {count} vulnerabilities")
            
            output_lines.append("")
            
            # Detection method breakdown
            output_lines.append("🔍 DETECTION METHOD BREAKDOWN:")
            for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
                output_lines.append(f"   {method}: {count} vulnerabilities")
            
            output_lines.append("")
            
            # Exploit summary
            output_lines.append("🚀 EXPLOIT SUMMARY:")
            output_lines.append("   • ADB Commands: Available for most vulnerabilities")
            output_lines.append("   • External Tools: Recommended for complex exploits")
            output_lines.append("   • Severity Levels: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIVE")
            output_lines.append("   • Exploit Types: Data Extraction, Component Hijacking, Authentication Bypass, etc.")
            output_lines.append("   • ICC Vulnerabilities: Multiple command options for comprehensive testing")
            
        else:
            # Legacy output format
            if not self.vulnerabilities:
                return "No vulnerabilities found.\n"
            
            output_lines.append(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}")
            output_lines.append("")
            
            # Group vulnerabilities by category
            categories = {}
            for vuln in self.vulnerabilities:
                category = vuln.get('category', 'Unknown')
                if category not in categories:
                    categories[category] = []
                categories[category].append(vuln)
            
            # Generate output for each category
            for category, vulns in categories.items():
                output_lines.append(f"📋 {category.upper().replace('_', ' ')} VULNERABILITIES")
                output_lines.append("-" * 60)
                
                for i, vuln in enumerate(vulns, 1):
                    output_lines.append(f"\n{i}. DISCOVERED VULNERABILITY TITLE:")
                    output_lines.append(f"   {vuln.get('title', 'Unknown Vulnerability')}")
                    
                    output_lines.append(f"\n   DISCOVERED VULNERABLE CLASS AND LINE:")
                    file_path = vuln.get('file_path', 'Unknown')
                    line_number = vuln.get('line_number', 'Unknown')
                    output_lines.append(f"   File: {file_path}")
                    output_lines.append(f"   Line: {line_number}")
                    
                    output_lines.append(f"\n   SHORT ONE-LINER DESCRIPTION:")
                    description = vuln.get('description', 'No description available')
                    output_lines.append(f"   {description}")
                    
                    output_lines.append(f"\n   EXPLOIT METHOD:")
                    exploit_method = vuln.get('exploitation_method', 'Unknown')
                    output_lines.append(f"   {exploit_method}")
                    
                    # Generate enhanced exploit payload if applicable
                    exploit_info = self._generate_enhanced_exploit_payload(vuln)
                    if exploit_info:
                        output_lines.append(f"\n   🚀 EXPLOIT PAYLOAD:")
                        output_lines.append(f"   ADB Command: {exploit_info.get('adb_command', 'N/A')}")
                        output_lines.append(f"   External Tool: {exploit_info.get('external_tool', 'N/A')}")
                        output_lines.append(f"   Exploit Type: {exploit_info.get('exploit_type', 'N/A')}")
                        output_lines.append(f"   Severity: {exploit_info.get('severity', 'N/A')}")
                    
                    output_lines.append("\n" + "-" * 40)
            
            # Legacy summary
            output_lines.append("\n" + "=" * 80)
            output_lines.append("📊 SCAN SUMMARY")
            output_lines.append("=" * 80)
            
            # Count by severity
            severity_counts = {}
            for vuln in self.vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                output_lines.append(f"{severity}: {count} vulnerabilities")
        
        return "\n".join(output_lines)
    
    def _generate_json_output(self) -> str:
        """Generate enhanced JSON output with separated results and exploit information."""
        if self.regex_vulnerabilities or self.ai_vulnerabilities:
            # Enhanced output format
            output_data = {
                "scan_info": {
                    "scan_date": datetime.now().isoformat(),
                    "total_vulnerabilities": len(self.regex_vulnerabilities) + len(self.ai_vulnerabilities),
                    "scan_methods": ["regex", "ai"],
                    "output_format": "enhanced_with_exploits"
                },
                "regex_scan_results": {
                    "total_vulnerabilities": len(self.regex_vulnerabilities),
                    "vulnerabilities": self._enhance_vulnerabilities_with_exploits(self.regex_vulnerabilities, "regex")
                },
                "ai_scan_results": {
                    "total_vulnerabilities": len(self.ai_vulnerabilities),
                    "vulnerabilities": self._enhance_vulnerabilities_with_exploits(self.ai_vulnerabilities, "ai")
                },
                "summary": {
                    "severity_breakdown": self._get_severity_breakdown(),
                    "method_breakdown": {
                        "regex": len(self.regex_vulnerabilities),
                        "ai": len(self.ai_vulnerabilities)
                    },
                    "exploit_availability": {
                        "adb_commands": "Available for most vulnerabilities",
                        "external_tools": "Recommended for complex exploits",
                        "severity_levels": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIVE"]
                    }
                }
            }
        else:
            # Legacy output format
            output_data = {
                "scan_info": {
                    "scan_date": datetime.now().isoformat(),
                    "total_vulnerabilities": len(self.vulnerabilities),
                    "scan_methods": ["legacy"],
                    "output_format": "legacy"
                },
                "vulnerabilities": self._enhance_vulnerabilities_with_exploits(self.vulnerabilities, "legacy")
            }
        
        return json.dumps(output_data, indent=2, ensure_ascii=False)
    
    def _enhance_vulnerabilities_with_exploits(self, vulnerabilities: List[Dict[str, Any]], method: str) -> List[Dict[str, Any]]:
        """Enhance vulnerabilities with exploit information."""
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            enhanced_vuln = vuln.copy()
            
            # Add exploit information
            if method == "regex":
                category = vuln.get('category', 'Unknown')
                subcategory = vuln.get('subcategory', 'Unknown')
            elif method == "ai":
                category = vuln.get('additional_info', {}).get('category', 'Unknown')
                subcategory = vuln.get('additional_info', {}).get('subcategory', 'Unknown')
            else:  # legacy
                category = vuln.get('category', 'Unknown')
                subcategory = vuln.get('subcategory', 'Unknown')
            
            exploit_info = get_comprehensive_exploit_payload(category, subcategory)
            enhanced_vuln['exploit'] = exploit_info
            
            # Add detection method
            enhanced_vuln['detection_method'] = method
            
            enhanced_vulns.append(enhanced_vuln)
        
        return enhanced_vulns
    
    def _group_vulnerabilities_by_category(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by category."""
        categories = {}
        
        for vuln in vulnerabilities:
            if 'category' in vuln:
                category = vuln['category']
            elif 'additional_info' in vuln:
                category = vuln['additional_info'].get('category', 'Unknown')
            else:
                category = 'Unknown'
            
            if category not in categories:
                categories[category] = []
            categories[category].append(vuln)
        
        return categories
    
    def _generate_enhanced_exploit_payload(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate enhanced exploit payload for vulnerabilities."""
        category = vuln.get('category', 'Unknown')
        subcategory = vuln.get('subcategory', 'Unknown')
        
        if category != 'Unknown' and subcategory != 'Unknown':
            return get_comprehensive_exploit_payload(category, subcategory)
        
        return None
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get severity breakdown for all vulnerabilities."""
        severity_counts = {}
        all_vulns = self.regex_vulnerabilities + self.ai_vulnerabilities
        
        for vuln in all_vulns:
            severity = None
            
            if 'severity' in vuln:
                severity = vuln['severity']
            elif 'additional_info' in vuln:
                severity = vuln['additional_info'].get('severity', 'Unknown')
            
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts
    
    # Legacy methods for backward compatibility
    def _generate_adb_payload(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Generate ADB payload for legacy vulnerabilities."""
        exploit_info = self._generate_enhanced_exploit_payload(vuln)
        if exploit_info:
            return exploit_info.get('adb_command', 'N/A')
        return None
    
    def save_results(self, results: Dict[str, Any], output_format: str, output_name: str) -> str:
        """Save enhanced scan results to file."""
        try:
            # Determine output filename
            if output_format == 'json':
                filename = f"{output_name}_enhanced.json"
            else:
                filename = f"{output_name}_enhanced.txt"
            
            # Generate output content
            if output_format == 'json':
                content = self._generate_json_output()
            else:
                content = self._generate_txt_output()
            
            # Write to file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return filename
            
        except Exception as e:
            raise Exception(f"Error saving results: {e}")
