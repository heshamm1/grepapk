#!/usr/bin/env python3
"""
Output Manager for GrepAPK
Manages and formats vulnerability findings output in various formats.
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import click

class OutputManager:
    """Manages output formatting for GrepAPK vulnerability findings."""
    
    def __init__(self, output_format: str = 'txt', output_file: Optional[str] = None):
        self.output_format = output_format.lower()
        self.output_file = output_file
        self.vulnerabilities = []
        
    def add_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Add vulnerabilities to the output manager."""
        self.vulnerabilities.extend(vulnerabilities)
    
    def generate_output(self) -> str:
        """Generate output in the specified format."""
        if self.output_format == 'json':
            return self._generate_json_output()
        else:
            return self._generate_txt_output()
    
    def _generate_txt_output(self) -> str:
        """Generate text output with the requested format."""
        if not self.vulnerabilities:
            return "No vulnerabilities found.\n"
        
        output_lines = []
        output_lines.append("=" * 80)
        output_lines.append("🔒 GREPAPK VULNERABILITY SCAN REPORT")
        output_lines.append("=" * 80)
        output_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
                
                # Generate ADB payload if applicable
                adb_payload = self._generate_adb_payload(vuln)
                if adb_payload:
                    output_lines.append(f"\n   ADB PAYLOAD:")
                    output_lines.append(f"   {adb_payload}")
                
                output_lines.append("\n" + "-" * 40)
        
        # Add summary
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
        
        # Count by detection method
        method_counts = {}
        for vuln in self.vulnerabilities:
            method = vuln.get('detection_method', 'Unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
        
        output_lines.append("\nDetection Methods:")
        for method, count in method_counts.items():
            output_lines.append(f"  {method}: {count} findings")
        
        return "\n".join(output_lines)
    
    def _generate_json_output(self) -> str:
        """Generate JSON output with the requested format."""
        if not self.vulnerabilities:
            return json.dumps({"vulnerabilities": [], "summary": {}}, indent=2)
        
        # Format vulnerabilities according to specifications
        formatted_vulns = []
        for vuln in self.vulnerabilities:
            formatted_vuln = {
                "discovered_vulnerability_title": vuln.get('title', 'Unknown Vulnerability'),
                "discovered_vulnerable_class_and_line": {
                    "file_path": vuln.get('file_path', 'Unknown'),
                    "line_number": vuln.get('line_number', 'Unknown')
                },
                "short_one_liner_description": vuln.get('description', 'No description available'),
                "exploit_method": vuln.get('exploitation_method', 'Unknown'),
                "adb_payload": self._generate_adb_payload(vuln),
                "additional_info": {
                    "category": vuln.get('category', 'Unknown'),
                    "severity": vuln.get('severity', 'Unknown'),
                    "detection_method": vuln.get('detection_method', 'Unknown'),
                    "confidence_score": vuln.get('confidence_score', 0.0),
                    "timestamp": vuln.get('timestamp', datetime.now().isoformat())
                }
            }
            formatted_vulns.append(formatted_vuln)
        
        # Generate summary
        severity_counts = {}
        method_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            method = vuln.get('detection_method', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            method_counts[method] = method_counts.get(method, 0) + 1
        
        summary = {
            "total_vulnerabilities": len(self.vulnerabilities),
            "scan_date": datetime.now().isoformat(),
            "severity_breakdown": severity_counts,
            "detection_methods": method_counts
        }
        
        output = {
            "vulnerabilities": formatted_vulns,
            "summary": summary
        }
        
        return json.dumps(output, indent=2)
    
    def _generate_adb_payload(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Generate accurate ADB payload for the vulnerability."""
        category = vuln.get('category', '')
        subcategory = vuln.get('subcategory', '')
        file_path = vuln.get('file_path', '')
        
        # Extract package name from file path if possible
        package_name = self._extract_package_name(file_path)
        component_name = self._extract_component_name(file_path)
        
        # Generate payloads based on vulnerability type
        if category == 'hardcoded_secrets':
            if subcategory in ['api_keys', 'tokens', 'passwords']:
                return f'adb shell "dumpsys package {package_name} | grep -i {subcategory}"'
            elif subcategory == 'base64_encoded':
                return f'adb shell "dumpsys package {package_name} | grep -E \'[A-Za-z0-9+/]{{32,}}={{0,2}}\'"'
        
        elif category == 'insecure_components':
            if subcategory == 'exported_components':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'payload\' \'test_value\'"'
            elif subcategory == 'webview':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'url\' \'javascript:alert(\\"XSS_TEST\\")\'"'
            elif subcategory == 'content_provider':
                return f'adb shell "content query --uri content://{package_name}/{component_name}"'
        
        elif category == 'intent_vulnerabilities':
            if subcategory == 'intent_spoofing':
                return f'adb shell "am start -W -a android.intent.action.VIEW -d \'ctf://payload\' -n {package_name}/{component_name}"'
            elif subcategory == 'deep_link':
                return f'adb shell "am start -W -a android.intent.action.VIEW -d \'{subcategory}://payload\' -n {package_name}/{component_name}"'
        
        elif category == 'input_validation':
            if subcategory == 'command_injection':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'input\' \'$(cat /data/data/{package_name}/files/secret.txt)\'"'
            elif subcategory == 'path_traversal':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'path\' \'../../../data/data/{package_name}/files/secret.txt\'"'
            elif subcategory == 'sql_injection':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'query\' \'1\' OR \'1\'=\'1\'"'
            elif subcategory == 'xss':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'input\' \'<script>alert(\\"XSS\\")</script>\'"'
        
        elif category == 'security_bypass':
            if subcategory == 'root_detection':
                return f'adb shell "su -c \'am start -W -n {package_name}/{component_name}\'"'
            elif subcategory == 'ssl_pinning':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'bypass_ssl\' \'true\'"'
            elif subcategory == 'debug_mode':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'debug\' \'true\'"'
            elif subcategory == 'secret_parameters':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'secret\' \'let_me_in\'"'
        
        elif category == 'network_security':
            if subcategory == 'cleartext_traffic':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'force_http\' \'true\'"'
            elif subcategory == 'weak_ssl':
                return f'adb shell "am start -W -n {package_name}/{component_name} --es \'weak_ssl\' \'true\'"'
        
        elif category == 'information_disclosure':
            if subcategory == 'logging':
                return f'adb shell "logcat | grep {package_name}"'
            elif subcategory == 'debug_info':
                return f'adb shell "dumpsys package {package_name}"'
        
        elif category == 'file_read':
            return f'adb shell "am start -W -n {package_name}/{component_name} --es \'path\' \'/data/data/{package_name}/files/secret.txt\'"'
        
        # Default payload for unknown types
        return f'adb shell "am start -W -n {package_name}/{component_name}"'
    
    def _extract_package_name(self, file_path: str) -> str:
        """Extract package name from file path."""
        if not file_path:
            return 'com.example.app'
        
        # Try to extract from path structure
        path_parts = file_path.split('/')
        for i, part in enumerate(path_parts):
            if part in ['java', 'kotlin', 'smali'] and i + 1 < len(path_parts):
                # Next part might be the package
                package_part = path_parts[i + 1]
                if '.' in package_part:
                    return package_part
                elif i + 2 < len(path_parts):
                    return f"{package_part}.{path_parts[i + 2]}"
        
        return 'com.example.app'
    
    def _extract_component_name(self, file_path: str) -> str:
        """Extract component name from file path."""
        if not file_path:
            return 'MainActivity'
        
        # Extract filename without extension
        filename = Path(file_path).stem
        
        # Common Android component names
        if filename.endswith('Activity'):
            return filename
        elif filename.endswith('Service'):
            return filename
        elif filename.endswith('Receiver'):
            return filename
        elif filename.endswith('Provider'):
            return filename
        else:
            # Try to find a suitable component name
            if 'main' in filename.lower():
                return 'MainActivity'
            elif 'activity' in filename.lower():
                return f"{filename}Activity"
            else:
                return 'MainActivity'
    
    def save_output(self, output_content: str) -> bool:
        """Save output to file if specified."""
        if not self.output_file:
            return False
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(output_content)
            return True
        except Exception as e:
            print(f"Error saving output to {self.output_file}: {e}")
            return False
    
    def display_output(self, output_content: str):
        """Display output to console and optionally save to file."""
        # Display to console
        print(output_content)
        
        # Save to file if specified
        if self.output_file:
            if self.save_output(output_content):
                print(f"\n✅ Output saved to: {self.output_file}")
            else:
                print(f"\n❌ Failed to save output to: {self.output_file}")
    
    def get_output_summary(self) -> Dict[str, Any]:
        """Get summary of output statistics."""
        if not self.vulnerabilities:
            return {"total": 0, "formats": []}
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "output_format": self.output_format,
            "output_file": self.output_file,
            "categories": list(set(v.get('category', 'Unknown') for v in self.vulnerabilities)),
            "severities": list(set(v.get('severity', 'Unknown') for v in self.vulnerabilities)),
            "detection_methods": list(set(v.get('detection_method', 'Unknown') for v in self.vulnerabilities))
        }
    
    def save_results(self, results: Dict[str, Any], output_format: str, output_name: str) -> str:
        """Save scan results to file in the specified format."""
        # Set the output format
        self.output_format = output_format.lower()

        # Check if this is a tiny scan (framework analysis)
        if results.get('scan_type') == 'TINY':
            return self._save_tiny_scan_results(results, output_name)
        
        # Extract vulnerabilities from results
        vulnerabilities = results.get('vulnerabilities', [])
        self.vulnerabilities = vulnerabilities

        # Generate output content
        output_content = self.generate_output()

        # Determine output filename
        if output_format.lower() == 'json':
            output_filename = f"{output_name}.json"
        else:
            output_filename = f"{output_name}.txt"

        # Save to file
        output_path = Path(output_filename)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output_content)

            return str(output_path.absolute())

        except Exception as e:
            raise Exception(f"Failed to save results to {output_filename}: {e}")

    def _save_tiny_scan_results(self, results: Dict[str, Any], output_name: str) -> str:
        """Save tiny scan results (framework and structure analysis)."""
        if self.output_format == 'json':
            return self._save_tiny_scan_json(results, output_name)
        else:
            return self._save_tiny_scan_txt(results, output_name)

    def _save_tiny_scan_json(self, results: Dict[str, Any], output_name: str) -> str:
        """Save tiny scan results in JSON format."""
        output_filename = f"{output_name}.json"
        output_path = Path(output_filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            return str(output_path.absolute())
        except Exception as e:
            raise Exception(f"Failed to save tiny scan results to {output_filename}: {e}")

    def _save_tiny_scan_txt(self, results: Dict[str, Any], output_name: str) -> str:
        """Save tiny scan results in text format."""
        output_filename = f"{output_name}.txt"
        output_path = Path(output_filename)
        
        try:
            output_content = self._generate_tiny_scan_txt_output(results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output_content)
            
            return str(output_path.absolute())
        except Exception as e:
            raise Exception(f"Failed to save tiny scan results to {output_filename}: {e}")

    def _generate_tiny_scan_txt_output(self, results: Dict[str, Any]) -> str:
        """Generate text output for tiny scan results."""
        output_lines = []
        output_lines.append("=" * 80)
        output_lines.append("🔒 GREPAPK TINY SCAN REPORT - FRAMEWORK & STRUCTURE ANALYSIS")
        output_lines.append("=" * 80)
        output_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output_lines.append(f"Directory: {results.get('directory', 'Unknown')}")
        output_lines.append("")
        
        # Framework Analysis Section
        framework_analysis = results.get('framework_analysis', {})
        output_lines.append("🏗️  FRAMEWORK ANALYSIS")
        output_lines.append("-" * 60)
        output_lines.append(f"Detected Framework: {framework_analysis.get('detected_framework', 'Unknown')}")
        output_lines.append(f"Build System: {framework_analysis.get('build_system', 'Unknown')}")
        output_lines.append(f"Target SDK: {framework_analysis.get('target_sdk', 'Unknown')}")
        output_lines.append(f"Min SDK: {framework_analysis.get('min_sdk', 'Unknown')}")
        
        # Programming Languages
        languages = framework_analysis.get('programming_languages', [])
        if languages:
            output_lines.append(f"Programming Languages: {', '.join(languages)}")
        
        # Package Info
        package_info = framework_analysis.get('package_info', {})
        if package_info.get('package_name'):
            output_lines.append(f"Package Name: {package_info['package_name']}")
        
        # RASP Controls
        rasp_controls = framework_analysis.get('rasp_controls', [])
        if rasp_controls:
            output_lines.append(f"RASP Controls Detected: {', '.join(rasp_controls)}")
        
        # Security Features
        security_features = framework_analysis.get('security_features', [])
        if security_features:
            output_lines.append(f"Security Features: {', '.join(security_features)}")
        
        # Permissions
        permissions = framework_analysis.get('permissions', [])
        if permissions:
            output_lines.append(f"Total Permissions: {len(permissions)}")
            output_lines.append("Key Permissions:")
            for perm in permissions[:10]:  # Show first 10 permissions
                output_lines.append(f"  - {perm}")
            if len(permissions) > 10:
                output_lines.append(f"  ... and {len(permissions) - 10} more")
        
        # Exported Components
        exported_components = framework_analysis.get('exported_components', {})
        if exported_components:
            output_lines.append("Exported Components:")
            for comp_type, comps in exported_components.items():
                if comps:
                    output_lines.append(f"  {comp_type.title()}: {len(comps)}")
                    for comp in comps[:5]:  # Show first 5 of each type
                        output_lines.append(f"    - {comp}")
                    if len(comps) > 5:
                        output_lines.append(f"    ... and {len(comps) - 5} more")
        
        output_lines.append("")
        
        # Structure Analysis Section
        structure_analysis = results.get('structure_analysis', {})
        output_lines.append("📁 STRUCTURE ANALYSIS")
        output_lines.append("-" * 60)
        output_lines.append(f"Total Files: {structure_analysis.get('total_files', 0):,}")
        
        # File Types
        file_types = structure_analysis.get('file_types', {})
        if file_types:
            output_lines.append("File Types:")
            sorted_types = sorted(file_types.items(), key=lambda x: x[1], reverse=True)
            for ext, count in sorted_types[:15]:  # Show top 15 file types
                output_lines.append(f"  {ext}: {count:,}")
            if len(file_types) > 15:
                output_lines.append(f"  ... and {len(file_types) - 15} more types")
        
        # Code Analysis
        code_analysis = structure_analysis.get('code_analysis', {})
        if code_analysis:
            output_lines.append("Code Analysis:")
            output_lines.append(f"  Smali Classes: {code_analysis.get('smali_classes', 0):,}")
            output_lines.append(f"  Java Files: {code_analysis.get('java_files', 0):,}")
            output_lines.append(f"  Kotlin Files: {code_analysis.get('kotlin_files', 0):,}")
            output_lines.append(f"  XML Files: {code_analysis.get('xml_files', 0):,}")
            output_lines.append(f"  DEX Files: {code_analysis.get('dex_files', 0):,}")
        
        # Resource Analysis
        resource_analysis = structure_analysis.get('resource_analysis', {})
        if resource_analysis:
            output_lines.append("Resource Analysis:")
            output_lines.append(f"  Drawable Resources: {resource_analysis.get('drawable_resources', 0)}")
            output_lines.append(f"  Layout Resources: {resource_analysis.get('layout_resources', 0)}")
            output_lines.append(f"  Value Resources: {resource_analysis.get('value_resources', 0)}")
            output_lines.append(f"  Raw Resources: {resource_analysis.get('raw_resources', 0)}")
            output_lines.append(f"  Asset Resources: {resource_analysis.get('asset_resources', 0)}")
        
        # Size Analysis
        size_analysis = structure_analysis.get('size_analysis', {})
        if size_analysis:
            output_lines.append("Size Analysis:")
            output_lines.append(f"  Total Size: {size_analysis.get('total_size_mb', 0)} MB")
            
            file_dist = size_analysis.get('file_size_distribution', {})
            if file_dist:
                output_lines.append("  File Size Distribution:")
                output_lines.append(f"    Tiny (0-1KB): {file_dist.get('tiny', 0):,}")
                output_lines.append(f"    Small (1-10KB): {file_dist.get('small', 0):,}")
                output_lines.append(f"    Medium (10-100KB): {file_dist.get('medium', 0):,}")
                output_lines.append(f"    Large (100KB-1MB): {file_dist.get('large', 0):,}")
                output_lines.append(f"    Huge (1MB+): {file_dist.get('huge', 0):,}")
            
            largest_files = size_analysis.get('largest_files', [])
            if largest_files:
                output_lines.append("  Largest Files:")
                for file_path, size_kb in largest_files[:5]:  # Show top 5
                    output_lines.append(f"    {size_kb} KB: {Path(file_path).name}")
        
        # Security Analysis
        security_analysis = structure_analysis.get('security_analysis', {})
        if security_analysis:
            output_lines.append("Security Analysis:")
            
            native_libs = security_analysis.get('native_libraries', [])
            if native_libs:
                output_lines.append(f"  Native Libraries: {len(native_libs)}")
                for lib in native_libs[:3]:  # Show first 3
                    output_lines.append(f"    - {Path(lib).name}")
                if len(native_libs) > 3:
                    output_lines.append(f"    ... and {len(native_libs) - 3} more")
            
            webview_files = security_analysis.get('webview_files', [])
            if webview_files:
                output_lines.append(f"  WebView Files: {len(webview_files)}")
            
            db_files = security_analysis.get('database_files', [])
            if db_files:
                output_lines.append(f"  Database Files: {len(db_files)}")
            
            cert_files = security_analysis.get('certificate_files', [])
            if cert_files:
                output_lines.append(f"  Certificate Files: {len(cert_files)}")
        
        output_lines.append("")
        output_lines.append("=" * 80)
        output_lines.append("📊 TINY SCAN COMPLETED SUCCESSFULLY")
        output_lines.append("=" * 80)
        
        return "\n".join(output_lines)
