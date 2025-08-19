#!/usr/bin/env python3
"""
Consolidated Enhanced Regex Scanner for GrepAPK
Incorporates intelligent false positive reduction with ICC-specific logic.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime

from config.vulnerability_patterns import is_false_positive, is_icc_vulnerability, get_vulnerability_title, get_exploitation_method, get_exploitation_scenario

logger = logging.getLogger(__name__)

class EnhancedRegexScanner:
    """
    Enhanced regex scanner with intelligent false positive detection.
    ICC vulnerabilities are NEVER filtered out as false positives.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.vulnerabilities = []
        
        # Security context patterns for non-ICC vulnerabilities
        self.security_indicators = {
            'safe_exported': [
                r'android:permission\s*=\s*["\'][^"\']+["\']',
                r'android:grantUriPermissions\s*=\s*["\']true["\']',
                r'android:readPermission\s*=\s*["\'][^"\']+["\']',
                r'android:writePermission\s*=\s*["\'][^"\']+["\']',
                r'android:exported\s*=\s*["\']false["\']'
            ],
            'safe_intent_filters': [
                r'android:scheme\s*=\s*["\']https?://',
                r'android:host\s*=\s*["\']localhost["\']',
                r'android:host\s*=\s*["\']127\.0\.0\.1["\']',
                r'android:host\s*=\s*["\']::1["\']',
                r'android:autoVerify\s*=\s*["\']true["\']'
            ],
            'safe_webview': [
                r'webView\.getSettings\(\)\.setAllowFileAccess\s*\(\s*false\s*\)',
                r'webView\.getSettings\(\)\.setAllowContentAccess\s*\(\s*false\s*\)',
                r'webView\.getSettings\(\)\.setJavaScriptEnabled\s*\(\s*false\s*\)'
            ],
            'safe_network': [
                r'android:networkSecurityConfig\s*=\s*["\'][^"\']+["\']',
                r'android:usesCleartextTraffic\s*=\s*["\']false["\']'
            ]
        }
        
        # Severity levels for different vulnerability types
        self.severity_levels = {
            'HIGH': [
                'hardcoded_secrets.api_keys',
                'hardcoded_secrets.tokens',
                'hardcoded_secrets.passwords',
                'insecure_webview.javascript_interface',
                'input_validation.sql_injection',
                'input_validation.command_injection',
                'insecure_icc.task_hijacking',
                'insecure_icc.intent_spoofing',
                'insecure_icc.deep_link_vulnerabilities'
            ],
            'MEDIUM': [
                'insecure_icc.exported_activities',
                'insecure_icc.exported_services',
                'insecure_icc.exported_receivers',
                'insecure_icc.exported_providers',
                'insecure_icc.implicit_intents',
                'insecure_icc.exported_without_protection',
                'insecure_network.cleartext_traffic',
                'insecure_network.accept_all_certs',
                'code_debug_config.debuggable_enabled'
            ],
            'LOW': [
                'hardcoded_secrets.backend_urls',
                'hardcoded_secrets.base64_encoded',
                'input_validation.xss',
                'input_validation.path_traversal',
                'code_debug_config.backup_allowed'
            ]
        }
    
    def scan_file(self, file_path: Path, patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_vulnerabilities = []
            
            for category, subcategories in patterns.items():
                for subcategory, pattern_list in subcategories.items():
                    if isinstance(pattern_list, list):
                        for pattern in pattern_list:
                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                            for match in matches:
                                line_number = content[:match.start()].count('\n') + 1
                                line_content = match.group()
                                
                                # CRITICAL: ICC vulnerabilities are NEVER filtered out
                                if is_icc_vulnerability(category, subcategory):
                                    if self.verbose:
                                        print(f"🔍 ICC vulnerability detected: {category}.{subcategory} in {file_path.name}:{line_number}")
                                    
                                    vulnerability = self._create_vulnerability(
                                        file_path, line_number, line_content, 
                                        category, subcategory, pattern, line_content
                                    )
                                    file_vulnerabilities.append(vulnerability)
                                    continue
                                
                                # For non-ICC vulnerabilities, apply minimal false positive filtering
                                if not self._is_false_positive(category, subcategory, line_content, content):
                                    vulnerability = self._create_vulnerability(
                                        file_path, line_number, line_content, 
                                        category, subcategory, pattern, line_content
                                    )
                                    file_vulnerabilities.append(vulnerability)
            
            return file_vulnerabilities
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error scanning {file_path}: {e}")
            return []
    
    def _is_false_positive(self, category: str, subcategory: str, line_content: str, content: str) -> bool:
        """
        Simplified false positive detection that NEVER filters out ICC vulnerabilities.
        """
        if is_icc_vulnerability(category, subcategory):
            return False

        line_lower = line_content.lower()

        if line_content.strip().startswith('//') or line_content.strip().startswith('#'):
                return True

        if any(word in line_lower for word in ['example', 'test', 'sample', 'demo', 'placeholder']):
                return True

        if self._has_safe_security_context(line_content, content, category):
                return True
        
        return False
    
    def _has_safe_security_context(self, line_content: str, content: str, category: str) -> bool:
        """Check if the vulnerability has safe security context."""
        if category == 'insecure_icc':
            return self._is_legitimate_export(line_content, content)
        
        for indicator_type, patterns in self.security_indicators.items():
            for pattern in patterns:
                if re.search(pattern, line_content, re.IGNORECASE):
                    return True
        
        return False
    
    def _is_legitimate_export(self, line_content: str, content: str) -> bool:
        """Check if this is a legitimate exported component."""
        if ('android.intent.action.MAIN' in content and 
            'android.intent.category.LAUNCHER' in content and
            'android:exported="true"' in line_content):
                return True

        if 'android:name="android.' in line_content:
                return True

        if self._has_proper_permissions(line_content, content):
                return True
        
        return False
    
    def _has_proper_permissions(self, line_content: str, content: str) -> bool:
        """Check if the component has proper security permissions."""
        permission_patterns = [
            r'android:permission\s*=\s*["\'][^"\']+["\']',
            r'android:readPermission\s*=\s*["\'][^"\']+["\']',
            r'android:writePermission\s*=\s*["\'][^"\']+["\']',
            r'android:grantUriPermissions\s*=\s*["\']true["\']'
        ]
        
        for pattern in permission_patterns:
            if re.search(pattern, line_content, re.IGNORECASE):
                    return True
        
        return False
    
    def _create_vulnerability(self, file_path: Path, line_number: int, line_content: str, 
                             category: str, subcategory: str, pattern: str, matched_text: str) -> Dict[str, Any]:
        """Create a vulnerability entry with enhanced information."""
        try:
            package_name, component_name = self._extract_package_and_component(file_path, line_content, category, line_number)

            exploitation_scenario = get_exploitation_scenario(category, subcategory, package_name, component_name)

            title = get_vulnerability_title(category, subcategory)
            description = self._generate_vulnerability_description(category, subcategory, matched_text, line_content)

            severity = self._determine_severity(category, subcategory, matched_text)
            confidence_score = self._calculate_confidence_score(category, subcategory, matched_text, line_content)
            
            vulnerability = {
                'discovered_vulnerability_title': title,
                'discovered_vulnerable_class_and_line': {
                    'file_path': str(file_path),
                    'line_number': line_number,
                    'line_content': line_content.strip()
                },
                'short_one_liner_description': description,
                'exploit_method': get_exploitation_method(category, subcategory),
                'exploitation_scenario': exploitation_scenario,
                'additional_info': {
                    'category': category,
                    'subcategory': subcategory,
                    'severity': severity,
                    'detection_method': 'regex_enhanced',
                    'confidence_score': confidence_score,
                    'matched_pattern': pattern,
                    'matched_text': matched_text[:200] + '...' if len(matched_text) > 200 else matched_text,
                    'timestamp': datetime.now().isoformat(),
                    'package_name': package_name,
                    'component_name': component_name,
                    'security_impact': self._assess_security_impact(category, subcategory),
                    'remediation_priority': self._get_remediation_priority(severity, confidence_score)
                }
            }
            
            return vulnerability
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error creating vulnerability: {e}")
            return None
    
    def _generate_vulnerability_description(self, category: str, subcategory: str, matched_text: str, line_content: str) -> str:
        """Generates a more detailed description for the vulnerability."""
        base_description = get_vulnerability_title(category, subcategory)
        
        if 'android:exported="true"' in matched_text:
            base_description += " (exported component)"
        if 'android:permission' in matched_text:
            base_description += " (with permission)"
        if 'android:grantUriPermissions="true"' in matched_text:
            base_description += " (with grantUriPermissions)"
        if 'android:scheme="https://"' in matched_text or 'android:scheme="http://"' in matched_text:
            base_description += " (with scheme)"
        if 'android:host="localhost"' in matched_text or 'android:host="127.0.0.1"' in matched_text or 'android:host="::1"' in matched_text:
            base_description += " (with host)"
        if 'android:autoVerify="true"' in matched_text:
            base_description += " (with autoVerify)"
        if 'webView.getSettings().setAllowFileAccess(false)' in matched_text:
            base_description += " (with webView settings)"
        if 'android:networkSecurityConfig' in matched_text:
            base_description += " (with network security config)"
        if 'android:usesCleartextTraffic="false"' in matched_text:
            base_description += " (with cleartext traffic)"

        if 'android:name=' in line_content:
            base_description += f" in {line_content.strip()}"
        
        return base_description
    
    def _assess_security_impact(self, category: str, subcategory: str) -> str:
        """Assesses the security impact of a vulnerability."""
        if is_icc_vulnerability(category, subcategory):
            return "High"

        if 'hardcoded_secrets' in category:
            return "High"
        if 'insecure_webview' in category:
            return "Medium"
        if 'insecure_network' in category:
            return "Medium"
        if 'insecure_icc' in category:
            return "Medium"
        if 'input_validation' in category:
            return "Low"
        if 'code_debug_config' in category:
            return "Low"
        
        return "Unknown"
    
    def _get_remediation_priority(self, severity: str, confidence_score: float) -> str:
        """Determines the remediation priority based on severity and confidence."""
        if severity == 'HIGH':
            return 'P1' # Critical
        if severity == 'MEDIUM':
            return 'P2' # High
        if confidence_score < 0.7:
            return 'P3' # Medium
        return 'P4' # Low
    
    def _extract_package_and_component(self, file_path: Path, line_content: str, category: str, line_number: int = 0) -> tuple[str, str]:
        """Extract package name and component name from file path and content."""
        package_name = "com.example.app"  # Default fallback
        component_name = "MainActivity"    # Default fallback
        
        try:
            if "AndroidManifest.xml" in str(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        manifest_content = f.read()
                        package_match = re.search(r'package="([^"]+)"', manifest_content)
                        if package_match:
                            package_name = package_match.group(1)
                            if self.verbose:
                                print(f"📦 Extracted package: {package_name}")
                except Exception as e:
                    if self.verbose:
                        print(f"⚠️ Could not read AndroidManifest.xml: {e}")

                if category == 'insecure_icc':
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            manifest_lines = f.readlines()
                            for i in range(max(0, line_number - 5), min(len(manifest_lines), line_number + 5)):
                                line = manifest_lines[i]
                                if 'android:name=' in line:
                                    component_match = re.search(r'android:name="([^"]+)"', line)
                                    if component_match:
                                        full_component = component_match.group(1)
                                        component_name = full_component.split('.')[-1]
                                        if self.verbose:
                                            print(f"🔧 Extracted component: {component_name}")
                                        break
                    except Exception as e:
                        if self.verbose:
                            print(f"⚠️ Could not read manifest for component extraction: {e}")
                    
                    if component_name == "MainActivity" and 'android:name=' in line_content:
                        component_match = re.search(r'android:name="([^"]+)"', line_content)
                        if component_match:
                            full_component = component_match.group(1)
                            component_name = full_component.split('.')[-1]
                            if self.verbose:
                                print(f"🔧 Extracted component from current line: {component_name}")
                
                else:
                    if 'android:name=' in line_content:
                        component_match = re.search(r'android:name="([^"]+)"', line_content)
                        if component_match:
                            full_component = component_match.group(1)
                            component_name = full_component.split('.')[-1]
                            if self.verbose:
                                print(f"🔧 Extracted component for non-ICC: {component_name}")
            
            elif file_path.suffix in ['.java', '.kt']:
                # Extract class name from file path
                component_name = file_path.stem
                if self.verbose:
                    print(f"🔧 Extracted component from file path: {component_name}")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        package_match = re.search(r'package\s+([^;]+);', content)
                        if package_match:
                            package_name = package_match.group(1).strip()
                            if self.verbose:
                                print(f"📦 Extracted package from Java/Kotlin: {package_name}")
                except Exception:
                    pass
            
            # For Smali files, try to extract class name and package
            elif file_path.suffix == '.smali':
                # Extract class name from file path
                component_name = file_path.stem
                if self.verbose:
                    print(f"🔧 Extracted component from Smali: {component_name}")
                
                # Try to extract package from smali file content
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Look for .class directive
                        class_match = re.search(r'\.class\s+([^;]+);', content)
                        if class_match:
                            full_class = class_match.group(1)
                            # Extract package and class name
                            parts = full_class.split('/')
                            if len(parts) > 1:
                                package_name = '.'.join(parts[:-1])
                                component_name = parts[-1]
                                if self.verbose:
                                    print(f"📦 Extracted from Smali - Package: {package_name}, Component: {component_name}")
                except Exception:
                    pass
                    
        except Exception as e:
            if self.verbose:
                print(f"⚠️ Error in package/component extraction: {e}")
        
        return package_name, component_name
    
    def _determine_severity(self, category: str, subcategory: str, matched_text: str) -> str:
        """Determine the severity level of a vulnerability."""
        full_category = f"{category}.{subcategory}"
        
        for level, categories in self.severity_levels.items():
            if full_category in categories:
                return level
        
        # Fallback for non-standard categories or specific patterns
        if 'hardcoded_secrets' in category:
            return 'HIGH'
        if 'insecure_webview' in category:
            return 'MEDIUM'
        if 'insecure_network' in category:
            return 'MEDIUM'
        if 'insecure_icc' in category:
            return 'MEDIUM'
        if 'input_validation' in category:
            return 'LOW'
        if 'code_debug_config' in category:
            return 'LOW'
        
        return 'MEDIUM'  # Default severity
    
    def _calculate_confidence_score(self, category: str, subcategory: str, matched_text: str, line_content: str) -> float:
        """Calculate confidence score for the vulnerability detection."""
        base_score = 0.5
        
        # ICC vulnerabilities get higher confidence
        if is_icc_vulnerability(category, subcategory):
            base_score = 0.8
        
        # Adjust based on context
        if 'android:exported="true"' in matched_text:
            base_score += 0.2
        
        if 'android:permission' in matched_text:
            base_score -= 0.1
        
        # Ensure score is within bounds
        return max(0.1, min(1.0, base_score))
    
    def scan_directory(self, directory: str, patterns: Dict[str, Any], 
                      max_workers: int = 4) -> List[Dict[str, Any]]:
        """Scan a directory for vulnerabilities using multiple threads."""
        if self.verbose:
            print(f"🔍 Scanning directory: {directory}")
        
        directory_path = Path(directory)
        if not directory_path.exists() or not directory_path.is_dir():
            if self.verbose:
                print(f"❌ Directory does not exist: {directory}")
            return []
        
        # Get all files to scan
        files_to_scan = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.java', '.kt', '.xml', '.smali', '.gradle', '.properties')):
                    file_path = Path(root) / file
                    files_to_scan.append(file_path)
        
        if self.verbose:
            print(f"📁 Found {len(files_to_scan)} files to scan")
        
        # Scan files using thread pool
        all_vulnerabilities = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.scan_file, file_path, patterns): file_path 
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_vulnerabilities = future.result()
                    all_vulnerabilities.extend(file_vulnerabilities)
                    
                    if file_vulnerabilities and self.verbose:
                        print(f"✅ {file_path.name}: {len(file_vulnerabilities)} vulnerabilities found")
                        
                except Exception as e:
                    if self.verbose:
                        print(f"❌ Error scanning {file_path}: {e}")
        
        if self.verbose:
            print(f"🎯 Total vulnerabilities found: {len(all_vulnerabilities)}")
        
        return all_vulnerabilities
    
    def get_scan_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of the scan results."""
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'severity_breakdown': {},
                'category_breakdown': {},
                'detection_methods': {}
            }
        
        # Severity breakdown
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('additional_info', {}).get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Category breakdown
        category_counts = {}
        for vuln in vulnerabilities:
            category = vuln.get('additional_info', {}).get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Detection methods breakdown
        method_counts = {}
        for vuln in vulnerabilities:
            method = vuln.get('detection_method', 'unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'detection_methods': method_counts
        }
