#!/usr/bin/env python3
"""
AI Scanner Module for GrepAPK
Handles all AI-based vulnerability scanning logic.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

logger = logging.getLogger(__name__)


class AIScanner:
    """Handles AI-based vulnerability scanning for Android APK code."""
    
    def __init__(self, ai_detector=None, verbose: bool = False):
        self.ai_detector = ai_detector
        self.verbose = verbose
        self.vulnerabilities = []
        self.vulnerabilities_lock = threading.Lock()
        self._processed_files = set()
        self._model_cache = {} 
        
    def is_available(self) -> bool:
        """Check if AI detection is available."""
        return self.ai_detector is not None
    
    def scan_directory(self, target_path, max_workers: int = 8, timeout: int = 300) -> List[Dict[str, Any]]:
        """Perform AI-powered vulnerability detection on target directory."""
        if not self.is_available():
            if self.verbose:
                print("⚠️  AI detection not available, skipping AI scan")
            return []
        
        if isinstance(target_path, str):
            target_path = Path(target_path)
        
        if self.verbose:
            print("🤖 Starting AI-powered vulnerability detection...")
        
        try:
            source_files = self._get_source_files(target_path)
            
            if self.verbose:
                print(f"📁 AI analyzing {len(source_files)} source files...")
            
            # Process files with AI detection
            batch_size = 16  # Optimal batch size for AI processing
            total_files = len(source_files)
            
            # Process files in batches for better performance
            for i in range(0, total_files, batch_size):
                batch_files = source_files[i:i + batch_size]
                if self.verbose:
                    print(f"🤖 Processing AI batch {i//batch_size + 1}/{(total_files + batch_size - 1)//batch_size}")
                
                self._process_ai_batch(batch_files, max_workers, timeout)
            
            if self.verbose:
                print(f"✅ AI scan completed - found {len(self.vulnerabilities)} AI-enhanced vulnerabilities")
            
            return self.vulnerabilities
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Error during AI scan: {e}")
            return []
    
    def _process_ai_batch(self, batch_files: List[Path], max_workers: int, timeout: int) -> None:
        """Process a batch of files with optimized AI detection."""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self._analyze_single_file, file_path): file_path 
                for file_path in batch_files
            }

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    future.result(timeout=timeout)
                except Exception as e:
                    if self.verbose:
                        logger.warning(f"AI analysis failed for {file_path}: {e}")
    
    def _analyze_single_file(self, file_path: Path) -> None:
        """Analyze a single file using comprehensive AI detection."""
        try:
            if file_path in self._processed_files:
                return
            
            # Read file content
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                if self.verbose:
                    logger.warning(f"Could not read {file_path}: {e}")
                return
            
            if len(content.strip()) < 10:
                return
            
            if self.ai_detector:
                try:
                    ai_vulnerabilities = self.ai_detector.analyze_code_file(file_path, content)
                    
                    if ai_vulnerabilities:
                        for ai_vuln in ai_vulnerabilities:
                            vuln = {
                                'discovered_vulnerability_title': ai_vuln.description,
                                'discovered_vulnerable_class_and_line': {
                                    'file_path': ai_vuln.file_path,
                                    'line_number': ai_vuln.line_number,
                                    'line_content': ai_vuln.line_content
                                },
                                'short_one_liner_description': ai_vuln.description,
                                'exploit_method': 'AI Detected',
                                'exploitation_scenario': ai_vuln.exploitation_scenario,
                                'additional_info': {
                                    'category': ai_vuln.category,
                                    'subcategory': ai_vuln.subcategory,
                                    'severity': ai_vuln.severity,
                                    'detection_method': 'ai_comprehensive',
                                    'confidence_score': ai_vuln.confidence_score,
                                    'security_impact': 'High' if ai_vuln.severity == 'HIGH' else 'Medium',
                                    'remediation_priority': 'P1' if ai_vuln.severity == 'HIGH' else 'P2',
                                    'timestamp': datetime.now().isoformat(),
                                    'package_name': 'AI Detected',
                                    'component_name': 'AI Detected',
                                    'ai_analysis': ai_vuln.ai_analysis
                                }
                            }
                            
                            with self.vulnerabilities_lock:
                                self.vulnerabilities.append(vuln)
                        
                        if self.verbose:
                            print(f"🤖 AI found {len(ai_vulnerabilities)} vulnerabilities in {file_path.name}")
                    
                except Exception as e:
                    if self.verbose:
                        logger.error(f"AI analysis failed for {file_path}: {e}")
            
            self._processed_files.add(file_path)
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Error analyzing {file_path}: {e}")
    
    def _get_source_files(self, target_path: Path) -> List[Path]:
        """Get all source files for AI analysis with optimization."""
        java_files = list(target_path.rglob("*.java")) + list(target_path.rglob("*.kt"))
        xml_files = list(target_path.rglob("*.xml"))
        smali_files = list(target_path.rglob("*.smali"))
        
        all_source_files = java_files + xml_files + smali_files
        filtered_files = []
        
        for file_path in all_source_files:
            file_path_str = str(file_path)
            
            if any(build_dir in file_path_str for build_dir in ['build', 'bin', 'obj', 'target', 'out', 'dist']):
                continue
            
            if any(test_dir in file_path_str for test_dir in ['test', 'tests', 'androidTest']):
                continue
            
            if any(generated in file_path_str for generated in ['R.java', 'BuildConfig.java', 'Manifest.java']):
                continue

            try:
                max_size = 500 * 1024  # 500KB file size limit
                if file_path.stat().st_size > max_size:
                    continue
            except Exception:
                continue
            
            # File type filtering
            if file_path.suffix.lower() in ['.java', '.kt', '.xml', '.smali']:
                filtered_files.append(file_path)
        
        if self.verbose:
            print(f"📁 Found {len(filtered_files)} source files for AI analysis")
        
        return filtered_files
    
    def _add_ai_vulnerability(self, file_path: Path, assessment: Any) -> None:
        """Add AI-detected vulnerability to the list."""
        try:
            category = self._map_ai_vulnerability_type(assessment.vulnerability_type)
            subcategory = 'ai_detected'
            
            vulnerability = {
                'timestamp': datetime.now().isoformat(),
                'file_path': str(file_path),
                'line_number': assessment.line_numbers[0] if assessment.line_numbers else 0,
                'category': category,
                'subcategory': subcategory,
                'title': f"AI-Detected {assessment.vulnerability_type.replace('_', ' ').title()}",
                'description': assessment.context_analysis,
                'severity': assessment.severity_level,
                'pattern': 'AI_ANALYSIS',
                'matched_text': assessment.code_context[:200] + '...' if len(assessment.code_context) > 200 else assessment.code_context,
                'exploitation_method': self._get_ai_exploitation_method(assessment),
                'recommendation': assessment.remediation_suggestions[0] if assessment.remediation_suggestions else 'Review code for security issues',
                'confidence_score': assessment.confidence_score,
                'detection_method': 'ai',
                'ai_assessment': {
                    'confidence_score': assessment.confidence_score,
                    'false_positive_probability': assessment.false_positive_probability,
                    'exploitation_difficulty': assessment.exploitation_difficulty,
                    'remediation_suggestions': assessment.remediation_suggestions
                }
            }
            
            with self.vulnerabilities_lock:
                self.vulnerabilities.append(vulnerability)
                
        except Exception as e:
            if self.verbose:
                logger.warning(f"Error adding AI vulnerability: {e}")
    
    def _map_ai_vulnerability_type(self, ai_type: str) -> str:
        """Map AI vulnerability types to our standard categories."""
        type_mapping = {
            'sql_injection': 'input_validation',
            'command_injection': 'input_validation',
            'path_traversal': 'input_validation',
            'xss': 'insecure_components',
            'hardcoded_secrets': 'hardcoded_secrets',
            'insecure_components': 'insecure_components'
        }
        return type_mapping.get(ai_type, 'ai_detected')
    
    def _get_ai_exploitation_method(self, assessment: Any) -> str:
        """Get exploitation method based on AI assessment."""
        try:
            difficulty = assessment.exploitation_difficulty.lower()
            if 'easy' in difficulty:
                return 'ADB'
            elif 'medium' in difficulty:
                return 'ADB + Exploitation'
            else:
                return 'Advanced Exploitation'
        except Exception:
            return 'Advanced Exploitation'
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the AI model being used."""
        if not self.is_available():
            return {
                'model_name': 'Not Available',
                'device': 'Not Available',
                'vulnerability_types': []
            }
        
        try:
            return self.ai_detector.get_model_info()
        except Exception:
            return {
                'model_name': 'Unknown',
                'device': 'Unknown',
                'vulnerability_types': []
            }
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of AI scan results."""
        return {
            'total_findings': len(self.vulnerabilities),
            'findings_by_category': self._group_findings_by_category(),
            'findings_by_severity': self._group_findings_by_severity(),
            'ai_model_info': self.get_model_info()
        }
    
    def _group_findings_by_category(self) -> Dict[str, int]:
        """Group findings by vulnerability category."""
        categories = {}
        for vuln in self.vulnerabilities:
            cat = vuln['category']
            categories[cat] = categories.get(cat, 0) + 1
        return categories
    
    def _group_findings_by_severity(self) -> Dict[str, int]:
        """Group findings by severity level."""
        severities = {}
        for vuln in self.vulnerabilities:
            sev = vuln['severity']
            severities[sev] = severities.get(sev, 0) + 1
        return severities
    
    def clear_results(self) -> None:
        """Clear all scan results."""
        with self.vulnerabilities_lock:
            self.vulnerabilities.clear()
    
    def get_ai_enhanced_description(self, vuln: Dict[str, Any], ai_assessment: Optional[Any]) -> str:
        """Get AI-enhanced vulnerability description."""
        if ai_assessment:
            return f"AI Analysis: {ai_assessment.context_analysis} (Confidence: {ai_assessment.confidence_score:.2f})"
        else:
            return vuln.get('description', 'No description')
    
    def get_ai_enhanced_severity(self, vuln: Dict[str, Any], ai_assessment: Optional[Any]) -> str:
        """Get AI-enhanced vulnerability severity."""
        if ai_assessment:
            return ai_assessment.severity_level
        else:
            # Map confidence score to severity
            confidence = vuln.get('confidence_score', 0.0)
            if confidence > 0.8:
                return 'HIGH'
            elif confidence > 0.6:
                return 'MEDIUM'
            else:
                return 'LOW'
    
    def get_ai_enhanced_recommendation(self, vuln: Dict[str, Any], ai_assessment: Optional[Any]) -> str:
        """Get AI-enhanced vulnerability recommendation."""
        if ai_assessment and ai_assessment.remediation_suggestions:
            return ' | '.join(ai_assessment.remediation_suggestions)
        else:
            return 'Review code for security issues'
