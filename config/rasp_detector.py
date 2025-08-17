#!/usr/bin/env python3
"""
RASP (Runtime Application Self-Protection) Detector for GrepAPK
Advanced detection mechanism analysis using AI for comprehensive security insights.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import logging

class RASPDetector:
    """Advanced RASP detection using AI analysis for comprehensive security insights."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        
        # RASP detection patterns and indicators
        self.rasp_patterns = {
            'root_detection': {
                'file_checks': [
                    r'"/system/bin/su"',
                    r'"/system/xbin/su"',
                    r'"/sbin/su"',
                    r'"/data/local/xbin/su"',
                    r'"/data/local/bin/su"',
                    r'"/system/app/Superuser.apk"',
                    r'"/system/etc/init.d/99SuperSUDaemon"',
                    r'"/dev/com.koushikdutta.superuser.daemon/"',
                    r'"/system/bin/busybox"',
                    r'"/system/xbin/busybox"'
                ],
                'package_checks': [
                    r'com\.topjohnwu\.magisk',
                    r'com\.noshufou\.android\.su',
                    r'com\.thirdparty\.superuser',
                    r'eu\.chainfire\.supersu',
                    r'com\.kingroot\.kinguser',
                    r'com\.kingo\.root',
                    r'com\.alephzain\.framaroot',
                    r'com\.rootcloak\.plus',
                    r'com\.saurik\.substrate',
                    r'de\.robv\.android\.xposed\.installer'
                ],
                'process_checks': [
                    r'getRunningProcesses\s*\(',
                    r'getRunningTasks\s*\(',
                    r'ActivityManager\.getRunningAppProcesses',
                    r'checkRootMethod',
                    r'isRooted',
                    r'hasRootAccess',
                    r'checkRootStatus'
                ],
                'binary_checks': [
                    r'Runtime\.getRuntime\(\)\.exec\s*\(\s*["\']su["\']',
                    r'ProcessBuilder\s*\(\s*\[["\']su["\']',
                    r'which\s+su',
                    r'command\s+su',
                    r'execute\s+su'
                ]
            },
            'frida_detection': {
                'library_checks': [
                    r'libfrida-gum\.so',
                    r'libfrida-core\.so',
                    r'libfrida-agent\.so',
                    r'libxposed\.so',
                    r'libsubstrate\.so',
                    r'libsandhook\.so',
                    r'libepic\.so',
                    r'libtaichi\.so'
                ],
                'process_checks': [
                    r'frida-server',
                    r'frida-helper',
                    r'xposed',
                    r'substrate',
                    r'epic',
                    r'taichi'
                ],
                'memory_patterns': [
                    r'frida_gum_init',
                    r'frida_agent_main',
                    r'xposed_handle_hooked_method',
                    r'substrate_hook',
                    r'epic_hook',
                    r'taichi_hook'
                ],
                'hook_detection': [
                    r'isHooked',
                    r'checkHook',
                    r'detectHook',
                    r'antiHook',
                    r'isMethodHooked',
                    r'hasActiveHooks'
                ]
            },
            'memory_protection': {
                'anti_debug': [
                    r'isDebuggerConnected',
                    r'Debug\.isDebuggerConnected',
                    r'checkDebugger',
                    r'antiDebug',
                    r'isDebugMode',
                    r'checkDebugStatus'
                ],
                'integrity_checks': [
                    r'checkIntegrity',
                    r'verifySignature',
                    r'checkChecksum',
                    r'verifyHash',
                    r'integrityCheck',
                    r'signatureVerification'
                ],
                'obfuscation': [
                    r'stringEncryption',
                    r'codeObfuscation',
                    r'nameMangling',
                    r'controlFlowFlattening',
                    r'deadCodeInsertion',
                    r'instructionSubstitution'
                ],
                'memory_scanning': [
                    r'scanMemory',
                    r'memoryIntegrity',
                    r'codeInjection',
                    r'memoryTampering',
                    r'heapProtection',
                    r'stackProtection'
                ]
            },
            'developer_mode_detection': {
                'adb_checks': [
                    r'checkAdbEnabled',
                    r'isAdbEnabled',
                    r'getAdbStatus',
                    r'adbDebugging',
                    r'usbDebugging',
                    r'developerOptions'
                ],
                'build_properties': [
                    r'ro\.debuggable',
                    r'ro\.secure',
                    r'ro\.build\.type',
                    r'ro\.build\.tags',
                    r'ro\.build\.fingerprint',
                    r'ro\.build\.description'
                ],
                'developer_options': [
                    r'checkDeveloperMode',
                    r'isDeveloperMode',
                    r'developerOptionsEnabled',
                    r'checkDebugMode',
                    r'isDebugMode'
                ],
                'usb_debugging': [
                    r'checkUsbDebugging',
                    r'isUsbDebugging',
                    r'usbDebuggingEnabled',
                    r'checkUsbDebug',
                    r'isUsbDebug'
                ]
            },
            'emulator_detection': {
                'hardware_checks': [
                    r'checkEmulator',
                    r'isEmulator',
                    r'emulatorDetection',
                    r'checkVirtualMachine',
                    r'isVirtualMachine',
                    r'vmDetection'
                ],
                'sensor_checks': [
                    r'checkSensors',
                    r'sensorDetection',
                    r'checkAccelerometer',
                    r'checkGyroscope',
                    r'checkMagnetometer',
                    r'checkProximity'
                ],
                'build_properties': [
                    r'ro\.product\.model',
                    r'ro\.product\.manufacturer',
                    r'ro\.product\.brand',
                    r'ro\.hardware',
                    r'ro\.board\.platform',
                    r'ro\.arch'
                ],
                'environment_checks': [
                    r'checkEnvironment',
                    r'environmentDetection',
                    r'checkBuildProps',
                    r'checkSystemProps',
                    r'checkDeviceProps'
                ]
            }
        }
        
        # AI analysis confidence thresholds
        self.confidence_thresholds = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
    
    def scan_for_rasp_mechanisms(self, directory: str) -> Dict[str, Any]:
        """Comprehensive RASP mechanism scanning using AI analysis."""
        if self.verbose:
            self.logger.info("🔍 Starting comprehensive RASP mechanism analysis...")
        
        results = {
            'scan_type': 'RASP_DETECTION',
            'directory': directory,
            'total_detections': 0,
            'detection_categories': {},
            'ai_analysis': {},
            'recommendations': [],
            'risk_assessment': {}
        }
        
        try:
            directory_path = Path(directory)
            
            # Scan each RASP category
            for category, subcategories in self.rasp_patterns.items():
                if self.verbose:
                    self.logger.info(f"🔍 Analyzing {category.replace('_', ' ').title()}...")
                
                category_results = self._analyze_rasp_category(directory_path, category, subcategories)
                results['detection_categories'][category] = category_results
                results['total_detections'] += category_results['total_detections']
            
            # Perform AI-based analysis
            ai_analysis = self._perform_ai_analysis(results['detection_categories'])
            results['ai_analysis'] = ai_analysis
            
            # Generate recommendations
            recommendations = self._generate_recommendations(results['detection_categories'], ai_analysis)
            results['recommendations'] = recommendations
            
            # Risk assessment
            risk_assessment = self._assess_risk(results['detection_categories'], ai_analysis)
            results['risk_assessment'] = risk_assessment
            
            if self.verbose:
                self.logger.info(f"✅ RASP analysis completed. Total detections: {results['total_detections']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error during RASP analysis: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
        
        return results
    
    def _analyze_rasp_category(self, directory_path: Path, category: str, subcategories: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze a specific RASP category for detection mechanisms."""
        category_results = {
            'category': category,
            'total_detections': 0,
            'subcategories': {},
            'files_analyzed': 0,
            'detection_methods': []
        }
        
        # Analyze each subcategory
        for subcategory, patterns in subcategories.items():
            subcategory_results = self._analyze_subcategory(directory_path, subcategory, patterns)
            category_results['subcategories'][subcategory] = subcategory_results
            category_results['total_detections'] += subcategory_results['detection_count']
            category_results['files_analyzed'] += subcategory_results['files_analyzed']
            
            if subcategory_results['detection_count'] > 0:
                category_results['detection_methods'].append(subcategory)
        
        return category_results
    
    def _analyze_subcategory(self, directory_path: Path, subcategory: str, patterns: List[str]) -> Dict[str, Any]:
        """Analyze a specific subcategory for detection patterns."""
        subcategory_results = {
            'subcategory': subcategory,
            'detection_count': 0,
            'detections': [],
            'files_analyzed': 0,
            'confidence_score': 0.0
        }
        
        # Scan relevant files
        relevant_extensions = ['.java', '.kt', '.smali', '.xml', '.so', '.cpp', '.c']
        files_scanned = 0
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in relevant_extensions):
                    file_path = Path(root) / file
                    files_scanned += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Check each pattern
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    detection = {
                                        'file': str(file_path),
                                        'pattern': pattern,
                                        'match': match.group(),
                                        'line_number': self._get_line_number(content, match.start()),
                                        'context': self._get_context(content, match.start(), 100),
                                        'confidence': self._calculate_pattern_confidence(pattern, match.group(), content)
                                    }
                                    
                                    subcategory_results['detections'].append(detection)
                                    subcategory_results['detection_count'] += 1
                    
                    except Exception as e:
                        if self.verbose:
                            self.logger.debug(f"Could not read file {file_path}: {e}")
                        continue
        
        subcategory_results['files_analyzed'] = files_scanned
        
        # Calculate overall confidence score
        if subcategory_results['detections']:
            total_confidence = sum(d['confidence'] for d in subcategory_results['detections'])
            subcategory_results['confidence_score'] = total_confidence / len(subcategory_results['detections'])
        
        return subcategory_results
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for a given position in content."""
        return content[:position].count('\n') + 1
    
    def _get_context(self, content: str, position: int, context_size: int) -> str:
        """Get context around a given position."""
        start = max(0, position - context_size)
        end = min(len(content), position + context_size)
        return content[start:end].strip()
    
    def _calculate_pattern_confidence(self, pattern: str, match: str, content: str) -> float:
        """Calculate confidence score for a pattern match using AI-like analysis."""
        confidence = 0.5  # Base confidence
        
        # Pattern complexity scoring
        if '\\' in pattern or '[' in pattern:
            confidence += 0.1  # Complex regex patterns are more reliable
        
        # Context analysis
        context_words = ['check', 'detect', 'verify', 'validate', 'is', 'has', 'get']
        if any(word in content.lower() for word in context_words):
            confidence += 0.2  # Context suggests intentional detection
        
        # Match quality
        if len(match) > 5:
            confidence += 0.1  # Longer matches are more specific
        
        # File type consideration
        if '.smali' in content or '.java' in content:
            confidence += 0.1  # Source code files are more reliable
        
        return min(1.0, confidence)
    
    def _perform_ai_analysis(self, detection_categories: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI-based analysis of RASP detection mechanisms."""
        ai_analysis = {
            'overall_effectiveness': 0.0,
            'detection_coverage': {},
            'evasion_resistance': {},
            'implementation_quality': {},
            'threat_model': {},
            'confidence_analysis': {}
        }
        
        # Analyze overall effectiveness
        total_detections = sum(cat['total_detections'] for cat in detection_categories.values())
        if total_detections > 0:
            ai_analysis['overall_effectiveness'] = min(1.0, total_detections / 50)  # Normalize to 0-1
        
        # Analyze each category
        for category, results in detection_categories.items():
            # Detection coverage
            coverage_score = min(1.0, results['total_detections'] / 20)
            ai_analysis['detection_coverage'][category] = coverage_score
            
            # Evasion resistance (based on detection method diversity)
            method_diversity = len(results['detection_methods'])
            resistance_score = min(1.0, method_diversity / 5)
            ai_analysis['evasion_resistance'][category] = resistance_score
            
            # Implementation quality (based on confidence scores)
            if results['subcategories']:
                avg_confidence = sum(sub['confidence_score'] for sub in results['subcategories'].values()) / len(results['subcategories'])
                ai_analysis['implementation_quality'][category] = avg_confidence
            
            # Threat model assessment
            threat_level = self._assess_threat_level(category, results)
            ai_analysis['threat_model'][category] = threat_level
        
        return ai_analysis
    
    def _assess_threat_level(self, category: str, results: Dict[str, Any]) -> str:
        """Assess threat level for a RASP category."""
        detection_count = results['total_detections']
        
        if detection_count == 0:
            return 'LOW'
        elif detection_count < 5:
            return 'MEDIUM'
        elif detection_count < 15:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _generate_recommendations(self, detection_categories: Dict[str, Any], ai_analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on RASP analysis."""
        recommendations = []
        
        # Overall recommendations
        if ai_analysis['overall_effectiveness'] < 0.3:
            recommendations.append("🔴 CRITICAL: Implement comprehensive RASP protection mechanisms")
        elif ai_analysis['overall_effectiveness'] < 0.6:
            recommendations.append("🟡 WARNING: Enhance RASP protection coverage")
        else:
            recommendations.append("🟢 GOOD: RASP protection appears comprehensive")
        
        # Category-specific recommendations
        for category, results in detection_categories.items():
            if results['total_detections'] == 0:
                recommendations.append(f"⚠️  {category.replace('_', ' ').title()}: No detection mechanisms found - consider implementing")
            elif results['total_detections'] < 3:
                recommendations.append(f"🟡 {category.replace('_', ' ').title()}: Limited detection coverage - enhance protection")
            else:
                recommendations.append(f"🟢 {category.replace('_', ' ').title()}: Good detection coverage")
        
        # Evasion resistance recommendations
        for category, resistance in ai_analysis['evasion_resistance'].items():
            if resistance < 0.4:
                recommendations.append(f"🔄 {category.replace('_', ' ').title()}: Implement multiple detection methods for better evasion resistance")
        
        return recommendations
    
    def _assess_risk(self, detection_categories: Dict[str, Any], ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall security risk based on RASP analysis."""
        risk_assessment = {
            'overall_risk': 'MEDIUM',
            'risk_factors': [],
            'risk_score': 0.0,
            'mitigation_priority': []
        }
        
        # Calculate risk score
        risk_score = 0.0
        
        # High detection count = lower risk (better protection)
        total_detections = sum(cat['total_detections'] for cat in detection_categories.values())
        if total_detections == 0:
            risk_score = 1.0  # Maximum risk - no protection
        elif total_detections > 50:
            risk_score = 0.1  # Low risk - comprehensive protection
        else:
            risk_score = 1.0 - (total_detections / 50)
        
        risk_assessment['risk_score'] = risk_score
        
        # Determine overall risk level
        if risk_score >= 0.8:
            risk_assessment['overall_risk'] = 'CRITICAL'
        elif risk_score >= 0.6:
            risk_assessment['overall_risk'] = 'HIGH'
        elif risk_score >= 0.4:
            risk_assessment['overall_risk'] = 'MEDIUM'
        elif risk_score >= 0.2:
            risk_assessment['overall_risk'] = 'LOW'
        else:
            risk_assessment['overall_risk'] = 'MINIMAL'
        
        # Identify risk factors
        if total_detections == 0:
            risk_assessment['risk_factors'].append("No RASP protection mechanisms detected")
        elif total_detections < 10:
            risk_assessment['risk_factors'].append("Limited RASP protection coverage")
        
        # Check for weak categories
        for category, results in detection_categories.items():
            if results['total_detections'] == 0:
                risk_assessment['risk_factors'].append(f"No {category.replace('_', ' ')} protection")
        
        # Set mitigation priority
        if risk_score >= 0.8:
            risk_assessment['mitigation_priority'] = ['IMMEDIATE', 'HIGH', 'MEDIUM']
        elif risk_score >= 0.6:
            risk_assessment['mitigation_priority'] = ['HIGH', 'MEDIUM', 'LOW']
        elif risk_score >= 0.4:
            risk_assessment['mitigation_priority'] = ['MEDIUM', 'LOW']
        else:
            risk_assessment['mitigation_priority'] = ['LOW', 'MONITOR']
        
        return risk_assessment
