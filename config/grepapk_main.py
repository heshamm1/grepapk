#!/usr/bin/env python3
"""
GrepAPK Main Controller - Consolidated Version
Main entry point for the Android APK security scanner.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

import click

from .vulnerability_patterns import (
    get_patterns, 
    get_vulnerability_title, 
    get_exploitation_method, 
    get_adb_payload,
    get_framework_patterns
)
from .regex_scanner_enhanced import EnhancedRegexScanner
from .ai_scanner import AIScanner
from .output_manager import OutputManager
from .help_banner import HelpBanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GrepAPKController:
    """Main controller for GrepAPK vulnerability scanning."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.vulnerabilities = []
        self.scan_summary = {}
        
        # Initialize scanners
        self.regex_scanner = EnhancedRegexScanner(verbose=verbose)
        self.ai_scanner = None
        self._initialize_ai_scanner()
        
        # Initialize output manager
        self.output_manager = OutputManager()
        
        # Get patterns
        self.patterns = get_patterns()
        self.framework_patterns = get_framework_patterns()
    
    def _initialize_ai_scanner(self):
        """Initialize AI scanner if dependencies are available."""
        try:
            self.ai_scanner = AIScanner(verbose=self.verbose)
            if self.verbose:
                print("🤖 AI scanner initialized successfully")
        except ImportError as e:
            if self.verbose:
                print(f"ℹ️  AI module not available: {e}")
            self.ai_scanner = None
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error initializing AI scanner: {e}")
            self.ai_scanner = None
    
    def perform_tiny_scan(self, directory: str) -> Dict[str, Any]:
        """Perform a tiny scan to analyze framework and basic structure."""
        if self.verbose:
            print("🔍 Performing Tiny Scan...")
        
        results = {
            'scan_type': 'TINY',
            'directory': directory,
            'framework_analysis': {},
            'structure_analysis': {},
            'vulnerabilities': []
        }
        
        # Analyze framework
        framework_results = self._analyze_framework(directory)
        results['framework_analysis'] = framework_results
        
        # Basic structure analysis
        structure_results = self._analyze_structure(directory)
        results['structure_analysis'] = structure_results
        
        if self.verbose:
            print(f"✅ Tiny scan completed. Framework: {framework_results.get('detected_framework', 'Unknown')}")
        
        return results
    
    def perform_full_scan(self, directory: str, scan_method: str = 'all') -> Dict[str, Any]:
        """Perform a full vulnerability scan."""
        if self.verbose:
            print(f"🔍 Performing Full Scan with method: {scan_method}")
        
        results = {
            'scan_type': 'FULL',
            'directory': directory,
            'scan_method': scan_method,
            'vulnerabilities': [],
            'scan_summary': {}
        }
        
        # Perform regex scanning
        if scan_method in ['all', 'regex']:
            if self.verbose:
                print("🔍 Running regex-based vulnerability detection...")
            
            regex_vulns = self.regex_scanner.scan_directory(directory, self.patterns)
            results['vulnerabilities'].extend(regex_vulns)
            
            if self.verbose:
                print(f"✅ Regex scan found {len(regex_vulns)} vulnerabilities")
        
        # Perform AI scanning if available and requested
        if scan_method in ['all', 'ai'] and self.ai_scanner:
            if self.verbose:
                print("🤖 Running AI-based vulnerability detection...")
            
            try:
                ai_vulns = self.ai_scanner.scan_directory(directory)
                results['vulnerabilities'].extend(ai_vulns)
                
                if self.verbose:
                    print(f"✅ AI scan found {len(ai_vulns)} vulnerabilities")
                    
            except Exception as e:
                if self.verbose:
                    print(f"⚠️  AI scan failed: {e}")
        
        # Generate scan summary
        if results['vulnerabilities']:
            results['scan_summary'] = self.regex_scanner.get_scan_summary(results['vulnerabilities'])
        
        if self.verbose:
            print(f"🎯 Full scan completed. Total vulnerabilities: {len(results['vulnerabilities'])}")
        
        return results
    
    def _analyze_framework(self, directory: str) -> Dict[str, Any]:
        """Analyze the framework and build system used."""
        framework_results = {
            'detected_framework': 'Unknown',
            'build_system': 'Unknown',
            'programming_languages': [],
            'rasp_controls': [],
            'package_info': {},
            'security_features': [],
            'target_sdk': 'Unknown',
            'min_sdk': 'Unknown',
            'permissions': [],
            'exported_components': []
        }
        
        try:
            directory_path = Path(directory)
            
            # Check for build files
            if (directory_path / 'build.gradle').exists():
                framework_results['build_system'] = 'Gradle'
                framework_results['detected_framework'] = 'Android Native'
            elif (directory_path / 'pom.xml').exists():
                framework_results['build_system'] = 'Maven'
                framework_results['detected_framework'] = 'Android Native'
            elif (directory_path / 'build.xml').exists():
                framework_results['build_system'] = 'Ant'
                framework_results['detected_framework'] = 'Android Native'
            
            # Check for programming languages
            java_files = list(directory_path.rglob('*.java'))
            kotlin_files = list(directory_path.rglob('*.kt'))
            smali_files = list(directory_path.rglob('*.smali'))
            xml_files = list(directory_path.rglob('*.xml'))
            
            if java_files:
                framework_results['programming_languages'].append('Java')
            if kotlin_files:
                framework_results['programming_languages'].append('Kotlin')
            if smali_files:
                framework_results['programming_languages'].append('Smali')
            if xml_files:
                framework_results['programming_languages'].append('XML')
            
            # Enhanced RASP controls detection
            rasp_indicators = {
                'root_detection': ['rootbeer', 'rootcloak', 'magisk', 'supersu', 'kingroot', 'rootchecker'],
                'anti_debug': ['anti_debug', 'debuggable', 'isdebuggerconnected', 'debuggable_check'],
                'anti_tamper': ['anti_tamper', 'integrity_check', 'signature_verify', 'checksum_verify'],
                'anti_vm': ['emulator_check', 'virtual_machine', 'genymotion', 'bluestacks'],
                'code_obfuscation': ['proguard', 'r8', 'obfuscation', 'string_encryption'],
                'hook_detection': ['xposed', 'frida', 'substrate', 'cydia', 'hook_detection'],
                'certificate_pinning': ['ssl_pinning', 'certificate_pinning', 'network_security_config'],
                'jailbreak_detection': ['jailbreak', 'cydia', 'sileo', 'unc0ver', 'checkra1n']
            }
            
            # Enhanced security features detection
            security_features = {
                'biometric_auth': ['biometric', 'fingerprint', 'face_recognition', 'biometric_prompt'],
                'encryption': ['aes', 'rsa', 'sha256', 'encryption', 'cipher'],
                'secure_storage': ['keystore', 'encrypted_shared_prefs', 'encrypted_database'],
                'network_security': ['network_security_config', 'cleartext_traffic', 'ssl_error_handler'],
                'app_signing': ['v1_signing', 'v2_signing', 'v3_signing', 'apk_signer']
            }
            
            # Analyze files for RASP controls and security features
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.java', '.kt', '.xml', '.smali')):
                        file_path = Path(root) / file
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read().lower()
                                
                                # Check RASP controls
                                for category, indicators in rasp_indicators.items():
                                    for indicator in indicators:
                                        if indicator in content:
                                            if indicator not in framework_results['rasp_controls']:
                                                framework_results['rasp_controls'].append(indicator)
                                
                                # Check security features
                                for category, indicators in security_features.items():
                                    for indicator in indicators:
                                        if indicator in content:
                                            if category not in framework_results['security_features']:
                                                framework_results['security_features'].append(category)
                                                
                        except:
                            continue
            
            # Remove duplicates
            framework_results['rasp_controls'] = list(set(framework_results['rasp_controls']))
            framework_results['security_features'] = list(set(framework_results['security_features']))
            
            # Try to extract package info from manifest
            manifest_files = list(directory_path.rglob('AndroidManifest.xml'))
            for manifest in manifest_files:
                try:
                    with open(manifest, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Extract package name
                        import re
                        package_match = re.search(r'package=["\']([^"\']+)["\']', content)
                        if package_match:
                            framework_results['package_info']['package_name'] = package_match.group(1)
                        
                        # Extract target SDK
                        target_sdk_match = re.search(r'android:targetSdkVersion=["\']([^"\']+)["\']', content)
                        if target_sdk_match:
                            framework_results['target_sdk'] = target_sdk_match.group(1)
                        
                        # Extract min SDK
                        min_sdk_match = re.search(r'android:minSdkVersion=["\']([^"\']+)["\']', content)
                        if min_sdk_match:
                            framework_results['min_sdk'] = min_sdk_match.group(1)
                        
                        # Extract permissions
                        permission_matches = re.findall(r'<uses-permission[^>]*android:name=["\']([^"\']+)["\']', content)
                        framework_results['permissions'].extend(permission_matches)
                        
                        # Extract exported components
                        exported_activities = re.findall(r'<activity[^>]*android:exported=["\']true["\'][^>]*android:name=["\']([^"\']+)["\']', content)
                        exported_services = re.findall(r'<service[^>]*android:exported=["\']true["\'][^>]*android:name=["\']([^"\']+)["\']', content)
                        exported_receivers = re.findall(r'<receiver[^>]*android:exported=["\']true["\'][^>]*android:name=["\']([^"\']+)["\']', content)
                        exported_providers = re.findall(r'<provider[^>]*android:exported=["\']true["\'][^>]*android:name=["\']([^"\']+)["\']', content)
                        
                        framework_results['exported_components'] = {
                            'activities': exported_activities,
                            'services': exported_services,
                            'receivers': exported_receivers,
                            'providers': exported_providers
                        }
                        
                except:
                    continue
            
            # Remove duplicate permissions
            framework_results['permissions'] = list(set(framework_results['permissions']))
            
            # Determine framework based on file analysis
            if smali_files:
                if len(smali_files) > 1000:  # Large number of smali files suggests complex app
                    framework_results['detected_framework'] = 'Android Native (Decompiled)'
                else:
                    framework_results['detected_framework'] = 'Android Native (Simple)'
            
            # Check for specific frameworks
            androidx_files = list(directory_path.rglob('*androidx*'))
            support_files = list(directory_path.rglob('*support*'))
            if androidx_files:
                framework_results['detected_framework'] = 'AndroidX'
            elif support_files:
                framework_results['detected_framework'] = 'Android Support Library'
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Framework analysis error: {e}")
        
        return framework_results
    
    def _analyze_structure(self, directory: str) -> Dict[str, Any]:
        """Analyze the basic structure of the project."""
        structure_results = {
            'total_files': 0,
            'file_types': {},
            'directories': [],
            'manifest_files': [],
            'security_analysis': {},
            'resource_analysis': {},
            'code_analysis': {},
            'size_analysis': {}
        }
        
        try:
            directory_path = Path(directory)
            
            # File counting and analysis
            for root, dirs, files in os.walk(directory):
                structure_results['total_files'] += len(files)
                
                for file in files:
                    ext = Path(file).suffix.lower()
                    structure_results['file_types'][ext] = structure_results['file_types'].get(ext, 0) + 1
                    
                    if 'manifest' in file.lower():
                        structure_results['manifest_files'].append(str(Path(root) / file))
                
                for dir_name in dirs:
                    if not dir_name.startswith('.'):
                        structure_results['directories'].append(dir_name)
            
            # Remove duplicates
            structure_results['directories'] = list(set(structure_results['directories']))
            
            # Enhanced security analysis
            security_analysis = {
                'native_libraries': [],
                'webview_files': [],
                'database_files': [],
                'certificate_files': [],
                'configuration_files': []
            }
            
            # Check for native libraries
            native_exts = ['.so', '.dll', '.dylib']
            for ext in native_exts:
                native_files = list(directory_path.rglob(f'*{ext}'))
                if native_files:
                    security_analysis['native_libraries'].extend([str(f) for f in native_files])
            
            # Check for WebView related files
            webview_patterns = ['webview', 'javascript', 'html', 'css', 'js']
            for pattern in webview_patterns:
                webview_files = list(directory_path.rglob(f'*{pattern}*'))
                if webview_files:
                    security_analysis['webview_files'].extend([str(f) for f in webview_files])
            
            # Check for database files
            db_exts = ['.db', '.sqlite', '.sqlite3']
            for ext in db_exts:
                db_files = list(directory_path.rglob(f'*{ext}'))
                if db_files:
                    security_analysis['database_files'].extend([str(f) for f in db_files])
            
            # Check for certificate files
            cert_exts = ['.cer', '.crt', '.pem', '.p12', '.keystore', '.jks']
            for ext in cert_exts:
                cert_files = list(directory_path.rglob(f'*{ext}'))
                if cert_files:
                    security_analysis['certificate_files'].extend([str(f) for f in cert_files])
            
            # Check for configuration files
            config_patterns = ['config', 'properties', 'ini', 'conf', 'cfg']
            for pattern in config_patterns:
                config_files = list(directory_path.rglob(f'*{pattern}*'))
                if config_files:
                    security_analysis['configuration_files'].extend([str(f) for f in config_files])
            
            # Remove duplicates from security analysis
            for key in security_analysis:
                security_analysis[key] = list(set(security_analysis[key]))
            
            structure_results['security_analysis'] = security_analysis
            
            # Resource analysis
            resource_analysis = {
                'drawable_resources': 0,
                'layout_resources': 0,
                'value_resources': 0,
                'raw_resources': 0,
                'asset_resources': 0
            }
            
            # Count resource types
            drawable_dirs = [d for d in structure_results['directories'] if 'drawable' in d.lower()]
            layout_dirs = [d for d in structure_results['directories'] if 'layout' in d.lower()]
            value_dirs = [d for d in structure_results['directories'] if 'values' in d.lower()]
            raw_dirs = [d for d in structure_results['directories'] if 'raw' in d.lower()]
            asset_dirs = [d for d in structure_results['directories'] if 'assets' in d.lower()]
            
            resource_analysis['drawable_resources'] = len(drawable_dirs)
            resource_analysis['layout_resources'] = len(layout_dirs)
            resource_analysis['value_resources'] = len(value_dirs)
            resource_analysis['raw_resources'] = len(raw_dirs)
            resource_analysis['asset_resources'] = len(asset_dirs)
            
            structure_results['resource_analysis'] = resource_analysis
            
            # Code analysis
            code_analysis = {
                'smali_classes': 0,
                'java_files': 0,
                'kotlin_files': 0,
                'xml_files': 0,
                'dex_files': 0
            }
            
            # Count code files
            code_analysis['smali_classes'] = structure_results['file_types'].get('.smali', 0)
            code_analysis['java_files'] = structure_results['file_types'].get('.java', 0)
            code_analysis['kotlin_files'] = structure_results['file_types'].get('.kt', 0)
            code_analysis['xml_files'] = structure_results['file_types'].get('.xml', 0)
            
            # Check for DEX files
            dex_dirs = [d for d in structure_results['directories'] if 'smali_classes' in d.lower()]
            code_analysis['dex_files'] = len(dex_dirs)
            
            structure_results['code_analysis'] = code_analysis
            
            # Size analysis
            size_analysis = {
                'total_size_mb': 0,
                'largest_files': [],
                'file_size_distribution': {}
            }
            
            # Calculate total size and find largest files
            total_size = 0
            file_sizes = []
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    try:
                        file_path = Path(root) / file
                        file_size = file_path.stat().st_size
                        total_size += file_size
                        file_sizes.append((str(file_path), file_size))
                    except:
                        continue
            
            size_analysis['total_size_mb'] = round(total_size / (1024 * 1024), 2)
            
            # Get top 10 largest files
            file_sizes.sort(key=lambda x: x[1], reverse=True)
            size_analysis['largest_files'] = [(f[0], round(f[1] / 1024, 2)) for f in file_sizes[:10]]
            
            # File size distribution
            size_ranges = {
                'tiny': (0, 1024),      # 0-1KB
                'small': (1024, 10240),  # 1-10KB
                'medium': (10240, 102400), # 10-100KB
                'large': (102400, 1048576), # 100KB-1MB
                'huge': (1048576, float('inf')) # 1MB+
            }
            
            for size_name, (min_size, max_size) in size_ranges.items():
                count = sum(1 for _, size in file_sizes if min_size <= size < max_size)
                size_analysis['file_size_distribution'][size_name] = count
            
            structure_results['size_analysis'] = size_analysis
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Structure analysis error: {e}")
        
        return structure_results
    
    def save_results(self, results: Dict[str, Any], output_format: str, output_name: str) -> str:
        """Save scan results to file."""
        try:
            output_file = self.output_manager.save_results(
                results, output_format, output_name
            )
            
            if self.verbose:
                print(f"💾 Results saved to: {output_file}")
            
            return output_file
            
        except Exception as e:
            if self.verbose:
                print(f"❌ Error saving results: {e}")
            raise

@click.command()
@click.option('-d', '--directory', required=True, help='Directory of the APK codebase to scan')
@click.option('-T', '--tiny-scan', is_flag=True, help='Perform tiny scan (framework analysis only)')
@click.option('-F', '--full-scan', is_flag=True, help='Perform full vulnerability scan')
@click.option('--ai-only', is_flag=True, help='Use AI model only for scanning')
@click.option('--regex-only', is_flag=True, help='Use regex patterns only for scanning')
@click.option('--all-methods', is_flag=True, help='Use all detection methods (AI + regex)')
@click.option('-f', '--format', 'output_format', default='txt', type=click.Choice(['txt', 'json']), help='Output format (txt or json)')
@click.option('-o', '--output', 'output_name', default='grepapk_scan', help='Output filename (without extension)')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
def main(directory: str, tiny_scan: bool, full_scan: bool, ai_only: bool, 
          regex_only: bool, all_methods: bool, output_format: str, 
          output_name: str, verbose: bool):
    """GrepAPK - Android APK Security Scanner v3.0"""
    
    # Display banner
    help_banner = HelpBanner()
    help_banner.display_banner()
    
    # Determine scan type and method
    if tiny_scan:
        scan_type = 'TINY'
        scan_method = 'framework_only'
    elif full_scan:
        scan_type = 'FULL'
        if ai_only:
            scan_method = 'ai'
        elif regex_only:
            scan_method = 'regex'
        elif all_methods:
            scan_method = 'all'
        else:
            scan_method = 'all'  # Default to all methods
    else:
        click.echo("❌ Error: Please specify scan type (-T for tiny scan or -F for full scan)")
        sys.exit(1)
    
    # Validate directory
    if not os.path.exists(directory):
        click.echo(f"❌ Error: Directory does not exist: {directory}")
        sys.exit(1)
    
    if not os.path.isdir(directory):
        click.echo(f"❌ Error: Path is not a directory: {directory}")
        sys.exit(1)
    
    try:
        # Initialize controller
        controller = GrepAPKController(verbose=verbose)
        
        # Perform scan
        if tiny_scan:
            results = controller.perform_tiny_scan(directory)
        else:  # full_scan
            results = controller.perform_full_scan(directory, scan_method)
        
        # Save results
        output_file = controller.save_results(results, output_format, output_name)
        
        # Display summary
        if verbose:
            click.echo(f"\n📊 Scan Summary:")
            click.echo(f"   Directory: {directory}")
            click.echo(f"   Scan Type: {results['scan_type']}")
            if 'scan_summary' in results and results['scan_summary']:
                summary = results['scan_summary']
                click.echo(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                if 'severity_breakdown' in summary:
                    for severity, count in summary['severity_breakdown'].items():
                        click.echo(f"   {severity}: {count}")
        
        click.echo(f"\n✅ Scan completed successfully!")
        click.echo(f"📁 Results saved to: {output_file}")
        
    except Exception as e:
        click.echo(f"❌ Error during scan: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
