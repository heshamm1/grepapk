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
            'rasp_controls': []
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
            
            if java_files:
                framework_results['programming_languages'].append('Java')
            if kotlin_files:
                framework_results['programming_languages'].append('Kotlin')
            if smali_files:
                framework_results['programming_languages'].append('Smali')
            
            # Check for RASP controls
            rasp_indicators = [
                'rootbeer', 'rootcloak', 'magisk', 'xposed', 'frida',
                'anti_debug', 'anti_tamper', 'code_integrity'
            ]
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(('.java', '.kt', '.xml')):
                        file_path = Path(root) / file
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read().lower()
                                for indicator in rasp_indicators:
                                    if indicator in content:
                                        framework_results['rasp_controls'].append(indicator)
                        except:
                            continue
            
            # Remove duplicates
            framework_results['rasp_controls'] = list(set(framework_results['rasp_controls']))
            
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
            'manifest_files': []
        }
        
        try:
            directory_path = Path(directory)
            
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
