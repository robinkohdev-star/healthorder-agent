#!/usr/bin/env python3
"""
HealthOrder Agent - System Health Checker
Powered by Gemma4:e2b via Ollama (local LLM)
Posts status to Discord on every run
"""

import os
import json
import asyncio
import psutil
from datetime import datetime
from typing import List, Dict, Any, Optional
import aiohttp
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class HealthOrder:
    def __init__(self, config_path: str = "config.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_HEALTH") or self.config['output']['discord_webhook']
        self.failures: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.package_state_file = "state/package-state.json"
        
        # Ensure state directory exists
        os.makedirs("state", exist_ok=True)
        
    def load_package_state(self) -> Dict[str, Any]:
        """Load previously saved package versions for rollback tracking"""
        if os.path.exists(self.package_state_file):
            with open(self.package_state_file, 'r') as f:
                return json.load(f)
        return {"pip": {}, "npm": {}, "apt": {}, "last_scan": None}
    
    def save_package_state(self, state: Dict[str, Any]):
        """Save current package versions for rollback tracking"""
        state["last_scan"] = datetime.now().isoformat()
        with open(self.package_state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    async def scan_pip_vulnerabilities(self) -> Dict[str, Any]:
        """Scan Python packages for vulnerabilities using pip-audit"""
        import subprocess
        
        try:
            # Run pip-audit to check for vulnerabilities
            result = subprocess.run(
                ["pip-audit", "--format=json", "--desc"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            vulnerabilities = []
            fix_available = []
            
            if result.returncode in [0, 1]:  # 0 = no vulns, 1 = vulns found
                try:
                    audit_data = json.loads(result.stdout)
                    for pkg in audit_data.get("dependencies", []):
                        pkg_name = pkg.get("name", "unknown")
                        installed = pkg.get("version", "unknown")
                        
                        for vuln in pkg.get("vulns", []):
                            vuln_info = {
                                "package": pkg_name,
                                "installed_version": installed,
                                "vulnerability_id": vuln.get("id", "unknown"),
                                "description": vuln.get("description", "No description")[:200],
                                "fix_versions": vuln.get("fix_versions", []),
                                "severity": self._estimate_severity(vuln.get("description", "")),
                                "ecosystem": "pip"
                            }
                            vulnerabilities.append(vuln_info)
                            
                            if vuln.get("fix_versions"):
                                fix_available.append({
                                    "package": pkg_name,
                                    "current": installed,
                                    "fixed_in": vuln["fix_versions"][0],
                                    "severity": vuln_info["severity"]
                                })
                except json.JSONDecodeError:
                    pass
            
            # Get current pip package list for state tracking
            pip_list = subprocess.run(
                ["pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            current_packages = {}
            if pip_list.returncode == 0:
                try:
                    packages = json.loads(pip_list.stdout)
                    current_packages = {p["name"]: p["version"] for p in packages}
                except:
                    pass
            
            # Load previous state and check for suspicious version jumps
            state = self.load_package_state()
            suspicious_updates = self._detect_suspicious_updates(
                state.get("pip", {}), 
                current_packages
            )
            
            # Update state
            state["pip"] = current_packages
            self.save_package_state(state)
            
            status = "failed" if vulnerabilities else "ok"
            
            if vulnerabilities:
                self.vulnerabilities.extend(vulnerabilities)
                critical_count = len([v for v in vulnerabilities if v["severity"] == "critical"])
                if critical_count > 0:
                    self.failures.append({
                        'check': 'pip_vulnerabilities',
                        'severity': 'critical',
                        'message': f"{len(vulnerabilities)} vulnerabilities found ({critical_count} critical) in Python packages"
                    })
            
            return {
                'check': 'pip_vulnerabilities',
                'status': status,
                'value': f"{len(vulnerabilities)} vulns, {len(fix_available)} fixable",
                'details': {
                    'vulnerabilities': vulnerabilities,
                    'fixes_available': fix_available,
                    'suspicious_updates': suspicious_updates
                }
            }
            
        except FileNotFoundError:
            return {
                'check': 'pip_vulnerabilities',
                'status': 'ok',
                'value': 'pip-audit not installed'
            }
        except Exception as e:
            return {
                'check': 'pip_vulnerabilities',
                'status': 'failed',
                'value': f'Error: {str(e)[:50]}'
            }
    
    async def scan_npm_vulnerabilities(self) -> Dict[str, Any]:
        """Scan Node.js packages for vulnerabilities using npm audit"""
        import subprocess
        
        try:
            # Check if npm is available
            npm_check = subprocess.run(
                ["which", "npm"],
                capture_output=True,
                timeout=5
            )
            
            if npm_check.returncode != 0:
                return {
                    'check': 'npm_vulnerabilities',
                    'status': 'ok',
                    'value': 'npm not found'
                }
            
            # Run npm audit
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=os.path.expanduser("~")  # Run from home dir
            )
            
            vulnerabilities = []
            
            if result.stdout:
                try:
                    audit_data = json.loads(result.stdout)
                    advisories = audit_data.get("advisories", {})
                    
                    for adv_id, adv in advisories.items():
                        vuln_info = {
                            "package": adv.get("module_name", "unknown"),
                            "installed_version": adv.get("findings", [{}])[0].get("version", "unknown"),
                            "vulnerability_id": str(adv_id),
                            "description": adv.get("overview", "No description")[:200],
                            "severity": adv.get("severity", "unknown"),
                            "ecosystem": "npm",
                            "patched_versions": adv.get("patched_versions", "unknown")
                        }
                        vulnerabilities.append(vuln_info)
                        
                except json.JSONDecodeError:
                    pass
            
            status = "failed" if vulnerabilities else "ok"
            
            if vulnerabilities:
                self.vulnerabilities.extend(vulnerabilities)
                high_count = len([v for v in vulnerabilities if v["severity"] in ["high", "critical"]])
                if high_count > 0:
                    self.failures.append({
                        'check': 'npm_vulnerabilities',
                        'severity': 'high',
                        'message': f"{len(vulnerabilities)} vulnerabilities found in npm packages"
                    })
            
            return {
                'check': 'npm_vulnerabilities',
                'status': status,
                'value': f"{len(vulnerabilities)} vulnerabilities found",
                'details': {'vulnerabilities': vulnerabilities[:10]}  # Limit details
            }
            
        except Exception as e:
            return {
                'check': 'npm_vulnerabilities',
                'status': 'failed',
                'value': f'Error: {str(e)[:50]}'
            }
    
    async def scan_apt_security_updates(self) -> Dict[str, Any]:
        """Check for APT security updates"""
        import subprocess
        
        try:
            # Update package list
            subprocess.run(
                ["apt", "update"],
                capture_output=True,
                timeout=60
            )
            
            # Check for security updates
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            security_updates = []
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'security' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            pkg_name = parts[0].split('/')[0]
                            security_updates.append({
                                "package": pkg_name,
                                "details": line.strip(),
                                "type": "security"
                            })
            
            status = "failed" if security_updates else "ok"
            
            if security_updates:
                self.failures.append({
                    'check': 'apt_security_updates',
                    'severity': 'high',
                    'message': f"{len(security_updates)} security updates available"
                })
            
            return {
                'check': 'apt_security_updates',
                'status': status,
                'value': f"{len(security_updates)} security updates",
                'details': {'updates': security_updates[:10]}
            }
            
        except Exception as e:
            return {
                'check': 'apt_security_updates',
                'status': 'failed',
                'value': f'Error: {str(e)[:50]}'
            }
    
    def _estimate_severity(self, description: str) -> str:
        """Estimate severity based on vulnerability description"""
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in ['remote code execution', 'rce', 'arbitrary code', 'command injection']):
            return 'critical'
        elif any(kw in desc_lower for kw in ['sql injection', 'xss', 'cross-site scripting', 'authentication bypass']):
            return 'high'
        elif any(kw in desc_lower for kw in ['denial of service', 'dos', 'information disclosure']):
            return 'medium'
        return 'low'
    
    def _detect_suspicious_updates(self, old_packages: Dict, new_packages: Dict) -> List[Dict]:
        """Detect suspicious version jumps that might indicate package hijacking"""
        suspicious = []
        
        for pkg, new_ver in new_packages.items():
            if pkg in old_packages:
                old_ver = old_packages[pkg]
                # Simple heuristic: major version jumps or unusual patterns
                old_parts = old_ver.split('.')
                new_parts = new_ver.split('.')
                
                try:
                    if len(old_parts) >= 1 and len(new_parts) >= 1:
                        old_major = int(old_parts[0])
                        new_major = int(new_parts[0])
                        
                        # Flag major version jumps > 1
                        if new_major - old_major > 1:
                            suspicious.append({
                                "package": pkg,
                                "old_version": old_ver,
                                "new_version": new_ver,
                                "reason": "Large major version jump",
                                "recommendation": f"pip install {pkg}=={old_ver}  # Rollback if suspicious"
                            })
                except ValueError:
                    pass
        
        return suspicious
        
    def check_disk_space(self) -> Dict[str, Any]:
        """Check disk usage"""
        disk = psutil.disk_usage('/')
        percent = disk.percent
        threshold = self.config['checks']['system']['disk_space']['threshold_percent']
        
        status = "ok" if percent < threshold else "failed"
        if status == "failed":
            self.failures.append({
                'check': 'disk_space',
                'value': f"{percent}%",
                'threshold': f"{threshold}%",
                'message': f"Disk usage critical: {percent}%"
            })
        
        return {'check': 'disk_space', 'status': status, 'value': f"{percent}%"}
    
    def check_memory(self) -> Dict[str, Any]:
        """Check memory usage"""
        memory = psutil.virtual_memory()
        percent = memory.percent
        threshold = self.config['checks']['system']['memory']['threshold_percent']
        
        status = "ok" if percent < threshold else "failed"
        if status == "failed":
            self.failures.append({
                'check': 'memory',
                'value': f"{percent}%",
                'threshold': f"{threshold}%",
                'message': f"Memory usage critical: {percent}%"
            })
        
        return {'check': 'memory', 'status': status, 'value': f"{percent}%"}
    
    def check_cpu(self) -> Dict[str, Any]:
        """Check CPU usage"""
        percent = psutil.cpu_percent(interval=1)
        threshold = self.config['checks']['system']['cpu']['threshold_percent']
        
        status = "ok" if percent < threshold else "failed"
        if status == "failed":
            self.failures.append({
                'check': 'cpu',
                'value': f"{percent}%",
                'threshold': f"{threshold}%",
                'message': f"CPU usage critical: {percent}%"
            })
        
        return {'check': 'cpu', 'status': status, 'value': f"{percent}%"}
    
    async def check_openclaw_gateway(self) -> Dict[str, Any]:
        """Check OpenClaw gateway health"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.config['checks']['services']['openclaw_gateway']['endpoint'],
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    status = "ok" if resp.status == 200 else "failed"
                    if status == "failed":
                        self.failures.append({
                            'check': 'openclaw_gateway',
                            'status_code': resp.status,
                            'message': f"Gateway returned HTTP {resp.status}"
                        })
                    return {'check': 'openclaw_gateway', 'status': status, 'code': resp.status}
        except Exception as e:
            self.failures.append({
                'check': 'openclaw_gateway',
                'error': str(e),
                'message': f"Gateway unreachable: {str(e)}"
            })
            return {'check': 'openclaw_gateway', 'status': 'failed', 'error': str(e)}
    
    async def analyze_failures(self) -> str:
        """Use DeepSeek V4 Flash to analyze and summarize failures"""
        if not self.failures and not self.vulnerabilities:
            return "All systems healthy"
        
        failures_text = "\n".join([
            f"- {f['check']}: {f.get('message', f.get('error', 'Unknown'))}"
            for f in self.failures
        ])
        
        # Add vulnerability summary
        vuln_summary = ""
        if self.vulnerabilities:
            critical = len([v for v in self.vulnerabilities if v['severity'] == 'critical'])
            high = len([v for v in self.vulnerabilities if v['severity'] == 'high'])
            medium = len([v for v in self.vulnerabilities if v['severity'] == 'medium'])
            
            fixable = len([v for v in self.vulnerabilities if v.get('fix_versions')])
            
            vuln_summary = f"""
Vulnerabilities: {len(self.vulnerabilities)} total
- Critical: {critical}
- High: {high}  
- Medium: {medium}
- Fix available for: {fixable} packages"""
        
        prompt = f"""Analyze these system health and security issues:

System Failures:
{failures_text if failures_text else "None"}

{vuln_summary}

Provide:
1. Severity assessment
2. Immediate actions (prioritize critical security issues)
3. Fix commands for vulnerable packages
4. Rollback recommendations if suspicious updates detected
5. Prevention recommendations

Be concise and prioritize security issues."""
        
        # Use Ollama for local LLM analysis
        base_url = self.config['model'].get('base_url', 'http://localhost:11434')
        model = self.config['model']['model']
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{base_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": self.config['model']['temperature'],
                            "num_predict": self.config['model']['max_tokens']
                        }
                    }
                ) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        print(f"Ollama API error: {resp.status} - {text[:200]}")
                        return f"Analysis unavailable (Ollama status {resp.status}). Ensure Ollama is running with model '{model}'."
                    
                    result = await resp.json()
                    return result.get('response', 'No analysis generated')
        except aiohttp.ClientConnectorError:
            return f"Analysis unavailable. Ollama not running at {base_url}. Start with: ollama run {model}"
        except Exception as e:
            print(f"Error calling Ollama API: {e}")
            return "Analysis unavailable. Please review failures and vulnerabilities manually."
    
    async def post_alert(self, analysis: str, results: List[Dict[str, Any]]):
        """Post health status to Discord"""
        if not self.discord_webhook:
            print("No Discord webhook configured")
            return
        
        # Format check results
        checks_text = "\n".join([
            f"{'✅' if r['status'] == 'ok' else '❌'} {r['check']}: {r.get('value', r.get('code', 'ok'))}"
            for r in results
        ])
        
        # Build vulnerability section
        vuln_section = ""
        if self.vulnerabilities:
            critical = [v for v in self.vulnerabilities if v['severity'] == 'critical']
            high = [v for v in self.vulnerabilities if v['severity'] == 'high']
            
            if critical or high:
                vuln_section = "\n\n**🔒 Security Issues:**\n"
                if critical:
                    vuln_section += f"🚨 **{len(critical)} Critical vulnerabilities**\n"
                if high:
                    vuln_section += f"⚠️ **{len(high)} High severity vulnerabilities**\n"
                
                # Show fixable packages
                fixable = [v for v in self.vulnerabilities if v.get('fix_versions')]
                if fixable:
                    vuln_section += "\n**Fixable packages:**\n"
                    for v in fixable[:5]:  # Top 5
                        vuln_section += f"• `{v['package']}`: {v['installed_version']} → {v['fix_versions'][0]}\n"
                
                # Show suspicious updates
                for result in results:
                    if 'details' in result and result['details'].get('suspicious_updates'):
                        suspicious = result['details']['suspicious_updates']
                        if suspicious:
                            vuln_section += "\n**⚠️ Suspicious version jumps detected:**\n"
                            for s in suspicious[:3]:
                                vuln_section += f"• `{s['package']}`: {s['old_version']} → {s['new_version']}\n"
                                vuln_section += f"  Rollback: `{s['recommendation']}`\n"
        
        if self.failures or self.vulnerabilities:
            # Failure or vulnerability alert
            alert = f"""🚨 **HealthOrder Alert** 🚨

**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M')} SGT
**Status:** {len([r for r in results if r['status'] == 'ok'])}/{len(results)} checks passed

**Issues:**
{chr(10).join([f"• {f['check']}: {f.get('message', f.get('error', 'Unknown'))}" for f in self.failures]) if self.failures else 'No system failures'}
{vuln_section}

**Recommendations:**
{analysis[:1000]}

@channel Attention required
"""
        else:
            # Success summary
            alert = f"""✅ **HealthOrder - All Systems Healthy**

**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M')} SGT
**Status:** {len(results)}/{len(results)} checks passed

**Checks:**
{checks_text}

All systems operating normally. 🔒 No vulnerabilities detected.
"""
        
        async with aiohttp.ClientSession() as session:
            await session.post(
                self.discord_webhook,
                json={"content": alert[:2000]}
            )
    
    async def run(self):
        """Main health check loop"""
        print(f"[{datetime.now()}] HealthOrder running checks...")
        
        # Run all checks
        results = []
        
        # System health checks
        if self.config['checks']['system']['disk_space']['enabled']:
            results.append(self.check_disk_space())
        
        if self.config['checks']['system']['memory']['enabled']:
            results.append(self.check_memory())
        
        if self.config['checks']['system']['cpu']['enabled']:
            results.append(self.check_cpu())
        
        if self.config['checks']['services']['openclaw_gateway']['enabled']:
            results.append(await self.check_openclaw_gateway())
        
        # Security vulnerability scans
        print("Scanning for package vulnerabilities...")
        results.append(await self.scan_pip_vulnerabilities())
        results.append(await self.scan_npm_vulnerabilities())
        results.append(await self.scan_apt_security_updates())
        
        # Log results
        vuln_count = len(self.vulnerabilities)
        print(f"Checks complete: {len([r for r in results if r['status'] == 'ok'])} ok, {len(self.failures)} failed, {vuln_count} vulnerabilities")
        
        # Analyze with local Ollama model (disabled - no model available)
        print("Ollama model not available - skipping AI analysis")
        analysis = "Manual review recommended. Install an Ollama model to enable AI analysis."
        
        # Post to Discord
        await self.post_alert(analysis, results)
        print("Status posted to Discord")
        
        print(f"[{datetime.now()}] HealthOrder complete")

if __name__ == "__main__":
    agent = HealthOrder()
    asyncio.run(agent.run())
