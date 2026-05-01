#!/usr/bin/env python3
"""
HealthOrder Agent - System Health Checker
Powered by DeepSeek V4 Flash via OpenCode
Silent by default, speaks up only on failure
"""

import os
import json
import asyncio
import psutil
from datetime import datetime
from typing import List, Dict, Any, Optional
import aiohttp

class HealthOrder:
    def __init__(self, config_path: str = "config.json"):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        self.opencode_api_key = os.getenv("OPENCODE_API_KEY")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_HEALTH") or self.config['output']['discord_webhook']
        self.failures: List[Dict[str, Any]] = []
        
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
        if not self.failures:
            return "All systems healthy"
        
        failures_text = "\n".join([
            f"- {f['check']}: {f.get('message', f.get('error', 'Unknown'))}"
            for f in self.failures
        ])
        
        prompt = f"""Analyze these system health failures and provide actionable recommendations:

Failures detected:
{failures_text}

Provide:
1. Severity assessment
2. Likely root causes
3. Immediate actions to take
4. Prevention recommendations

Be concise and actionable."""
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.opencode.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.opencode_api_key}"},
                json={
                    "model": self.config['model']['model'],
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": self.config['model']['temperature'],
                    "max_tokens": self.config['model']['max_tokens']
                }
            ) as resp:
                result = await resp.json()
                return result['choices'][0]['message']['content']
    
    async def post_alert(self, analysis: str):
        """Post alert to Discord if there are failures"""
        if not self.discord_webhook:
            print("No Discord webhook configured")
            return
        
        if not self.failures:
            return  # Silent on success
        
        alert = f"""🚨 **HealthOrder Alert** 🚨

**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M')} SGT
**Failed Checks:** {len(self.failures)}

**Summary:**
{chr(10).join([f"• {f['check']}: {f.get('message', f.get('error', 'Unknown'))}" for f in self.failures])}

**Analysis & Recommendations:**
{analysis[:1500]}

@channel Attention required
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
        
        if self.config['checks']['system']['disk_space']['enabled']:
            results.append(self.check_disk_space())
        
        if self.config['checks']['system']['memory']['enabled']:
            results.append(self.check_memory())
        
        if self.config['checks']['system']['cpu']['enabled']:
            results.append(self.check_cpu())
        
        if self.config['checks']['services']['openclaw_gateway']['enabled']:
            results.append(await self.check_openclaw_gateway())
        
        # Log results
        print(f"Checks complete: {len([r for r in results if r['status'] == 'ok'])} ok, {len(self.failures)} failed")
        
        # Analyze failures with DeepSeek V4 Flash
        if self.failures:
            print(f"Analyzing {len(self.failures)} failures with DeepSeek V4 Flash...")
            analysis = await self.analyze_failures()
            await self.post_alert(analysis)
            print("Alert posted to Discord")
        else:
            print("All checks passed - remaining silent")
        
        print(f"[{datetime.now()}] HealthOrder complete")

if __name__ == "__main__":
    agent = HealthOrder()
    asyncio.run(agent.run())
