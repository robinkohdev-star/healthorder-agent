# HealthOrder Agent

**Twice-daily Health Checker** powered by DeepSeek V4 Flash via OpenCode.

## Mission
Silent-by-default system health monitoring. Only speaks up when something fails.

## Model
- **Provider**: OpenCode
- **Model**: DeepSeek V4 Flash (`deepseek/deepseek-v4-flash`)
- **Temperature**: 0.1 (deterministic)
- **Use case**: Failure analysis and actionable recommendations

## Checks Performed
- Disk space usage
- Memory usage
- CPU usage
- OpenClaw Gateway health
- Agent activity (configurable)

## Schedule
Runs at 9 AM and 9 PM Singapore time (twice daily).

## Behavior
- ✅ **All checks pass**: Silent (no Discord message)
- ❌ **Any check fails**: Posts alert to Discord with:
  - Failed checks summary
  - AI-generated analysis from DeepSeek V4 Flash
  - Root cause assessment
  - Actionable recommendations

## Setup

```bash
cp .env.example .env
pip install -r requirements.txt
python agent.py
```

## Output
Only posts to Discord when failures detected. Uses DeepSeek V4 Flash to analyze failures and provide actionable insights.
