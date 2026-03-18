import json
import requests
from crecon.utils.config import get_keys, mark_exhausted


PROMPTS = {
    "scan": """You are an expert penetration tester. Analyze these open ports and services found on a target system and provide specific, actionable attack vectors.

For each open port/service:
- Identify the exact vulnerability or weakness
- Give a specific exploit or attack technique
- Show the exact command or payload to use
- Rate severity (Critical/High/Medium/Low)

Be direct and technical. No generic advice.

Scan results:
{data}""",

    "recon": """You are an expert penetration tester. Analyze this web recon data and identify attack vectors.

For each finding:
- Emails found → phishing/OSINT attack vectors
- Tech stack detected → known CVEs or misconfigs for those exact versions
- Directories found → what sensitive data might be there
- Give exact tools/commands to exploit each finding

Be direct and technical. No generic advice.

Recon results:
{data}""",

    "enum": """You are an expert penetration tester. Analyze these enumeration results and identify what to attack next.

For each finding:
- Interesting directories → what to look for inside them
- Subdomains found → which ones look like dev/staging/admin panels
- Give exact next steps and commands

Be direct and technical. No generic advice.

Enum results:
{data}""",

    "auto": """You are an expert penetration tester doing a full assessment. Analyze ALL these recon findings together and build a complete attack chain.

Think like an attacker:
1. What is the highest priority target?
2. What is the most likely path to initial access?
3. How would you chain these findings together?
4. What would you try first, second, third?

Give exact commands, payloads, and tools for each step.
Point out anything that looks misconfigured or unusual.
Be specific to the versions and services found — no generic advice.

Full scan results:
{data}"""
}


def _call_anthropic(key: str, prompt: str) -> str:
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key":         key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
        json={
            "model":      "claude-opus-4-6",
            "max_tokens": 2048,
            "messages":   [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    if resp.status_code == 402:
        raise CreditError()
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


def _call_openai(key: str, prompt: str) -> str:
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type":  "application/json",
        },
        json={
            "model":      "gpt-4o",
            "max_tokens": 2048,
            "messages":   [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    if resp.status_code in (402, 429):
        raise CreditError()
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _call_groq(key: str, prompt: str) -> str:
    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type":  "application/json",
        },
        json={
            "model":      "llama3-70b-8192",
            "max_tokens": 2048,
            "messages":   [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    if resp.status_code == 429:
        raise CreditError()
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


CALLERS = {
    "anthropic": _call_anthropic,
    "openai":    _call_openai,
    "groq":      _call_groq,
}


class CreditError(Exception):
    pass


def analyze(mode: str, data: dict) -> str | None:
    """
    Try every saved key in order until one works.
    Automatically marks exhausted keys and moves to the next.
    Returns the AI response string, or None if all keys fail.
    """
    keys = get_keys()
    if not keys:
        return None

    prompt = PROMPTS[mode].format(data=json.dumps(data, indent=2, default=str))

    for k in keys:
        provider = k["provider"]
        api_key  = k["key"]
        caller   = CALLERS.get(provider)

        if not caller:
            continue

        try:
            return caller(api_key, prompt)

        except CreditError:
            mark_exhausted(api_key)
            continue

        except requests.exceptions.Timeout:
            continue

        except Exception:
            continue

    return None