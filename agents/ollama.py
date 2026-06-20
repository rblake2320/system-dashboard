"""Ollama LLM agent — uses a local model to diagnose issues."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from core import config as cfg
from .base import AgentBase, DiagnosisResult

_SYSTEM_PROMPT = """\
You are a system reliability engineer analyzing a live workstation dashboard.
You will be given a detected issue and current system context.
Respond ONLY with valid JSON matching this exact schema:
{
  "summary": "one sentence describing the issue",
  "root_cause": "what is actually causing this",
  "suggested_fix": "specific, actionable steps to resolve it",
  "fixer_id": "process_fixer | service_fixer | storage_fixer | null",
  "fix_params": {},
  "confidence": "high | medium | low"
}
Be concise and technical. Do not wrap in markdown. Return raw JSON only."""


class OllamaAgent(AgentBase):
    def __init__(self) -> None:
        lcfg = cfg.llm()
        self._host = lcfg.get("host", "http://localhost:11434").rstrip("/")
        self._model = lcfg.get("model", "gemma3:latest")
        self._timeout = int(lcfg.get("timeout_seconds", 60))

    def available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self._host}/api/tags")
            with urllib.request.urlopen(req, timeout=3):
                return True
        except Exception:
            return False

    def diagnose(self, issue: dict, context: dict) -> DiagnosisResult:
        user_msg = (
            f"ISSUE:\n{json.dumps(issue, indent=2)}\n\n"
            f"SYSTEM CONTEXT:\n{json.dumps(context, indent=2, default=str)}"
        )
        payload = json.dumps({
            "model": self._model,
            "system": _SYSTEM_PROMPT,
            "prompt": user_msg,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 512},
        }).encode()

        req = urllib.request.Request(
            f"{self._host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            raw_resp = json.loads(resp.read())

        raw_text = raw_resp.get("response", "")

        # Strip markdown fences if model added them
        text = raw_text.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.rsplit("```", 1)[0].strip()

        parsed = json.loads(text)
        return DiagnosisResult(
            summary=parsed.get("summary", ""),
            root_cause=parsed.get("root_cause", ""),
            suggested_fix=parsed.get("suggested_fix", ""),
            fixer_id=parsed.get("fixer_id"),
            fix_params=parsed.get("fix_params", {}),
            confidence=parsed.get("confidence", "medium"),
            raw=raw_text,
        )


class OpenAIAgent(AgentBase):
    """OpenAI / Anthropic compatible agent (uses chat completions API)."""

    def __init__(self) -> None:
        lcfg = cfg.llm()
        self._provider = lcfg.get("provider", "openai")
        self._model = lcfg.get("model", "gpt-4o-mini")
        self._api_key = lcfg.get("api_key", "")
        self._timeout = int(lcfg.get("timeout_seconds", 60))

        if self._provider == "anthropic":
            self._endpoint = "https://api.anthropic.com/v1/messages"
        else:
            self._endpoint = "https://api.openai.com/v1/chat/completions"

    def available(self) -> bool:
        return bool(self._api_key)

    def diagnose(self, issue: dict, context: dict) -> DiagnosisResult:
        user_msg = (
            f"ISSUE:\n{json.dumps(issue, indent=2)}\n\n"
            f"SYSTEM CONTEXT:\n{json.dumps(context, indent=2, default=str)}"
        )
        if self._provider == "anthropic":
            payload = json.dumps({
                "model": self._model,
                "max_tokens": 512,
                "system": _SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_msg}],
            }).encode()
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
            }
        else:
            payload = json.dumps({
                "model": self._model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                "max_tokens": 512,
                "temperature": 0.1,
            }).encode()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            }

        req = urllib.request.Request(
            self._endpoint, data=payload, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            raw_resp = json.loads(resp.read())

        if self._provider == "anthropic":
            raw_text = raw_resp["content"][0]["text"]
        else:
            raw_text = raw_resp["choices"][0]["message"]["content"]

        text = raw_text.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.rsplit("```", 1)[0].strip()

        parsed = json.loads(text)
        return DiagnosisResult(
            summary=parsed.get("summary", ""),
            root_cause=parsed.get("root_cause", ""),
            suggested_fix=parsed.get("suggested_fix", ""),
            fixer_id=parsed.get("fixer_id"),
            fix_params=parsed.get("fix_params", {}),
            confidence=parsed.get("confidence", "medium"),
            raw=raw_text,
        )


def get_agent() -> AgentBase:
    """Return the appropriate agent based on config."""
    lcfg = cfg.llm()
    provider = lcfg.get("provider", "none")
    if provider == "none":
        return _NoopAgent()
    if provider == "ollama":
        return OllamaAgent()
    return OpenAIAgent()


class _NoopAgent(AgentBase):
    def available(self) -> bool:
        return False

    def diagnose(self, issue: dict, context: dict) -> DiagnosisResult:
        return DiagnosisResult(
            summary="LLM not configured",
            root_cause="No LLM provider configured in config.yaml",
            suggested_fix="Set llm.provider to 'ollama', 'openai', or 'anthropic'",
            fixer_id=None,
            fix_params={},
            confidence="low",
        )
