import json
import httpx
from app.core.config import get_settings


class AIProvider:
    name = "base"

    def complete(self, system: str, prompt: str, context: dict) -> str:
        raise NotImplementedError


class NullProvider(AIProvider):
    """Offline deterministic provider: restates direct observations only. Never speculates."""
    name = "none"

    def complete(self, system, prompt, context):
        stmts = []
        for o in context["observations"][:25]:
            stmts.append({"text": o["description"], "classification": "direct_observation",
                          "evidence_ids": [o["evidence_id"]], "confidence": o["confidence"]})
        if not stmts:
            stmts.append({"text": "No evidence available for this analysis area.", "classification": "unknown",
                          "evidence_ids": [], "confidence": "low"})
        return json.dumps({"statements": stmts})


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def complete(self, system, prompt, context):
        s = get_settings()
        r = httpx.post((s.ai_base_url or "https://api.anthropic.com") + "/v1/messages", timeout=120,
                       headers={"x-api-key": s.ai_api_key, "anthropic-version": "2023-06-01"},
                       json={"model": s.ai_model, "max_tokens": 2000, "system": system,
                             "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json()["content"])


class OpenAICompatibleProvider(AIProvider):
    name = "openai_compatible"

    def complete(self, system, prompt, context):
        s = get_settings()
        r = httpx.post(s.ai_base_url.rstrip("/") + "/chat/completions", timeout=120,
                       headers={"Authorization": f"Bearer {s.ai_api_key}"},
                       json={"model": s.ai_model, "messages": [{"role": "system", "content": system},
                                                               {"role": "user", "content": prompt}]})
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def get_provider() -> AIProvider:
    return {"anthropic": AnthropicProvider, "openai_compatible": OpenAICompatibleProvider}.get(
        get_settings().ai_provider, NullProvider)()
