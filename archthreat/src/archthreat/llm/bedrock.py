"""AWS Bedrock provider via the Converse API (one request shape for every Bedrock model).

Auth comes from the standard AWS credential chain (env vars, ~/.aws, SSO, or an IAM role on
Lambda). No keys in code. IAM needs `bedrock:InvokeModel` on the model / inference profile ARN.

Model IDs differ by region; many Claude models need a cross-region inference profile ID such
as "us.anthropic.claude-haiku-4-5-20251001-v1:0". Check the Bedrock console for your region.
Docs: https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference.html
"""

from __future__ import annotations

import json
from typing import Any

from archthreat.llm.base import LLMError, LLMResponse, Message, RetryableError, Timer, with_retries

RETRYABLE_CODES = {"ThrottlingException", "ServiceUnavailableException", "ModelNotReadyException"}


def _client(region: str) -> Any:
    try:
        import boto3  # optional dependency: pip install -e ".[aws]"
    except ImportError as exc:
        raise LLMError("boto3 is not installed; run: pip install -e '.[aws]'") from exc
    return boto3.client("bedrock-runtime", region_name=region)


class BedrockLLM:
    name = "bedrock"

    def __init__(
        self,
        model: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        region: str = "us-east-1",
        client: Any = None,
    ) -> None:
        self.model = model
        self._client = client or _client(region)

    def complete(
        self,
        messages: list[Message],
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        json_mode: bool = False,
    ) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "modelId": self.model,
            "messages": [{"role": m.role, "content": [{"text": m.content}]} for m in messages],
            "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature},
        }
        if system:
            kwargs["system"] = [{"text": system}]

        def call() -> dict:
            try:
                return self._client.converse(**kwargs)
            except Exception as exc:  # botocore ClientError; imported lazily
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in RETRYABLE_CODES:
                    raise RetryableError(f"Bedrock {code}") from exc
                raise LLMError(f"Bedrock error: {exc}") from exc

        with Timer() as t:
            data = with_retries(call)
        content = data["output"]["message"]["content"]
        usage = data.get("usage", {})
        return LLMResponse(
            text="".join(block.get("text", "") for block in content),
            model=self.model,
            input_tokens=usage.get("inputTokens", 0),
            output_tokens=usage.get("outputTokens", 0),
            latency_ms=t.ms,
            stop_reason=data.get("stopReason"),
        )


class BedrockEmbedder:
    """Amazon Titan Text Embeddings V2 (one text per request)."""

    name = "bedrock"

    def __init__(
        self,
        model: str = "amazon.titan-embed-text-v2:0",
        region: str = "us-east-1",
        dims: int = 512,
        client: Any = None,
    ) -> None:
        self.model = model
        self.dims = dims
        self._client = client or _client(region)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            body = json.dumps(
                {"inputText": text[:8000], "dimensions": self.dims, "normalize": True}
            )
            resp = self._client.invoke_model(modelId=self.model, body=body)
            vectors.append(json.loads(resp["body"].read())["embedding"])
        return vectors
