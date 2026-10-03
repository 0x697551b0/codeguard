"""LLM 客户端测试。

使用 ``httpx.MockTransport`` 注入伪造响应，**完全不访问网络**，覆盖：
    * 正常响应解析（content / tool_calls / usage）
    * 工具调用参数非法 JSON 时的容错
    * HTTP 429 / 500 的退避重试与最终成功
    * 401 鉴权失败不重试（快速失败）
    * 响应结构异常的错误提示
    * 端点 URL 拼接
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.config import Config
from codeguard.exceptions import LLMAuthError, LLMResponseError
from codeguard.llm import LLMClient, MockLLMClient, _extract_error_message, _safe_json_object
from codeguard.models import ChatMessage


def make_config(**overrides: object) -> Config:
    defaults = {
        "api_key": "sk-test",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "max_retries": 2,
        "backoff_base": 1.0,
        "timeout": 5.0,
    }
    defaults.update(overrides)
    return Config(**defaults)  # type: ignore[arg-type]


def make_client(handler, *, config: Config | None = None, sleeps: list[float] | None = None) -> LLMClient:
    """构造注入了 MockTransport 的客户端；``sleeps`` 收集退避等待时长。"""
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport, base_url="https://api.deepseek.com")
    client = LLMClient(config or make_config(), http_client=http_client)
    if sleeps is not None:
        # 打桩 time.sleep，避免测试真实等待
        import codeguard.llm as llm_module

        llm_module.time.sleep = lambda seconds: sleeps.append(seconds)  # type: ignore[assignment]
    return client


def completion_response(content: str = "ok", *, tool_calls=None, usage=None) -> httpx.Response:
    message: dict[str, object] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "model": "deepseek-chat",
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
    )


def test_plain_content_response() -> None:
    client = make_client(lambda request: completion_response("hello"))
    response = client.chat([ChatMessage(role="user", content="hi")])
    assert response.content == "hello"
    assert response.tool_calls == []
    assert response.usage is not None
    assert response.usage.total_tokens == 15
    assert response.finish_reason == "stop"


def test_tool_call_parsing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # 校验请求体携带了工具定义
        body = json.loads(request.content)
        assert body["model"] == "deepseek-chat"
        assert body["tool_choice"] == "auto"
        assert body["stream"] is False
        assert body["messages"][0]["role"] == "user"
        return completion_response(
            "",
            tool_calls=[
                {
                    "id": "call_abc",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path": "a.py", "start_line": 3}'},
                }
            ],
        )

    client = make_client(handler)
    response = client.chat(
        [ChatMessage(role="user", content="read it")],
        tools=[{"type": "function", "function": {"name": "read_file", "parameters": {}}}],
    )
    assert len(response.tool_calls) == 1
    call = response.tool_calls[0]
    assert call.id == "call_abc"
    assert call.name == "read_file"
    assert call.arguments == {"path": "a.py", "start_line": 3}
    assert call.raw_arguments == ""


def test_invalid_tool_arguments_json_is_tolerated() -> None:
    """参数不是合法 JSON 时不应抛异常，而是保留原文供 Agent 回灌模型。"""
    def handler(request: httpx.Request) -> httpx.Response:
        return completion_response(
            "",
            tool_calls=[
                {
                    "id": "call_bad",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{path: broken"},
                }
            ],
        )

    client = make_client(handler)
    response = client.chat([ChatMessage(role="user", content="x")])
    call = response.tool_calls[0]
    assert call.arguments == {}
    assert call.raw_arguments == "{path: broken"


def test_retry_then_success_on_429() -> None:
    sleeps: list[float] = []
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return httpx.Response(429, json={"error": {"message": "rate limited"}}, headers={"Retry-After": "2"})
        return completion_response("recovered")

    client = make_client(handler, sleeps=sleeps)
    # 用模块级打桩替换 sleep
    import codeguard.llm as llm_module

    original_sleep = llm_module.time.sleep
    llm_module.time.sleep = lambda seconds: sleeps.append(seconds)  # type: ignore[assignment]
    try:
        response = client.chat([ChatMessage(role="user", content="hi")])
    finally:
        llm_module.time.sleep = original_sleep  # type: ignore[assignment]

    assert response.content == "recovered"
    assert attempts["count"] == 2
    # 尊重 Retry-After，且不超过 backoff_max
    assert sleeps and sleeps[0] == 2.0


def test_retry_exhausted_raises_rate_limit_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": {"message": "overloaded"}})

    client = make_client(handler, config=make_config(max_retries=2))
    import codeguard.llm as llm_module
    from codeguard.exceptions import LLMRateLimitError

    original_sleep = llm_module.time.sleep
    llm_module.time.sleep = lambda seconds: None  # type: ignore[assignment]
    try:
        try:
            client.chat([ChatMessage(role="user", content="hi")])
        except LLMRateLimitError as exc:
            assert "503" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("应当抛出 LLMRateLimitError")
    finally:
        llm_module.time.sleep = original_sleep  # type: ignore[assignment]


def test_auth_error_is_not_retried() -> None:
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        return httpx.Response(401, json={"error": {"message": "invalid api key"}})

    client = make_client(handler)
    try:
        client.chat([ChatMessage(role="user", content="hi")])
    except LLMAuthError as exc:
        assert "鉴权失败" in str(exc)
        assert "invalid api key" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("应当抛出 LLMAuthError")
    assert attempts["count"] == 1, "401 不应重试"


def test_missing_choices_raises_response_error() -> None:
    client = make_client(lambda request: httpx.Response(200, json={"id": "x"}))
    try:
        client.chat([ChatMessage(role="user", content="hi")])
    except LLMResponseError as exc:
        assert "choices" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("应当抛出 LLMResponseError")


def test_error_field_with_http_200_raises() -> None:
    client = make_client(lambda request: httpx.Response(200, json={"error": {"message": "quota exceeded"}}))
    try:
        client.chat([ChatMessage(role="user", content="hi")])
    except LLMResponseError as exc:
        assert "quota exceeded" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("应当抛出 LLMResponseError")


def test_non_json_body_raises_response_error() -> None:
    client = make_client(lambda request: httpx.Response(200, text="<html>bad gateway</html>"))
    try:
        client.chat([ChatMessage(role="user", content="hi")])
    except LLMResponseError as exc:
        assert "JSON" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("应当抛出 LLMResponseError")


def test_chat_completions_url_joining() -> None:
    assert Config(base_url="https://api.deepseek.com").chat_completions_url == "https://api.deepseek.com/chat/completions"
    assert Config(base_url="https://api.deepseek.com/").chat_completions_url == "https://api.deepseek.com/chat/completions"
    assert Config(base_url="https://api.openai.com/v1").chat_completions_url == "https://api.openai.com/v1/chat/completions"
    assert (
        Config(base_url="https://x.com/v1/chat/completions").chat_completions_url
        == "https://x.com/v1/chat/completions"
    )


def test_safe_json_object_helper() -> None:
    assert _safe_json_object('{"a": 1}') == ({"a": 1}, True)
    assert _safe_json_object("") == ({}, True)
    parsed, ok = _safe_json_object("[1, 2]")
    assert parsed == {"value": [1, 2]} and ok
    assert _safe_json_object("nope") == ({}, False)


def test_extract_error_message_variants() -> None:
    assert "bad" in _extract_error_message(httpx.Response(400, json={"error": {"message": "bad request"}}))
    assert "plain" in _extract_error_message(httpx.Response(400, json={"error": "plain"}))
    assert _extract_error_message(httpx.Response(400, text="raw text")) == "raw text"


def test_mock_client_script_advances_and_substitutes_target() -> None:
    client = MockLLMClient(Config(mock=True), target="demo/dir")
    first = client.chat([ChatMessage(role="user", content="go")])
    assert first.tool_calls, "第一轮应返回工具调用"
    assert first.tool_calls[0].arguments.get("path") == "demo/dir"
    assert client.model_name == "mock-scripted-model"

    # 脚本耗尽后应收敛为纯文本
    for _ in range(5):
        response = client.chat([ChatMessage(role="user", content="go")])
    assert response.tool_calls == []
