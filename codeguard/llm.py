"""
LLM 客户端：用 httpx 直接调用 OpenAI 兼容的 /chat/completions。

用原生 HTTP 而非官方 SDK：只需 httpx、协议透明、换服务商只改 base_url 与 model。
内置指数退避重试（尊重 Retry-After）、区分可重试(429/5xx/超时)与不可重试(401/403/400)、工具参数 JSON 容错。
"""

from __future__ import annotations

import json
import logging
import random
import time
from abc import ABC, abstractmethod
from typing import Any, Sequence

import httpx

from codeguard.config import Config
from codeguard.exceptions import (
    LLMAuthError,
    LLMError,
    LLMRateLimitError,
    LLMResponseError,
    LLMTimeoutError,
)
from codeguard.models import ChatMessage, LLMResponse, TokenUsage, ToolCall

logger = logging.getLogger(__name__)


# 抽象接口
class BaseLLMClient(ABC):
    """LLM 客户端接口。Agent 只依赖此抽象，因此可替换为 MockLLMClient 做离线测试。"""

    @abstractmethod
    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResponse:
        """发起一次带（可选）工具定义的对话补全。"""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """当前使用的模型标识，用于报告元数据。"""

    def close(self) -> None:  # pragma: no cover - 默认无资源可释放
        """释放底层连接等资源。"""


# 真实实现
class LLMClient(BaseLLMClient):
    """OpenAI 兼容协议的同步 LLM 客户端。"""

    def __init__(self, config: Config, *, http_client: httpx.Client | None = None) -> None:
        self.config = config
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=httpx.Timeout(config.timeout, connect=min(15.0, config.timeout)),
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json",
                **config.extra_headers,
            },
            follow_redirects=True,
        )

    @property
    def model_name(self) -> str:
        return self.config.model

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "LLMClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResponse:
        """调用一次 chat completion，内部完成重试。"""
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [m.to_payload() for m in messages],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = list(tools)
            payload["tool_choice"] = tool_choice or "auto"

        attempts = self.config.max_retries + 1
        last_error: LLMError | None = None

        for attempt in range(1, attempts + 1):
            try:
                response = self._client.post(self.config.chat_completions_url, json=payload)
                self._raise_for_status(response)
                data = self._parse_json(response)
                return self._normalize(data)
            except LLMError as exc:
                last_error = exc
                if not exc.retryable or attempt >= attempts:
                    raise
                delay = self._backoff_delay(attempt, exc)
                logger.warning(
                    "LLM 调用失败（第 %d/%d 次）：%s —— %.1fs 后重试",
                    attempt,
                    attempts,
                    exc,
                    delay,
                )
                time.sleep(delay)

        # 理论不可达：循环内要么 return 要么 raise
        raise last_error or LLMError("LLM 调用失败且未捕获到具体原因")  # pragma: no cover

    # 内部工具
    def _backoff_delay(self, attempt: int, error: LLMError) -> float:
        """指数退避 + 全抖动，避免多进程同时重试造成惊群。"""
        if isinstance(error, LLMRateLimitError) and error.retry_after:
            return min(error.retry_after, self.config.backoff_max)
        base = self.config.backoff_base
        delay = min(base ** attempt, self.config.backoff_max)
        return delay * (0.5 + random.random() * 0.5)

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        """把 HTTP 状态码翻译成带重试语义的领域异常。"""
        status = response.status_code
        if status < 400:
            return

        detail = _extract_error_message(response)
        if status in (401, 403):
            raise LLMAuthError(f"鉴权失败（HTTP {status}）：{detail}。请检查 API Key 是否正确、是否有该模型权限。")
        if status == 429:
            retry_after = _parse_retry_after(response.headers.get("Retry-After"))
            raise LLMRateLimitError(f"触发限流（HTTP 429）：{detail}", retry_after=retry_after)
        if status >= 500:
            raise LLMRateLimitError(f"服务端错误（HTTP {status}）：{detail}")
        if status == 408:
            raise LLMTimeoutError(f"请求超时（HTTP 408）：{detail}")
        raise LLMResponseError(f"请求被拒绝（HTTP {status}）：{detail}")

    def _parse_json(self, response: httpx.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise LLMResponseError(f"响应不是合法 JSON：{response.text[:400]}") from exc
        if not isinstance(data, dict):
            raise LLMResponseError(f"响应 JSON 顶层应为对象，实际为 {type(data).__name__}")
        return data

    @staticmethod
    def _normalize(data: dict[str, Any]) -> LLMResponse:
        """把原始响应转成 :class:`LLMResponse`。"""
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            # 有些兼容实现出错时返回 200 + error 字段
            if isinstance(data.get("error"), dict):
                message = data["error"].get("message", data["error"])
                raise LLMResponseError(f"服务端返回错误：{message}")
            raise LLMResponseError(f"响应缺少 choices 字段：{json.dumps(data, ensure_ascii=False)[:400]}")

        choice = choices[0] or {}
        message = choice.get("message") or {}
        finish_reason = str(choice.get("finish_reason") or "")

        content = message.get("content")
        if isinstance(content, list):
            # 少数实现把 content 返回为分段数组
            content = "".join(
                part.get("text", "") for part in content if isinstance(part, dict)
            )
        content = content or ""

        tool_calls: list[ToolCall] = []
        for index, raw_call in enumerate(message.get("tool_calls") or []):
            if not isinstance(raw_call, dict):
                continue
            function = raw_call.get("function") or {}
            raw_args = function.get("arguments")
            if isinstance(raw_args, dict):
                raw_args = json.dumps(raw_args, ensure_ascii=False)
            raw_args = raw_args if isinstance(raw_args, str) else ""
            arguments, parse_ok = _safe_json_object(raw_args)
            tool_calls.append(
                ToolCall(
                    id=str(raw_call.get("id") or f"call_{index}"),
                    name=str(function.get("name") or ""),
                    arguments=arguments,
                    raw_arguments="" if parse_ok else raw_args,
                )
            )

        usage = None
        if isinstance(data.get("usage"), dict):
            raw_usage = data["usage"]
            usage = TokenUsage(
                prompt_tokens=int(raw_usage.get("prompt_tokens") or 0),
                completion_tokens=int(raw_usage.get("completion_tokens") or 0),
                total_tokens=int(raw_usage.get("total_tokens") or 0),
                calls=1,
            )

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            usage=usage,
            finish_reason=finish_reason,
            model=str(data.get("model") or ""),
            raw=data,
        )


# 离线脚本化实现
class MockLLMClient(BaseLLMClient):
    """
    离线脚本化 LLM，用于无 API Key 演示与端到端测试。按预设脚本依次返回工具调用：静态分析 → 读文件 → 提交报告。
    最后一步会读取 run_static_analysis 的真实结果填入报告，因此演示报告基于真实分析数据而非编造。
    要体验真实模型的语义理解，去掉 --mock 并配置 API Key。
    """

    #: 提交报告时最多回填多少条问题
    MAX_MOCK_FINDINGS = 12

    def __init__(
        self,
        config: Config | None = None,
        *,
        script: list[LLMResponse] | None = None,
        target: str = "",
        toolbox: Any = None,
    ) -> None:
        self.config = config or Config(mock=True)
        #: 是否为内置脚本；自定义脚本不做动态回填
        self._uses_default_script = script is None
        self._script = list(script) if script else _default_mock_script()
        self._cursor = 0
        #: 脚本中 ``__TARGET__`` 占位符会被替换成真实审查路径
        self.target = target
        #: 可选的工具箱引用：用于读取 ``run_static_analysis`` 的完整结构化结果。
        #: 传 None 时退化为解析对话历史里的工具消息文本。
        self.toolbox = toolbox
        #: 记录收到的对话历史，便于测试断言
        self.received: list[list[ChatMessage]] = []

    @property
    def model_name(self) -> str:
        return "mock-scripted-model"

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: Sequence[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResponse:
        self.received.append(list(messages))

        # 已经执行过工具 → 需要基于观察结果继续；脚本耗尽后直接收敛
        if self._cursor >= len(self._script):
            return LLMResponse(
                content="（Mock 脚本已执行完毕）审查流程结束。",
                finish_reason="stop",
                usage=TokenUsage(10, 20, 30, 1),
                model=self.model_name,
            )

        step = self._script[self._cursor]
        self._cursor += 1

        if step is None:  # 脚本洞：让 Agent 收敛
            return LLMResponse(content="审查完成。", finish_reason="stop", model=self.model_name)

        resolved_target = self.target or "."
        tool_calls: list[ToolCall] = []
        for call in step.tool_calls:
            arguments = json.loads(json.dumps(call.arguments))
            for key, value in list(arguments.items()):
                if value == "__TARGET__":
                    arguments[key] = resolved_target
            # 内置脚本的最后一步：用前面静态分析的真实结果填充报告
            if self._uses_default_script and call.name == TERMINATION_TOOL_NAME:
                arguments = _populate_report_from_observations(
                    arguments, messages, target=resolved_target, toolbox=self.toolbox
                )
            tool_calls.append(ToolCall(call.id, call.name, arguments, call.raw_arguments))

        return LLMResponse(
            content=step.content,
            tool_calls=tool_calls,
            usage=TokenUsage(120, 60, 180, 1),
            finish_reason=step.finish_reason,
            model=self.model_name,
        )


#: 终止工具名（避免与 agent 模块循环导入，这里重复定义常量）
TERMINATION_TOOL_NAME = "submit_review"


def _populate_report_from_observations(
    arguments: dict[str, Any],
    messages: Sequence[ChatMessage],
    *,
    target: str,
    toolbox: Any = None,
) -> dict[str, Any]:
    """
    把 run_static_analysis 的结果回填进报告参数（Mock 模式保证报告基于真实分析输出）。
    来源优先级：toolbox.tool_state（完整，首选）→ 对话历史里的工具消息 JSON（兜底，可能已截断）。
    """
    findings: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    files: list[str] = []

    state = getattr(toolbox, "last_static_analysis", None) if toolbox is not None else None
    payloads: list[dict[str, Any]] = []
    if isinstance(state, dict):
        payloads.append(state)
    else:
        for message in messages:
            if message.role != "tool" or message.name != "run_static_analysis":
                continue
            raw = message.content or ""
            if not raw.lstrip().startswith("{"):
                continue
            try:
                parsed = json.loads(raw)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                payloads.append(parsed)

    for payload in payloads:
        counts = payload.get("counts_by_severity") or counts
        if payload.get("target"):
            files.append(str(payload["target"]))
        for item in payload.get("findings", []):
            if isinstance(item, dict):
                # 明确标注来源为规则引擎 —— 这些条目不是"模型语义判断"的产物，
                # 报告里必须如实区分，否则读者会高估结论的可信度。
                findings.append({**item, "source": "static"})

    if not findings:
        return arguments

    arguments["findings"] = findings[: MockLLMClient.MAX_MOCK_FINDINGS]
    arguments["files_reviewed"] = sorted(set(files)) or [target]
    arguments["score"] = _mock_score(counts)
    arguments["overall_risk"] = _mock_risk(counts)
    arguments["summary"] = (
        "【离线 Mock 模式】已按脚本完整跑通 Agent 闭环（推理 → 工具调用 → 观察 → 报告）。"
        f"报告中的 {len(arguments['findings'])} 条问题取自内置静态规则引擎在 `{target}` 上的真实输出，"
        "因此可与 `python -m codeguard scan` 的结果交叉验证。"
        "语义层面的深入结论（逻辑缺陷、业务边界、并发时序等）需要配置真实 API Key 后由模型给出。"
    )
    arguments["positives"] = [
        "内置静态规则引擎与 Agent 循环解耦，可单独作为 CI 质量门禁复用",
        "工具层对工作区做了路径沙箱约束，避免越权读取",
    ]
    arguments["open_questions"] = ["配置 CODEGUARD_API_KEY 后重新运行，以获得基于语义理解的完整审查结论"]
    return arguments


def _mock_risk(counts: dict[str, int]) -> str:
    if counts.get("critical"):
        return "critical"
    if counts.get("high"):
        return "high"
    if counts.get("medium"):
        return "medium"
    return "low"


def _mock_score(counts: dict[str, int]) -> int:
    """按问题分布给出一个粗略的演示评分（仅用于展示字段效果）。"""
    penalty = (
        counts.get("critical", 0) * 12
        + counts.get("high", 0) * 6
        + counts.get("medium", 0) * 3
        + counts.get("low", 0) * 1
        + counts.get("info", 0) * 0.5
    )
    return max(5, min(100, int(100 - penalty)))


def _default_mock_script() -> list[LLMResponse]:
    """默认脚本：演示一次完整的“静态分析 → 读文件 → 提交报告”闭环。"""
    return [
        LLMResponse(
            content="第一步：先对目标路径做确定性静态分析，拿到客观的规则命中清单。",
            tool_calls=[
                ToolCall(
                    id="mock_call_1",
                    name="analyze_code",
                    arguments={"path": "__TARGET__"},
                )
            ],
            finish_reason="tool_calls",
        ),
        LLMResponse(
            content="第二步：静态规则的命中结果已拿到，接下来读取主要源文件，结合上下文判断真实影响面。",
            tool_calls=[
                ToolCall(
                    id="mock_call_2",
                    name="run_static_analysis",
                    arguments={"path": "__TARGET__"},
                )
            ],
            finish_reason="tool_calls",
        ),
        LLMResponse(
            content="第三步：整合规则命中与人工阅读结论，提交结构化审查报告。",
            tool_calls=[
                ToolCall(
                    id="mock_call_3",
                    name="submit_review",
                    arguments={
                        "summary": (
                            "离线 Mock 模式：已完成静态规则扫描与文件读取流程演示。"
                            "命中结果来自内置静态分析器，本条摘要由脚本化模型生成，仅用于验证 Agent 闭环。"
                        ),
                        "overall_risk": "medium",
                        "positives": ["项目结构清晰", "模块职责划分明确"],
                        "files_reviewed": ["__TARGET__"],
                        "open_questions": ["配置真实 API Key 后可获得基于语义理解的深度审查结论"],
                    },
                )
            ],
            finish_reason="tool_calls",
        ),
    ]


# 辅助函数
def _safe_json_object(raw: str) -> tuple[dict[str, Any], bool]:
    """解析工具调用参数，返回 (参数字典, 是否解析成功)。失败时返回空字典与 False，交由 Agent 回灌模型而非崩溃。"""
    text = (raw or "").strip()
    if not text:
        return {}, True
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}, False
    if isinstance(parsed, dict):
        return parsed, True
    return {"value": parsed}, True


def _extract_error_message(response: httpx.Response) -> str:
    """从错误响应中提取人类可读的消息。"""
    try:
        data = response.json()
    except (json.JSONDecodeError, ValueError):
        return (response.text or "").strip()[:300] or "无附加信息"
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error)[:300]
        if isinstance(error, str):
            return error[:300]
        if "message" in data:
            return str(data["message"])[:300]
    return json.dumps(data, ensure_ascii=False)[:300]


def _parse_retry_after(header: str | None) -> float | None:
    """解析 ``Retry-After`` 头（仅支持秒数形式）。"""
    if not header:
        return None
    try:
        value = float(header)
    except ValueError:
        return None
    return max(0.0, value)
