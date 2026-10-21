"""
CodeGuard 异常体系。
LLM 异常带 retryable 语义供退避重试消费；ToolError 不中断 Agent 循环，而是回灌给模型触发自愈。
"""

from __future__ import annotations


class CodeGuardError(Exception):
    """CodeGuard 所有异常的基类。"""


# 配置类异常
class ConfigError(CodeGuardError):
    """配置缺失或非法（例如没有提供 API Key）。"""


# LLM 层异常
class LLMError(CodeGuardError):
    """LLM 调用相关错误的基类。"""

    #: 是否值得重试（子类覆写）
    retryable: bool = False


class LLMTimeoutError(LLMError):
    """请求超时。"""

    retryable = True


class LLMConnectionError(LLMError):
    """网络不可达 / 连接被重置。"""

    retryable = True


class LLMRateLimitError(LLMError):
    """触发限流（HTTP 429）或服务端 5xx 过载。"""

    retryable = True

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        #: 服务端 ``Retry-After`` 提示的等待秒数
        self.retry_after = retry_after


class LLMAuthError(LLMError):
    """API Key 无效或权限不足（HTTP 401/403）—— 重试无意义。"""

    retryable = False


class LLMResponseError(LLMError):
    """响应体不符合预期（缺少 choices / 非法 JSON 等）。"""

    retryable = False


class LLMTruncatedError(LLMResponseError):
    """模型输出被 ``max_tokens`` 截断。"""


# 工具层异常
class ToolError(CodeGuardError):
    """工具执行失败。会被 Agent 捕获并作为观察结果回灌给模型。"""


class ToolNotFoundError(ToolError):
    """模型请求了未注册的工具名。"""


class ToolArgumentError(ToolError):
    """工具入参不合法（缺字段 / 类型错误 / 越界）。"""


# Agent 层异常
class AgentBudgetExceeded(CodeGuardError):
    """达到最大迭代轮数或工具调用预算，Agent 提前收敛。"""
