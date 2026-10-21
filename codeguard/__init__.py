"""
CodeGuard —— 基于 LLM 工具调用的代码审查 Agent。
实现 Agent 闭环：输入 → 推理 → 工具调用 → 观察 → 输出。对外入口见下方 __all__。
"""

from codeguard.agent import AgentResult, CodeReviewAgent
from codeguard.config import Config
from codeguard.exceptions import (
    AgentBudgetExceeded,
    CodeGuardError,
    LLMAuthError,
    LLMError,
    LLMRateLimitError,
    LLMResponseError,
    LLMTimeoutError,
    ToolError,
)
from codeguard.llm import LLMClient
from codeguard.models import Finding, ReviewReport, Severity
from codeguard.tools import ToolRegistry, build_default_registry

__version__ = "1.0.0"

__all__ = [
    "AgentResult",
    "AgentBudgetExceeded",
    "CodeGuardError",
    "CodeReviewAgent",
    "Config",
    "Finding",
    "LLMAuthError",
    "LLMClient",
    "LLMError",
    "LLMRateLimitError",
    "LLMResponseError",
    "LLMTimeoutError",
    "ReviewReport",
    "Severity",
    "ToolError",
    "ToolRegistry",
    "__version__",
    "build_default_registry",
]
