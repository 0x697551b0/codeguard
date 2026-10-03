"""CodeGuard —— 基于 LLM 工具调用的代码审查 Agent。

本包实现作业要求的最小 Agent 闭环：

    输入(Input) → 推理(Reasoning) → 工具调用(Tool Calling) → 观察(Observation) → 输出(Output)

对外主要入口：
    * :class:`codeguard.agent.CodeReviewAgent` —— Agent 主循环
    * :class:`codeguard.llm.LLMClient`         —— LLM 调用与重试
    * :class:`codeguard.tools.ToolRegistry`    —— 工具注册表
    * :func:`codeguard.cli.main`               —— 命令行入口
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
