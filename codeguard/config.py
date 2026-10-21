"""
配置加载。优先级：显式参数 > 环境变量 > .env 文件 > 代码默认值。
刻意不引入 python-dotenv，用手写极简 .env 解析器，保证裸 Python 环境即可运行（只需 httpx）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from codeguard.exceptions import ConfigError

#: 环境变量前缀
ENV_PREFIX = "CODEGUARD_"

#: 是否把模型的思维链回显到终端
DEFAULT_SYSTEM_PROMPT_LANG = "zh"


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def load_dotenv(path: str | Path = ".env", *, override: bool = False) -> dict[str, str]:
    """
    极简 .env 解析器，支持 KEY=VALUE、# 注释、export 前缀与成对引号。
    返回解析出的键值对；已存在的环境变量默认不覆盖（override=True 可强制覆盖）。
    """
    file_path = Path(path)
    if not file_path.is_file():
        return {}

    parsed: dict[str, str] = {}
    for raw_line in file_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if not key:
            continue
        parsed[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    return parsed


@dataclass
class Config:
    """Agent 运行期配置。字段名到环境变量的映射：base_url → CODEGUARD_BASE_URL。"""

    # ---- LLM ----
    api_key: str = ""
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-chat"
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: float = 90.0
    max_retries: int = 3
    backoff_base: float = 1.5
    backoff_max: float = 30.0

    # ---- Agent ----
    max_iterations: int = 12
    max_tool_calls: int = 40
    lang: str = DEFAULT_SYSTEM_PROMPT_LANG
    verbose: bool = False
    #: 离线脚本化模型（不访问网络，用于无 Key 演示与测试）
    mock: bool = False

    # ---- 工具 ----
    max_file_bytes: int = 200_000
    max_tool_output_chars: int = 20_000
    #: 工具可访问的根目录；空表示不限制（默认限制为当前工作目录更安全）
    workspace_root: str = ""

    #: 额外透传给 HTTP 请求的头部
    extra_headers: dict[str, str] = field(default_factory=dict)

    # 构造
    @classmethod
    def from_env(cls, dotenv_path: str | Path | None = ".env", **overrides: Any) -> "Config":
        """从 ``.env`` + 环境变量 + 关键字覆盖构造配置。"""
        if dotenv_path is not None:
            load_dotenv(dotenv_path)

        kwargs: dict[str, Any] = {}
        for f in fields(cls):
            env_name = f"{ENV_PREFIX}{f.name.upper()}"
            if env_name not in os.environ:
                continue
            raw = os.environ[env_name]
            kwargs[f.name] = _coerce(raw, f.type, f.name)

        kwargs.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**kwargs)

    # 校验与派生属性
    def validate(self, *, require_api_key: bool = True) -> None:
        """启动前校验配置，尽早暴露问题而不是等第一次网络调用。"""
        if require_api_key and not self.mock and not self.api_key.strip():
            raise ConfigError(
                "缺少 API Key。请任选一种方式配置：\n"
                f"  1) 设置环境变量 {ENV_PREFIX}API_KEY=sk-xxxx\n"
                "  2) 复制 .env.example 为 .env 并填写 CODEGUARD_API_KEY\n"
                "  3) 命令行传入 --api-key sk-xxxx\n"
                "  4) 无 Key 体验：加 --mock 参数运行离线演示模式"
            )
        if not self.base_url.startswith(("http://", "https://")):
            raise ConfigError(f"base_url 必须是 http(s) 地址，当前为：{self.base_url!r}")
        if self.temperature < 0:
            raise ConfigError("temperature 不能为负数")
        if self.max_iterations < 1:
            raise ConfigError("max_iterations 至少为 1")
        if self.max_retries < 0:
            raise ConfigError("max_retries 不能为负数")
        if self.lang not in {"zh", "en"}:
            raise ConfigError(f"lang 仅支持 'zh' 或 'en'，当前为：{self.lang!r}")
        if self.max_tokens < 256:
            raise ConfigError("max_tokens 至少为 256")

    @property
    def chat_completions_url(self) -> str:
        """拼接 /chat/completions 端点。兼容根地址与已带该路径的完整地址，只做幂等拼接，不做服务商特判。"""
        base = self.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    @property
    def workspace_path(self) -> Path:
        """工具可访问的根目录。"""
        return Path(self.workspace_root).resolve() if self.workspace_root else Path.cwd().resolve()

    def describe(self) -> str:
        """人类可读的配置摘要（**不包含** API Key 明文）。"""
        masked = "未配置"
        if self.mock:
            masked = "离线 Mock 模式（不调用真实 API）"
        elif self.api_key:
            key = self.api_key
            # 只展示前 8 位便于识别是哪个 Key；短 Key 完全遮蔽
            masked = f"{key[:8]}...{key[-4:]}" if len(key) > 16 else "***（已配置，长度过短不便展示）"
        return (
            f"model={self.model}  base_url={self.base_url}\n"
            f"api_key={masked}  temperature={self.temperature}  "
            f"max_iterations={self.max_iterations}  lang={self.lang}"
        )


def _coerce(raw: str, type_hint: Any, name: str) -> Any:
    """把环境变量的字符串转成 dataclass 字段声明的类型。"""
    hint = type_hint if isinstance(type_hint, str) else getattr(type_hint, "__name__", "str")
    try:
        if hint == "bool":
            return _parse_bool(raw)
        if hint == "int":
            return int(raw)
        if hint == "float":
            return float(raw)
    except ValueError as exc:  # pragma: no cover - 依赖用户输入
        raise ConfigError(f"环境变量 {ENV_PREFIX}{name.upper()} 的值 {raw!r} 无法解析为 {hint}") from exc
    return raw
