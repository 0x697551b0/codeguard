"""示例：一个**写得比较规范**的模块，用于对照演示。

它的作用是让审查报告有"值得肯定的设计"可以写，
同时验证 CodeGuard 不会在干净代码上乱报问题（低误报率）。

本文件是参考实现（reference implementation），确实用于演示对照，
因此不属于"故意注入缺陷"的文件。
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Sequence

logger = logging.getLogger(__name__)

#: 默认重试次数
DEFAULT_MAX_RETRIES = 3
#: 基础退避秒数
DEFAULT_BACKOFF_SECONDS = 0.5
#: 认为可重试的 HTTP 状态码
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class UpstreamError(RuntimeError):
    """上游服务返回错误。"""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"upstream returned {status_code}: {message}")
        self.status_code = status_code


@dataclass(frozen=True)
class RetryPolicy:
    """重试策略（不可变，避免被调用方意外修改）。"""

    max_retries: int = DEFAULT_MAX_RETRIES
    base_delay: float = DEFAULT_BACKOFF_SECONDS
    max_delay: float = 30.0

    def delay_for(self, attempt: int) -> float:
        """计算第 ``attempt`` 次重试的等待秒数（指数退避，带上限）。

        Args:
            attempt: 从 1 开始的尝试序号。

        Returns:
            等待秒数，不超过 :attr:`max_delay`。
        """
        if attempt < 1:
            raise ValueError("attempt must be >= 1")
        return min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)


@dataclass
class RequestRecord:
    """一次请求的结果记录。"""

    url: str
    attempts: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


def read_int_env(name: str, default: int) -> int:
    """从环境变量读取整数，缺失或非法时返回默认值。

    Args:
        name: 环境变量名。
        default: 默认值。

    Returns:
        解析后的整数。
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("环境变量 %s 的值 %r 不是整数，回退到默认值 %d", name, raw, default)
        return default


def chunked(items: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    """把序列切成固定大小的块。

    Args:
        items: 输入序列。
        size: 每块的最大长度，必须为正。

    Yields:
        连续的子序列。

    Raises:
        ValueError: ``size`` 不是正数时。
    """
    if size <= 0:
        raise ValueError(f"size must be positive, got {size}")
    for start in range(0, len(items), size):
        yield items[start : start + size]


def classify_status(status_code: int) -> str:
    """把 HTTP 状态码归类。

    Args:
        status_code: HTTP 状态码。

    Returns:
        ``"success"`` / ``"retryable"`` / ``"fatal"`` 之一。
    """
    if 200 <= status_code < 300:
        return "success"
    if status_code in RETRYABLE_STATUS_CODES:
        return "retryable"
    return "fatal"


def execute_with_retry(
    operation: "callable",
    policy: RetryPolicy | None = None,
    *,
    sleep: "callable" = time.sleep,
) -> tuple[Any, RequestRecord]:
    """执行可重试操作，失败时按策略退避重试。

    通过注入 ``sleep`` 可以在测试中避免真实等待。

    Args:
        operation: 无参可调用对象；抛出的异常若带 ``status_code`` 且属于可重试集合则重试。
        policy: 重试策略；``None`` 时使用默认值。
        sleep: 休眠函数，便于测试替换。

    Returns:
        ``(操作返回值, 请求记录)``。

    Raises:
        UpstreamError: 重试耗尽后最后一次失败仍为可重试错误。
    """
    active_policy = policy or RetryPolicy()
    record = RequestRecord(url=getattr(operation, "__name__", "<operation>"))
    started = time.perf_counter()

    last_error: Exception | None = None
    for attempt in range(1, active_policy.max_retries + 2):
        record.attempts = attempt
        try:
            result = operation()
        except UpstreamError as exc:
            last_error = exc
            record.errors.append(str(exc))
            retryable = classify_status(exc.status_code) == "retryable"
            if not retryable or attempt > active_policy.max_retries:
                break
            delay = active_policy.delay_for(attempt)
            logger.warning("第 %d 次调用失败（%s），%.2fs 后重试", attempt, exc, delay)
            sleep(delay)
        except Exception as exc:  # 非上游错误：不重试，直接向上抛
            record.duration_seconds = time.perf_counter() - started
            logger.exception("操作发生未预期异常，不再重试")
            raise
        else:
            record.duration_seconds = time.perf_counter() - started
            return result, record

    record.duration_seconds = time.perf_counter() - started
    if last_error is not None:
        raise last_error
    raise RuntimeError("retry loop exited without result")  # pragma: no cover


def dedupe_preserving_order(items: Iterable[Any]) -> list[Any]:
    """去重并保持首次出现的顺序。

    Args:
        items: 可迭代对象，元素必须可哈希。

    Returns:
        去重后的列表。
    """
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
