"""示例：工具函数模块，问题相对轻微，用于展示"分级"的审查结论。

⚠️ 本文件同样**故意**包含若干缺陷，请勿用于生产环境。
"""

import datetime
import re
import sys


def parse_config_line(line):
    parts = line.split("=")
    if len(parts) != 2:
        return None
    key = parts[0].strip()
    value = parts[1].strip()
    if value.upper() == "TRUE":
        return (key, True)
    if value.upper() == "FALSE":
        return (key, False)
    return (key, value)


def is_valid_email(email):
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email) != None


def retry_call(func, times=3, delay=1):
    last_error = None
    for _ in range(times):
        try:
            return func()
        except Exception as e:
            last_error = e
    raise last_error


def format_timestamp(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def truncate(text, limit):
    if len(text) <= limit:
        return text
    else:
        return text[:limit] + "..."


def safe_int(value):
    try:
        return int(value)
    except:
        return 0


def merge_dicts(a, b):
    result = {}
    result.update(a)
    result.update(b)
    return result


def get_env_or_default(name, default=None):
    if name in os.environ:
        return os.environ[name]
    return default


def chunk(items, size=100):
    chunks = []
    for index in range(0, len(items), size):
        chunks.append(items[index:index + size])
    return chunks
