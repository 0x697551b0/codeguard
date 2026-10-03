"""配置加载测试：环境变量、.env 解析、校验与派生属性。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.compat import writable_tempdir
from codeguard.config import Config, load_dotenv
from codeguard.exceptions import ConfigError


def clear_env() -> None:
    for key in list(os.environ):
        if key.startswith("CODEGUARD_"):
            del os.environ[key]


def test_env_overrides_and_defaults() -> None:
    clear_env()
    os.environ["CODEGUARD_API_KEY"] = "sk-from-env"
    os.environ["CODEGUARD_MODEL"] = "deepseek-reasoner"
    os.environ["CODEGUARD_MAX_ITERATIONS"] = "7"
    os.environ["CODEGUARD_MOCK"] = "true"
    os.environ["CODEGUARD_TEMPERATURE"] = "0.7"
    try:
        config = Config.from_env(dotenv_path=None)
        assert config.api_key == "sk-from-env"
        assert config.model == "deepseek-reasoner"
        assert config.max_iterations == 7
        assert config.mock is True
        assert config.temperature == 0.7
    finally:
        clear_env()


def test_keyword_override_beats_env() -> None:
    clear_env()
    os.environ["CODEGUARD_MODEL"] = "from-env"
    try:
        config = Config.from_env(dotenv_path=None, model="from-arg")
        assert config.model == "from-arg"
    finally:
        clear_env()


def test_load_dotenv_parsing_rules() -> None:
    with writable_tempdir("dotenv_") as tmp:
        env_file = Path(tmp) / ".env"
        env_file.write_text(
            "\n".join(
                [
                    "# 注释行",
                    "",
                    "CODEGUARD_MODEL=deepseek-chat",
                    'CODEGUARD_API_KEY="sk-quoted-value"',
                    "export CODEGUARD_LANG=en",
                    "MALFORMED_LINE_WITHOUT_EQUALS",
                    "CODEGUARD_TIMEOUT=12.5",
                ]
            ),
            encoding="utf-8",
        )
        clear_env()
        parsed = load_dotenv(env_file)
        try:
            assert parsed["CODEGUARD_MODEL"] == "deepseek-chat"
            assert parsed["CODEGUARD_API_KEY"] == "sk-quoted-value"
            assert os.environ["CODEGUARD_LANG"] == "en"
            config = Config.from_env(dotenv_path=env_file)
            assert config.timeout == 12.5
        finally:
            clear_env()


def test_load_dotenv_missing_file_is_silent() -> None:
    assert load_dotenv("definitely_not_here.env") == {}


def test_load_dotenv_does_not_override_existing() -> None:
    clear_env()
    os.environ["CODEGUARD_MODEL"] = "preset"
    with writable_tempdir("dotenv2_") as tmp:
        env_file = Path(tmp) / ".env"
        env_file.write_text("CODEGUARD_MODEL=from-file\n", encoding="utf-8")
        load_dotenv(env_file)
        assert os.environ["CODEGUARD_MODEL"] == "preset"
        load_dotenv(env_file, override=True)
        assert os.environ["CODEGUARD_MODEL"] == "from-file"
    clear_env()


def test_validate_requires_api_key_unless_mock() -> None:
    try:
        Config(api_key="").validate()
    except ConfigError as exc:
        assert "API Key" in str(exc)
        assert "--mock" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("缺少 API Key 应当报错")

    Config(api_key="", mock=True).validate()  # 不应抛异常


def test_validate_rejects_bad_values() -> None:
    for bad in (
        Config(api_key="k", base_url="ftp://x"),
        Config(api_key="k", temperature=-1),
        Config(api_key="k", max_iterations=0),
        Config(api_key="k", max_retries=-1),
        Config(api_key="k", lang="fr"),
        Config(api_key="k", max_tokens=10),
    ):
        try:
            bad.validate()
        except ConfigError:
            continue
        raise AssertionError(f"非法配置应当报错：{bad}")


def test_describe_masks_api_key() -> None:
    config = Config(api_key="sk-1234567890abcdefgh")
    described = config.describe()
    assert "sk-1234" in described
    assert "567890abcdefgh" not in described
    assert "..." in described

    short = Config(api_key="short").describe()
    assert "short" not in short

    assert "离线 Mock" in Config(mock=True).describe()
    assert "未配置" in Config(api_key="").describe()


def test_workspace_path_resolution() -> None:
    config = Config(workspace_root=".")
    assert config.workspace_path.is_absolute()
    assert Config().workspace_path == Path.cwd().resolve()
