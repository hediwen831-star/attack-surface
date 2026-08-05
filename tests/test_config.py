"""配置加载与校验测试。

覆盖重点：配置错误必须在启动时炸掉。
「跑到一半才发现并发数是字符串」是典型的低质量工具行为。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asp.config import Config, load_config
from asp.exceptions import ConfigError


def test_defaults_are_valid():
    config = Config()
    config.validate()
    assert config.discover.concurrency == 100
    assert config.discover.sources == ["crtsh"]
    assert config.log_level == "INFO"


def test_from_dict_basic():
    config = Config.from_dict(
        {
            "http": {"timeout": 5.0, "retries": 1},
            "discover": {"concurrency": 30, "sources": ["crtsh", "brute"]},
            "database": "x.db",
            "log_level": "DEBUG",
        }
    )
    assert config.http.timeout == 5.0
    assert config.http.retries == 1
    assert config.discover.concurrency == 30
    assert config.discover.sources == ["crtsh", "brute"]
    assert config.database == "x.db"
    assert config.log_level == "DEBUG"


def test_unknown_top_level_key_raises():
    with pytest.raises(ConfigError, match="未知字段"):
        Config.from_dict({"nope": 1})


def test_unknown_section_key_raises():
    with pytest.raises(ConfigError, match="未知字段"):
        Config.from_dict({"discover": {"concurency": 10}})  # 故意拼错


def test_section_must_be_mapping():
    with pytest.raises(ConfigError, match="必须是映射"):
        Config.from_dict({"discover": [1, 2, 3]})


@pytest.mark.parametrize(
    "payload, reason",
    [
        ({"discover": {"concurrency": 0}}, "并发数不能为 0"),
        ({"discover": {"concurrency": -5}}, "并发数不能为负"),
        ({"discover": {"rate_limit": 0}}, "限速必须为正"),
        ({"http": {"timeout": 0}}, "超时必须为正"),
        ({"http": {"retries": -1}}, "重试次数不能为负"),
        ({"log_level": "VERBOSE"}, "日志级别非法"),
    ],
)
def test_semantic_validation(payload, reason):
    with pytest.raises(ConfigError):
        Config.from_dict(payload)


def test_env_override(monkeypatch):
    monkeypatch.setenv("ASP_DISCOVER_CONCURRENCY", "250")
    monkeypatch.setenv("ASP_HTTP_TIMEOUT", "3.5")
    monkeypatch.setenv("ASP_DATABASE", "custom.db")

    config = Config.from_dict({"discover": {"concurrency": 10}})
    assert config.discover.concurrency == 250
    assert config.http.timeout == 3.5
    assert config.database == "custom.db"


def test_env_override_type_coercion(monkeypatch):
    """环境变量永远是字符串，必须被转成目标类型。"""
    monkeypatch.setenv("ASP_HTTP_VERIFY_SSL", "true")
    monkeypatch.setenv("ASP_DISCOVER_RATE_LIMIT", "12.5")

    config = Config.from_dict({})
    assert config.http.verify_ssl is True
    assert config.discover.rate_limit == 12.5


def test_from_file_roundtrip(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "discover:\n  concurrency: 42\n  sources: [crtsh]\nlog_level: WARNING\n",
        encoding="utf-8",
    )
    config = Config.from_file(path)
    assert config.discover.concurrency == 42
    assert config.log_level == "WARNING"


def test_from_file_missing(tmp_path: Path):
    with pytest.raises(ConfigError, match="不存在"):
        Config.from_file(tmp_path / "nope.yaml")


def test_from_file_yaml_syntax_error(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("discover:\n  - broken: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.from_file(path)


def test_from_file_root_not_mapping(tmp_path: Path):
    path = tmp_path / "list.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="根节点"):
        Config.from_file(path)


def test_load_config_without_file_falls_back_to_defaults(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert isinstance(config, Config)
    assert config.discover.concurrency == 100


def test_example_config_file_is_valid():
    """自检：仓库里的配置示例必须能通过校验（防止示例自己就是错的）。"""
    example = Path(__file__).resolve().parent.parent / "conf" / "config.example.yaml"
    config = Config.from_file(example)
    assert config.discover.sources == ["crtsh", "brute"]
    assert config.engine.poc_dirs == ["pocs"]
