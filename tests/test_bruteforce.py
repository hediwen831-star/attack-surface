"""资产发现与泛解析过滤测试。

这是整个项目**最有价值的一组测试**，因为泛解析过滤的正确性直接决定
扫描结果可用还是不可用。全部离线：通过 monkeypatch 替换 DNS 解析函数。

测试思路：构造一个「假 DNS 世界」——
- 泛解析域名下，任意名字都解析到固定的 wildcard IP
- 真实域名额外解析到自己的 IP

然后断言：泛解析产生的假资产被丢掉，真实资产被保留。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asp.config import Config
from asp.discover import bruteforce
from asp.discover.base import DiscoveredAsset
from asp.discover.bruteforce import (
    BUILTIN_WORDLIST,
    BruteForceSource,
    detect_wildcard,
    load_wordlist,
)

# ----------------------------------------------------------- 数据规范化


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("WWW.Example.COM", "www.example.com"),
        ("www.example.com.", "www.example.com"),
        ("*.example.com", "example.com"),
        ("  mail.example.com  ", "mail.example.com"),
        ("*.api.example.com", "api.example.com"),
    ],
)
def test_discovered_asset_normalize(raw, expected):
    assert DiscoveredAsset.normalize(raw) == expected


def test_discovered_asset_normalizes_on_init():
    """__post_init__ 里做规范化，保证任何构造路径都不会漏掉。"""
    asset = DiscoveredAsset(value="*.Test.Example.com.", source="x")
    assert asset.value == "test.example.com"


# ----------------------------------------------------------- 字典


def test_load_wordlist_builtin_when_none():
    words = load_wordlist(None)
    assert words == list(BUILTIN_WORDLIST)
    assert "www" in words and "api" in words


def test_load_wordlist_from_file(tmp_path: Path):
    path = tmp_path / "words.txt"
    path.write_text("# 注释\nwww\n\napi\n  mail  \n", encoding="utf-8")
    assert load_wordlist(path) == ["www", "api", "mail"]


def test_load_wordlist_missing_falls_back(tmp_path: Path):
    """字典文件不存在时降级用内置字典，而不是直接失败。"""
    assert load_wordlist(tmp_path / "nope.txt") == list(BUILTIN_WORDLIST)


def test_load_wordlist_all_comments_falls_back(tmp_path: Path):
    path = tmp_path / "only_comments.txt"
    path.write_text("# a\n# b\n", encoding="utf-8")
    assert load_wordlist(path) == list(BUILTIN_WORDLIST)


# ----------------------------------------------------------- 泛解析检测


def _fake_resolver(mapping: dict[str, set[str]]):
    """构造一个假的解析函数：按 mapping 返回，查不到返回空集。"""

    async def _resolve(hostname: str, timeout: float = 5.0) -> set[str]:
        return set(mapping.get(hostname, set()))

    return _resolve


async def test_detect_wildcard_absent(monkeypatch):
    """所有随机探测都解析失败 → 不存在泛解析。"""
    monkeypatch.setattr(bruteforce, "resolve_host", _fake_resolver({}))
    assert await detect_wildcard("example.com") == set()


async def test_detect_wildcard_present(monkeypatch):
    """所有随机探测都指向同一 IP → 判定存在泛解析。"""
    mapping = {
        "asp-probe-a.example.com": {"1.2.3.4"},
        "asp-probe-b.example.com": {"1.2.3.4"},
        "asp-probe-c.example.com": {"1.2.3.4"},
    }
    monkeypatch.setattr(bruteforce, "resolve_host", _fake_resolver(mapping))

    # 随机标签每次不同，所以用一个忽略具体名字的解析器
    async def _always_wildcard(hostname: str, timeout: float = 5.0) -> set[str]:
        return {"1.2.3.4"}

    monkeypatch.setattr(bruteforce, "resolve_host", _always_wildcard)
    assert await detect_wildcard("example.com") == {"1.2.3.4"}


async def test_detect_wildcard_single_hit_is_noise(monkeypatch):
    """只有 1 个随机域名命中 → 视为偶发噪声（如运营商 DNS 劫持），不判为泛解析。"""
    calls = {"n": 0}

    async def _single_hit(hostname: str, timeout: float = 5.0) -> set[str]:
        calls["n"] += 1
        return {"9.9.9.9"} if calls["n"] == 1 else set()

    monkeypatch.setattr(bruteforce, "resolve_host", _single_hit)
    assert await detect_wildcard("example.com") == set()


# ----------------------------------------------------------- 爆破 + 过滤


async def test_bruteforce_filters_wildcard_fake_assets(monkeypatch):
    """核心场景：泛解析域名的爆破结果必须几乎全部被过滤。

    假 DNS 世界：
    - 任意 *.example.com 都解析到 1.2.3.4（泛解析）
    - mail.example.com 额外解析到 5.6.7.8（真实记录）
    """
    real_only = {"mail.example.com"}
    wildcard_ip = "1.2.3.4"
    real_ip = "5.6.7.8"

    async def _resolve(hostname: str, timeout: float = 5.0) -> set[str]:
        if hostname in real_only:
            return {wildcard_ip, real_ip}   # 同时有泛解析 IP 与真实 IP
        if hostname.endswith(".example.com"):
            return {wildcard_ip}            # 泛解析兜底
        return set()

    monkeypatch.setattr(bruteforce, "resolve_host", _resolve)

    config = Config.from_dict({"discover": {"brute_concurrency": 50}})
    source = BruteForceSource(config, None, wordlist=None)
    results = await source.fetch("example.com")

    values = {r.value for r in results}

    # 真实资产保留
    assert "mail.example.com" in values
    # 泛解析产生的假资产被过滤 —— 这是本测试的核心断言
    assert not any(v.endswith(".example.com") for v in values if v != "mail.example.com")
    assert len(values) == 1


async def test_bruteforce_no_wildcard_keeps_all(monkeypatch):
    """没有泛解析时，所有解析成功的域名都应保留。"""
    alive = {"www.example.com", "api.example.com", "mail.example.com"}

    async def _resolve(hostname: str, timeout: float = 5.0) -> set[str]:
        return {"10.0.0.1"} if hostname in alive else set()

    monkeypatch.setattr(bruteforce, "resolve_host", _resolve)

    config = Config.from_dict({})
    source = BruteForceSource(config, None, wordlist=None)
    results = await source.fetch("example.com")

    assert {r.value for r in results} == alive


async def test_bruteforce_records_wildcard_ips(monkeypatch):
    """源必须把泛解析基线暴露出来，供报告展示与二次判断。"""

    async def _resolve(hostname: str, timeout: float = 5.0) -> set[str]:
        return {"1.2.3.4"}

    monkeypatch.setattr(bruteforce, "resolve_host", _resolve)

    config = Config.from_dict({})
    source = BruteForceSource(config, None, wordlist=None)
    await source.fetch("example.com")

    assert source.wildcard_ips == {"1.2.3.4"}


async def test_bruteforce_merges_extra_ips(monkeypatch):
    """外部传入的额外泛解析 IP（如来自其它检测手段）应与内置检测结果合并。"""

    async def _resolve(hostname: str, timeout: float = 5.0) -> set[str]:
        return set()

    monkeypatch.setattr(bruteforce, "resolve_host", _resolve)

    config = Config.from_dict({})
    source = BruteForceSource(config, None, extra_ips={"8.8.8.8"})
    await source.fetch("example.com")

    assert source.wildcard_ips == {"8.8.8.8"}


async def test_bruteforce_dedupes_wordlist(monkeypatch):
    seen: list[str] = []

    async def _resolve(hostname: str, timeout: float = 5.0) -> set[str]:
        seen.append(hostname)
        return set()

    monkeypatch.setattr(bruteforce, "resolve_host", _resolve)

    config = Config.from_dict({})
    source = BruteForceSource(config, None, wordlist=None)
    await source.fetch("example.com")

    probed = [h for h in seen if h.endswith(".example.com") and not h.startswith("asp-probe-")]
    assert len(probed) == len(set(probed)), "字典中的重复词应被去重"


def test_builtin_wordlist_is_sane():
    """内置字典自检：无重复、无空项、无非法字符。"""
    words = list(BUILTIN_WORDLIST)
    assert len(words) == len(set(words)), "内置字典存在重复项"
    assert all(w and w == w.strip().lower() for w in words)
    assert all("." not in w for w in words), "字典项不该包含点号"
    assert len(words) >= 100
