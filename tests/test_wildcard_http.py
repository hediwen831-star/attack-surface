"""HTTP 指纹判定单测（离线）。

覆盖三件事：
1. 正文归一化能把随机 trace id、时间戳抹掉，同一张默认页相似度接近 1；
2. 两个不同页面相似度低；
3. 接进 BruteForceSource 后：CDN 同 IP 的真实站点能留下来，
   而泛解析噪音照样被过滤；HTTP 探测失败时退回纯 IP 比对。
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import asp.discover.bruteforce as brute_mod  # noqa: E402
from asp.config import Config  # noqa: E402
from asp.core.http import Response  # noqa: E402
from asp.discover.bruteforce import BruteForceSource  # noqa: E402
from asp.discover.wildcard_http import (  # noqa: E402
    Fingerprint,
    looks_like_wildcard,
    normalize_body,
    similarity,
)

ZONE = "cdn.test"
DEFAULT_PAGE = """
<html><body>默认站点 trace 5f3a9c1d2e4b6a8f
<script>var t=1730000000123;</script></body></html>
"""
REAL_PAGE = """
<html><body><h1>某某科技官网</h1><nav>产品 方案 关于我们</nav></body></html>
"""


class FakeClient:
    """按 host 返回预设页面，模拟 CDN 边缘节点。"""

    def __init__(self, pages: dict[str, str], *, fail: bool = False) -> None:
        self.pages = pages
        self.fail = fail
        self.calls: list[str] = []

    async def get(self, url: str, **_: object) -> Response:
        self.calls.append(url)
        if self.fail:
            return Response(url=url, status=0, error="timeout")
        host = url.split("://", 1)[1].split("/", 1)[0]
        body = self.pages.get(host, self.pages.get("*", DEFAULT_PAGE))
        return Response(url=url, status=200, headers={"server": "cdn"}, content=body.encode())


def test_normalize_strips_volatile_parts() -> None:
    a = normalize_body("<html>trace 5f3a9c1d2e4b6a8f  时间 1730000000123</html>")
    b = normalize_body("<html>trace 9a8b7c6d5e4f3a2b\n时间 1730000099999</html>")
    assert a == b


def test_similarity_distinguishes_pages() -> None:
    default = Fingerprint(status=200, sample=normalize_body(DEFAULT_PAGE))
    same = Fingerprint(status=200, sample=normalize_body(DEFAULT_PAGE))
    real = Fingerprint(status=200, sample=normalize_body(REAL_PAGE))

    assert similarity(default, same) > 0.95
    assert similarity(default, real) < 0.6
    assert looks_like_wildcard(same, [default]) is True
    assert looks_like_wildcard(real, [default]) is False


def _source(pages: dict[str, str], *, fail: bool = False, http_verify: bool = True) -> BruteForceSource:
    config = Config()
    config.discover.brute_concurrency = 4
    source = BruteForceSource(config, FakeClient(pages, fail=fail), http_verify=http_verify)
    source.words = ["www", "api", "dev"]
    source.wildcard_ips = {"9.9.9.9"}
    return source


def test_cdn_same_ip_real_host_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(hostname: str, timeout: float = 1.0) -> set[str]:
        return {"9.9.9.9"}

    monkeypatch.setattr(brute_mod, "resolve_host", resolve)

    pages = {"www.cdn.test": REAL_PAGE}
    assets = asyncio.run(_source(pages).fetch(ZONE))

    assert [a.value for a in assets] == ["www.cdn.test"]
    assert assets[0].metadata.get("http_verified") == "1"


def test_uniform_wildcard_page_is_still_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(hostname: str, timeout: float = 1.0) -> set[str]:
        return {"9.9.9.9"}

    monkeypatch.setattr(brute_mod, "resolve_host", resolve)

    # 所有 host 都返回同一张默认页 —— HTTP 判定不该把噪音救回来
    assets = asyncio.run(_source({}).fetch(ZONE))
    assert assets == []


def test_http_failure_falls_back_to_ip_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(hostname: str, timeout: float = 1.0) -> set[str]:
        return {"9.9.9.9"}

    monkeypatch.setattr(brute_mod, "resolve_host", resolve)

    pages = {"www.cdn.test": REAL_PAGE}
    assets = asyncio.run(_source(pages, fail=True).fetch(ZONE))

    # 探测不到就维持原判：过滤。宁可少留，也不放大片噪音。
    assert assets == []


def test_http_verify_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve(hostname: str, timeout: float = 1.0) -> set[str]:
        return {"9.9.9.9"}

    monkeypatch.setattr(brute_mod, "resolve_host", resolve)

    pages = {"www.cdn.test": REAL_PAGE}
    assets = asyncio.run(_source(pages, http_verify=False).fetch(ZONE))
    assert assets == []


def test_client_ignores_env_proxy_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """默认不继承环境代理。

    本机踩过：环境里有 http_proxy 时，连不上的端口会返回代理的 502，
    看起来像「有响应」，指纹判定会把整片关闭端口当成同一张页面。
    """
    from asp.core.http import AsyncHttpClient

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:7897")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7897")

    client = AsyncHttpClient(concurrency=1, rate_limit=1)
    try:
        assert client.trust_env is False
        assert client._client.trust_env is False
    finally:
        asyncio.run(client.aclose())
