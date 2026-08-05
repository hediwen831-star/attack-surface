"""pytest 共享夹具。

原则：所有单测必须**离线可跑**。
测绘工具天生依赖网络，但测试绝不能依赖网络 ——
否则 CI 会因为某个第三方站点抖动而红，久了就没人信测试了。
所以这里统一用构造的 ``Response`` 对象，不发起真实请求。
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import pytest

from asp.core.http import Response


@pytest.fixture
def make_response():
    """构造 ``Response`` 的工厂夹具。

    Example:
        >>> def test_x(make_response):
        ...     resp = make_response(status=200, body="[core]")
        ...     assert resp.ok
    """

    def _make(
        status: int = 200,
        body: str = "",
        headers: dict[str, str] | None = None,
        url: str = "http://example.com/",
    ) -> Response:
        return Response(
            url=url,
            status=status,
            headers=headers or {},
            content=body.encode("utf-8"),
            elapsed=0.01,
        )

    return _make


class FakeHttpClient:
    """假的 HTTP 客户端，用于测试引擎逻辑。

    行为约定：
    - 命中 ``routes`` 中注册的 URL → 返回对应响应
    - URL 含 ``asp-ctl-``（负向对照请求）→ 返回 404
    - 其他 → 返回 404

    这个设计让「负向对照校验」可以被精确测试：
    只要让对照 URL 返回 404，就等价于「对照未命中」。
    """

    def __init__(self, routes: dict[str, Response] | None = None, default_status: int = 404) -> None:
        self.routes = routes or {}
        self.default_status = default_status
        self.calls: list[str] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.calls.append(url)

        # 负向对照请求：模拟「随机路径不存在」
        if "asp-ctl-" in url:
            return Response(url=url, status=404, headers={}, content=b"", elapsed=0.0)

        # 精确匹配优先，其次按路径匹配
        if url in self.routes:
            return self.routes[url]

        parsed = urlparse(url)
        if parsed.path in self.routes:
            return self.routes[parsed.path]

        return Response(
            url=url, status=self.default_status, headers={}, content=b"", elapsed=0.0
        )

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Response:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        return None


@pytest.fixture
def fake_client():
    """返回 ``FakeHttpClient`` 类本身，便于各测试自行构造路由。"""
    return FakeHttpClient
