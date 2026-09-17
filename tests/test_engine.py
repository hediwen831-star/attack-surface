"""执行引擎测试。

覆盖重点：
- 变量渲染（含自动补协议）
- **负向对照校验**：这是引擎防误报的核心机制，必须有测试守住
- 提取器结果进入漏洞记录
- 置信度与排序
"""

from __future__ import annotations

from conftest import FakeHttpClient

from asp.plugins.engine import (
    build_variables,
    render,
    run_poc,
    scan_target,
)
from asp.plugins.loader import parse_poc


def _poc(matchers, paths=None, condition="and", extractors=None):
    """构造测试用 PoC。"""
    request = {
        "method": "GET",
        "path": paths or ["{{BaseURL}}/target"],
        "matchers-condition": condition,
        "matchers": matchers,
    }
    if extractors:
        request["extractors"] = extractors
    return parse_poc(
        {
            "id": "t",
            "info": {"name": "t", "severity": "high"},
            "requests": [request],
        }
    )


# --------------------------------------------------------------- 变量


def test_build_variables_adds_scheme():
    variables = build_variables("example.com")
    assert variables["BaseURL"] == "http://example.com"
    assert variables["Hostname"] == "example.com"
    assert variables["Scheme"] == "http"


def test_build_variables_https_with_port():
    variables = build_variables("https://example.com:8443")
    assert variables["BaseURL"] == "https://example.com:8443"
    assert variables["RootURL"] == "https://example.com"
    assert variables["Port"] == "8443"


def test_build_variables_default_port():
    assert build_variables("https://example.com")["Port"] == "443"
    assert build_variables("http://example.com")["Port"] == "80"


def test_render_substitutes_all_variables():
    variables = build_variables("http://1.2.3.4:8080")
    assert render("{{BaseURL}}/.git/config", variables) == "http://1.2.3.4:8080/.git/config"
    assert render("{{RootURL}}/x", variables) == "http://1.2.3.4/x"
    assert render("{{Port}}", variables) == "8080"


def test_render_leaves_unknown_placeholder():
    """未知占位符保持原样 —— 便于在结果里一眼看出 PoC 写错了变量名。"""
    assert render("{{Nope}}", {"BaseURL": "x"}) == "{{Nope}}"


# --------------------------------------------------------------- 命中


async def test_run_poc_hit(fake_client):
    poc = _poc(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["[core]"]},
        ]
    )
    client = fake_client(
        {
            "/target": __import__("asp.core.http", fromlist=["Response"]).Response(
                url="http://example.com/target",
                status=200,
                headers={},
                content=b"[core]\nrepositoryformatversion = 0",
            )
        }
    )

    results = await run_poc(poc, "http://example.com", client)
    assert len(results) == 1
    assert results[0].poc_id == "t"
    assert results[0].severity == "high"
    assert results[0].confidence == 1.0
    assert results[0].verified is True


async def test_run_poc_miss_returns_empty(fake_client):
    poc = _poc([{"type": "status", "status": [200]}])
    client = fake_client()  # 默认全部 404
    assert await run_poc(poc, "http://example.com", client) == []


async def test_run_poc_or_condition_lower_confidence(fake_client):
    from asp.core.http import Response

    poc = _poc(
        [
            {"type": "word", "part": "body", "words": ["swagger"], "case-insensitive": True},
            {"type": "regex", "part": "body", "regex": ['"paths"\\s*:\\s*\\{']},
        ],
        condition="or",
    )
    client = fake_client(
        {
            "/target": Response(
                url="http://example.com/target",
                status=200,
                headers={},
                content=b"swagger-ui",
            )
        }
    )

    results = await run_poc(poc, "http://example.com", client)
    assert len(results) == 1
    assert results[0].confidence < 1.0


# --------------------------------------------------- 负向对照（核心）


async def test_negative_control_filters_universal_200_page(fake_client):
    """误报场景：站点对任何路径都返回 200 + 相同页面。

    此时 PoC 应该判为**误报**并被丢弃，
    否则一个「状态码 200」的 PoC 会命中全部路径。
    """
    from asp.core.http import Response

    universal = Response(
        url="", status=200, headers={}, content=b"[core]\nrepositoryformatversion = 0"
    )
    assert universal.status == 200  # 保留引用，说明上面构造的「通用页面」是什么样子
    poc = _poc(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["[core]"]},
        ]
    )

    # 构造一个「任何路径都返回同一页面」的客户端
    class UniversalClient(FakeHttpClient):
        async def request(self, method, url, **kwargs):
            self.calls.append(url)
            return Response(
                url=url,
                status=200,
                headers={},
                content=b"[core]\nrepositoryformatversion = 0",
            )

    client = UniversalClient()
    results = await run_poc(poc, "http://example.com", client)

    assert results == [], "通用 200 页面必须被负向对照识别为误报"
    # 证明确实发了对照请求
    assert any("asp-ctl-" in url for url in client.calls)


async def test_negative_control_keeps_real_hit(fake_client):
    """真实漏洞场景：特殊路径命中，随机路径不命中 → 保留。"""
    from asp.core.http import Response

    poc = _poc(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["[core]"]},
        ]
    )
    client = fake_client(
        {
            "/target": Response(
                url="http://example.com/target",
                status=200,
                headers={},
                content=b"[core]\nrepositoryformatversion = 0",
            )
        }
    )

    results = await run_poc(poc, "http://example.com", client)
    assert len(results) == 1
    assert results[0].verified is True


async def test_negative_control_can_be_disabled(fake_client):
    from asp.core.http import Response

    poc = _poc(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["[core]"]},
        ]
    )
    client = fake_client(
        {
            "/target": Response(
                url="http://example.com/target", status=200, headers={}, content=b"[core]"
            )
        }
    )

    results = await run_poc(poc, "http://example.com", client, negative_control=False)
    assert len(results) == 1
    # 关闭对照后不应产生 asp-ctl- 请求
    assert not any("asp-ctl-" in url for url in client.calls)


async def test_control_url_same_directory():
    """对照 URL 必须落在与命中 URL 相同的目录下，否则对照没有意义。"""
    from asp.plugins.engine import _random_control_url

    control = _random_control_url("http://example.com/admin/config.php")
    assert control.startswith("http://example.com/admin/asp-ctl-")

    control_root = _random_control_url("http://example.com/config.php")
    assert control_root.startswith("http://example.com/asp-ctl-")


# --------------------------------------------------------------- 提取器


async def test_extractor_results_included(fake_client):
    from asp.core.http import Response

    poc = _poc(
        [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["version"]},
        ],
        extractors=[
            {
                "type": "regex",
                "part": "body",
                "name": "ver",
                "regex": [r"version[=:]\s*([\d.]+)"],
            }
        ],
    )
    client = fake_client(
        {
            "/target": Response(
                url="http://example.com/target",
                status=200,
                headers={},
                content=b"app version:1.2.3",
            )
        }
    )

    results = await run_poc(poc, "http://example.com", client)
    assert results[0].extracted["ver"] == "1.2.3"


# --------------------------------------------------------------- 多路径


async def test_multiple_paths_report_separately(fake_client):
    from asp.core.http import Response

    poc = _poc(
        [{"type": "status", "status": [200]}],
        paths=["{{BaseURL}}/a", "{{BaseURL}}/b", "{{BaseURL}}/c"],
    )
    hit = lambda url: Response(url=url, status=200, headers={}, content=b"ok")  # noqa: E731
    client = fake_client({"/a": hit("http://example.com/a"), "/c": hit("http://example.com/c")})

    results = await run_poc(poc, "http://example.com", client)
    targets = sorted(r.target for r in results)
    assert targets == ["http://example.com/a", "http://example.com/c"]


# --------------------------------------------------------------- 批量


async def test_scan_target_sorts_by_severity(fake_client):
    from asp.core.http import Response

    body = b"[core]\nrepositoryformatversion = 0"
    low_poc = parse_poc(
        {
            "id": "low-one",
            "info": {"name": "low", "severity": "low"},
            "requests": [
                {
                    "path": ["{{BaseURL}}/low"],
                    "matchers": [{"type": "status", "status": [200]}],
                }
            ],
        }
    )
    critical_poc = parse_poc(
        {
            "id": "crit-one",
            "info": {"name": "crit", "severity": "critical"},
            "requests": [
                {
                    "path": ["{{BaseURL}}/crit"],
                    "matchers": [{"type": "status", "status": [200]}],
                }
            ],
        }
    )

    client = fake_client(
        {
            "/low": Response(url="http://x/low", status=200, headers={}, content=body),
            "/crit": Response(url="http://x/crit", status=200, headers={}, content=body),
        }
    )

    result = await scan_target("http://x", [low_poc, critical_poc], client)
    assert result.hit_count == 2
    assert result.vulns[0].severity == "critical"
    assert result.vulns[1].severity == "low"
    assert result.by_severity() == {"critical": 1, "low": 1}


async def test_scan_target_survives_broken_poc(fake_client):
    """单个 PoC 内部抛错不能中断整次扫描。"""

    broken = parse_poc(
        {
            "id": "broken",
            "info": {"name": "b", "severity": "low"},
            "requests": [
                {
                    "path": ["{{BaseURL}}/x"],
                    "matchers": [{"type": "status", "status": [200]}],
                }
            ],
        }
    )
    broken.requests[0].matchers = [{"type": "nonsense"}]

    good = parse_poc(
        {
            "id": "good",
            "info": {"name": "g", "severity": "high"},
            "requests": [
                {
                    "path": ["{{BaseURL}}/y"],
                    "matchers": [{"type": "status", "status": [200]}],
                }
            ],
        }
    )

    from asp.core.http import Response

    client = fake_client(
        {"/y": Response(url="http://x/y", status=200, headers={}, content=b"ok")}
    )
    result = await scan_target("http://x", [broken, good], client)
    assert result.hit_count == 1
    assert result.vulns[0].poc_id == "good"
    assert result.errors  # 错误被记录而不是被吞掉


async def test_scan_target_records_zero_hits(fake_client):
    poc = _poc([{"type": "status", "status": [200]}])
    result = await scan_target("http://x", [poc], fake_client())
    assert result.hit_count == 0
    assert result.poc_count == 1
