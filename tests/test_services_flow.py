"""服务层编排流程的测试（离线）。

`test_services.py` 覆盖的是数据类与纯函数；这里补的是**编排**：
源怎么拼、结果怎么合并、什么时候提前返回、写库写了什么。

这一层原来的覆盖率是 28% / 39%，缺的不是「难测」，而是外部依赖直接写在
函数体里（AsyncHttpClient、scan_host、resolve_host）。测试用 monkeypatch
把它们替换掉，产品代码不为测试让步 —— 除了上一轮加的 trust_env 参数。

每个用例的注释写的是它防的回归，不是它调用了哪个函数。
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

import asp.services.host as host_mod
import asp.services.subdomain as sub_mod
from asp.config import Config
from asp.core.database import (
    Asset,
    Component,
    Port,
    ScanTask,
    Service,
    create_db_engine,
    session_scope,
)
from asp.core.http import Response
from asp.discover.base import DiscoveredAsset
from asp.discover.fingerprint import CATEGORY_MIDDLEWARE, ComponentResult
from asp.discover.portscan import PortResult, ServiceInfo
from asp.services.host import HostReport, persist_host_report, probe_http, scan_and_fingerprint
from asp.services.subdomain import (
    SubdomainReport,
    _verify_assets,
    build_sources,
    collect_subdomains,
    diff_tasks,
    persist_report,
)

# ---------------------------------------------------------------- 假实现


class FakeClient:
    """只实现 get，够 probe_http / _fetch_favicon 用。"""

    def __init__(self, pages: dict[str, Response] | None = None) -> None:
        self.pages = pages or {}
        self.calls: list[str] = []

    async def get(self, url: str, **_: object) -> Response:
        self.calls.append(url)
        if url in self.pages:
            return self.pages[url]
        return Response(url=url, status=404, content=b"")


class FakeClientCtx:
    """替代 AsyncHttpClient 的异步上下文管理器，记录构造参数。"""

    last_kwargs: dict = {}

    def __init__(self, **kwargs: object) -> None:
        FakeClientCtx.last_kwargs = kwargs

    async def __aenter__(self) -> FakeClient:
        return FakeClient()

    async def __aexit__(self, *exc: object) -> None:
        return None


class FakeSource:
    """可配置的资产源。"""

    name = "fake"
    requires_network = False

    def __init__(self, assets: list[DiscoveredAsset], wildcard: set[str] | None = None) -> None:
        self.assets = assets
        self.wildcard_ips = wildcard or set()

    async def discover(self, target: str) -> list[DiscoveredAsset]:
        return list(self.assets)


def make_port(port: int, service: str = "http", state: str = "open", banner: str = "") -> PortResult:
    return PortResult(host="10.0.0.1", port=port, state=state, service=ServiceInfo(name=service), banner=banner)


def make_component(name: str, confidence: float = 0.8, evidence: str = "e") -> ComponentResult:
    return ComponentResult(
        name=name,
        version="1.0",
        category=CATEGORY_MIDDLEWARE,
        confidence=confidence,
        evidence=[evidence],
    )


class StubRule:
    """最小规则替身：只为验证 probe_http 把规则传进了匹配器。"""

    name = "demo"
    category = CATEGORY_MIDDLEWARE
    confidence = 0.8

    def matches(self, **_: object) -> list[str]:
        return ["stub"]

    def extract_version(self, text: str) -> str:
        return "1.0"


@pytest.fixture
def cfg(tmp_path) -> Config:
    config = Config()
    config.database = str(tmp_path / "test.db")
    return config


# ---------------------------------------------------------------- 源装配


class TestBuildSources:
    def test_unknown_name_is_skipped_not_fatal(self, cfg):
        """拼错源名不该让整次收集失败 —— 这是使用侧最常见的输入错误。"""
        built = build_sources(["crtsh", "not-a-source"], cfg, client=object())
        assert [s.name for s in built] == ["crtsh"]

    def test_brute_gets_wordlist_and_others_do_not(self, cfg, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("www\n", encoding="utf-8")
        built = build_sources(["brute", "crtsh"], cfg, client=object(), wordlist=str(wordlist))

        assert [s.name for s in built] == ["brute", "crtsh"]
        assert built[0].words == ["www"]

    def test_name_is_case_and_space_insensitive(self, cfg):
        built = build_sources([" CrTsH "], cfg, client=object())
        assert [s.name for s in built] == ["crtsh"]


# ---------------------------------------------------------------- 子域名编排


class TestCollectSubdomains:
    def test_merges_sources_and_records_provenance(self, cfg, monkeypatch):
        """同一个域名被两个源发现时必须合并成一条，并把来源拼起来。

        这条防的是「同一资产在报告里出现两次、来源只剩最后一个」的回归。
        """
        monkeypatch.setattr(sub_mod, "AsyncHttpClient", FakeClientCtx)

        a = DiscoveredAsset(value="www.example.com", source="crtsh", resolved_ip="1.1.1.1")
        b = DiscoveredAsset(value="WWW.example.com.", source="brute")
        monkeypatch.setattr(
            sub_mod,
            "SOURCE_REGISTRY",
            {
                "a": lambda config, client: FakeSource([a], {"9.9.9.9"}),
                "b": lambda config, client: FakeSource([b]),
            },
        )

        async def alive(host: str, timeout: float = 1.0) -> set[str]:
            return {"1.1.1.1"}

        monkeypatch.setattr(sub_mod, "resolve_host", alive)

        report = asyncio.run(collect_subdomains("example.com", cfg, sources=["a", "b"]))

        assert report.count == 1
        assert report.assets[0].value == "www.example.com"
        assert report.assets[0].metadata["sources"] == "crtsh,brute"
        assert report.wildcard_ips == {"9.9.9.9"}
        assert report.by_source() == {"crtsh": 1, "brute": 1}
        assert [x.value for x in report.multi_source()] == ["www.example.com"]

    def test_verify_false_keeps_unresolvable_candidates(self, cfg, monkeypatch):
        """关闭验证时必须保留死域名 —— 这是「快速模式」的语义。

        之前有版本无论 verify 与否都过滤，导致快速模式拿不到全量候选。
        """
        monkeypatch.setattr(sub_mod, "AsyncHttpClient", FakeClientCtx)
        monkeypatch.setattr(
            sub_mod,
            "SOURCE_REGISTRY",
            {"a": lambda config, client: FakeSource([DiscoveredAsset(value="dead.example.com", source="a")])},
        )

        report = asyncio.run(collect_subdomains("example.com", cfg, sources=["a"], verify=False))
        assert [a.value for a in report.assets] == ["dead.example.com"]

    def test_verify_true_drops_dead_and_fills_ips(self, cfg, monkeypatch):
        monkeypatch.setattr(sub_mod, "AsyncHttpClient", FakeClientCtx)
        monkeypatch.setattr(
            sub_mod,
            "SOURCE_REGISTRY",
            {
                "a": lambda config, client: FakeSource(
                    [
                        DiscoveredAsset(value="alive.example.com", source="a"),
                        DiscoveredAsset(value="dead.example.com", source="a"),
                    ]
                )
            },
        )

        async def resolve(host: str, timeout: float = 1.0) -> set[str]:
            return {"2.2.2.2", "1.1.1.1"} if host.startswith("alive") else set()

        monkeypatch.setattr(sub_mod, "resolve_host", resolve)

        report = asyncio.run(collect_subdomains("example.com", cfg, sources=["a"]))
        assert [a.value for a in report.assets] == ["alive.example.com"]
        assert report.assets[0].resolved_ip == "1.1.1.1"
        assert report.assets[0].metadata["all_ips"] == "1.1.1.1,2.2.2.2"

    def test_no_valid_source_returns_early(self, cfg, monkeypatch):
        """源名全都拼错时必须快速返回空报告，而不是抛异常。"""
        monkeypatch.setattr(sub_mod, "AsyncHttpClient", FakeClientCtx)
        report = asyncio.run(collect_subdomains("example.com", cfg, sources=["nope"]))
        assert report.count == 0
        assert report.sources_used == ["nope"]

    def test_assets_are_sorted_by_depth(self, cfg, monkeypatch):
        monkeypatch.setattr(sub_mod, "AsyncHttpClient", FakeClientCtx)
        monkeypatch.setattr(
            sub_mod,
            "SOURCE_REGISTRY",
            {
                "a": lambda config, client: FakeSource(
                    [
                        DiscoveredAsset(value="a.b.example.com", source="a"),
                        DiscoveredAsset(value="example.com", source="a"),
                        DiscoveredAsset(value="b.example.com", source="a"),
                    ]
                )
            },
        )
        monkeypatch.setattr(sub_mod, "resolve_host", lambda host, timeout=1.0: _async({"1.1.1.1"}))

        report = asyncio.run(collect_subdomains("example.com", cfg, sources=["a"], verify=True))
        assert [a.value for a in report.assets] == [
            "example.com",
            "b.example.com",
            "a.b.example.com",
        ]

    def test_empty_candidates_skip_verify(self, cfg):
        assert asyncio.run(_verify_assets([], cfg)) == []


async def _async(value):
    return value


# ---------------------------------------------------------------- 子域名持久化


class TestSubdomainPersistence:
    def test_persist_creates_task_and_assets(self, cfg):
        report = SubdomainReport(root="example.com", sources_used=["crtsh"], elapsed=1.23)
        report.assets = [
            DiscoveredAsset(value="www.example.com", source="crtsh", resolved_ip="1.1.1.1"),
            DiscoveredAsset(value="api.example.com", source="brute", resolved_ip="1.1.1.2"),
        ]
        report.assets[0].metadata["sources"] = "crtsh"
        report.assets[1].metadata["sources"] = "brute"

        assert persist_report(report, cfg) == 2

        engine = create_db_engine(cfg.database)
        with session_scope(engine) as session:
            task = session.execute(select(ScanTask)).scalars().one()
            rows = session.execute(select(Asset).order_by(Asset.value)).scalars().all()
            assert task.target == "example.com"
            assert task.get_stats()["total"] == 2
            assert [r.value for r in rows] == ["api.example.com", "www.example.com"]
            assert rows[0].source == "brute"

    def test_diff_between_two_runs(self, cfg):
        """两次扫描之间新增/消失的资产要能算出来 —— 这是平台的核心卖点。"""
        first = SubdomainReport(root="example.com", elapsed=0.1)
        first.assets = [
            DiscoveredAsset(value="a.example.com", source="s"),
            DiscoveredAsset(value="b.example.com", source="s"),
        ]
        persist_report(first, cfg)

        second = SubdomainReport(root="example.com", elapsed=0.1)
        second.assets = [
            DiscoveredAsset(value="b.example.com", source="s"),
            DiscoveredAsset(value="c.example.com", source="s"),
        ]
        persist_report(second, cfg)

        diff = diff_tasks(cfg, "example.com")
        assert diff["added"] == ["c.example.com"]
        assert diff["removed"] == ["a.example.com"]
        assert diff["unchanged"] == ["b.example.com"]

    def test_diff_with_single_run_is_empty(self, cfg):
        """只有一次历史时不能算出 diff，返回空而不是报错。"""
        report = SubdomainReport(root="only.example.com", elapsed=0.1)
        report.assets = [DiscoveredAsset(value="a.only.example.com", source="s")]
        persist_report(report, cfg)

        diff = diff_tasks(cfg, "only.example.com")
        assert diff == {"added": [], "removed": [], "unchanged": []}


# ---------------------------------------------------------------- HTTP 指纹


class TestProbeHttp:
    def test_ok_response_matches_rules_and_favicon(self):
        client = FakeClient(
            {
                "http://h:80/": Response(url="http://h:80/", status=200, content=b"<title>x</title>"),
                "http://h:80/favicon.ico": Response(url="x", status=200, content=b"a" * 32),
            }
        )
        components, favicon, note = asyncio.run(
            probe_http("h", 80, client, rules=[StubRule()])
        )
        assert note.startswith("HTTP 200")
        assert favicon is not None
        assert [c.name for c in components] == ["demo"]

    def test_request_exception_is_reported_not_raised(self):
        class Boom:
            async def get(self, url, **_):
                raise RuntimeError("connection reset")

        components, favicon, note = asyncio.run(probe_http("h", 80, Boom(), rules=[]))
        assert components == [] and favicon is None
        assert "请求失败" in note

    def test_transport_error_response(self):
        client = FakeClient({"http://h:80/": Response(url="x", status=0, error="timeout")})
        components, favicon, note = asyncio.run(probe_http("h", 80, client, rules=[], with_favicon=False))
        assert components == []
        assert "timeout" in note

    def test_favicon_too_small_is_ignored(self):
        """小于 16 字节的 favicon 没有区分度，不能拿来当指纹。"""
        client = FakeClient(
            {
                "http://h:80/": Response(url="x", status=200, content=b"ok"),
                "http://h:80/favicon.ico": Response(url="x", status=200, content=b"tiny"),
            }
        )
        _, favicon, note = asyncio.run(probe_http("h", 80, client, rules=[]))
        assert favicon is None
        assert "过小" in note

    def test_favicon_404_is_not_fatal(self):
        client = FakeClient({"http://h:80/": Response(url="x", status=200, content=b"ok")})
        _, favicon, note = asyncio.run(probe_http("h", 80, client, rules=[]))
        assert favicon is None
        assert "HTTP 404" in note

    def test_favicon_exception_is_not_fatal(self):
        class Partial:
            async def get(self, url, **_):
                if url.endswith("favicon.ico"):
                    raise RuntimeError("boom")
                return Response(url=url, status=200, content=b"ok")

        _, favicon, note = asyncio.run(probe_http("h", 80, Partial(), rules=[]))
        assert favicon is None
        assert "favicon 请求失败" in note

    def test_https_port_uses_https(self):
        client = FakeClient({"https://h:443/": Response(url="x", status=200, content=b"ok")})
        asyncio.run(probe_http("h", 443, client, rules=[], with_favicon=False))
        assert client.calls[0].startswith("https://")


# ---------------------------------------------------------------- 主机编排


class TestScanAndFingerprint:
    def test_no_open_port_skips_fingerprint(self, cfg, monkeypatch):
        """没有开放端口时不该去加载规则、也不该建 HTTP 客户端。"""
        called: list[str] = []

        async def scan(host, ports, **kwargs):
            return [make_port(80, state="closed")]

        def load(*args, **kwargs):
            called.append("load_rules")
            return []

        monkeypatch.setattr(host_mod, "scan_host", scan)
        monkeypatch.setattr(host_mod, "load_rules", load)

        report = asyncio.run(scan_and_fingerprint("10.0.0.1", cfg, ports=[80]))
        assert report.ports and not report.open_ports
        assert called == []

    def test_only_http_ports_are_probed(self, cfg, monkeypatch):
        probed: list[int] = []

        async def scan(host, ports, **kwargs):
            return [make_port(80), make_port(22, service="ssh"), make_port(8888, service="http")]

        async def fake_probe(host, port, client, **kwargs):
            probed.append(port)
            return [], None, "ok"

        monkeypatch.setattr(host_mod, "scan_host", scan)
        monkeypatch.setattr(host_mod, "load_rules", lambda dirs: [])
        monkeypatch.setattr(host_mod, "AsyncHttpClient", FakeClientCtx)
        monkeypatch.setattr(host_mod, "probe_http", fake_probe)

        report = asyncio.run(scan_and_fingerprint("10.0.0.1", cfg, ports=[80, 22, 8888]))
        assert probed == [80, 8888]
        assert sorted(report.open_ports) == [22, 80, 8888]

    def test_probe_exception_goes_to_errors(self, cfg, monkeypatch):
        """单个端口探测炸掉不能拖垮整台主机的结果。"""

        async def scan(host, ports, **kwargs):
            return [make_port(80), make_port(81)]

        async def fake_probe(host, port, client, **kwargs):
            if port == 81:
                raise RuntimeError("boom")
            return [make_component("nginx")], 12345, "HTTP 200"

        monkeypatch.setattr(host_mod, "scan_host", scan)
        monkeypatch.setattr(host_mod, "load_rules", lambda dirs: [])
        monkeypatch.setattr(host_mod, "AsyncHttpClient", FakeClientCtx)
        monkeypatch.setattr(host_mod, "probe_http", fake_probe)

        report = asyncio.run(scan_and_fingerprint("10.0.0.1", cfg, ports=[80, 81]))
        assert report.favicons == {80: 12345}
        assert len(report.errors) == 1 and "81" in report.errors[0]
        assert [c.name for c in report.all_components] == ["nginx"]


# ---------------------------------------------------------------- 主机持久化


class TestHostPersistence:
    def test_persist_writes_port_service_component(self, cfg):
        report = HostReport(host="10.0.0.1", elapsed=2.0)
        report.ports = [make_port(80, banner="<title>后台登录</title>"), make_port(22, service="ssh", state="closed")]
        report.components = {80: [make_component("nginx"), make_component("php")]}
        report.favicons = {80: 999}

        count = persist_host_report(report, cfg)
        assert count == 2

        engine = create_db_engine(cfg.database)
        with session_scope(engine) as session:
            task = session.execute(select(ScanTask)).scalars().one()
            asset = session.execute(select(Asset)).scalars().one()
            ports = session.execute(select(Port)).scalars().all()
            services = session.execute(select(Service)).scalars().all()
            components = session.execute(select(Component)).scalars().all()

            assert task.get_stats()["open_ports"] == [80]
            assert asset.alive is True
            assert [p.number for p in ports] == [80]
            assert services[0].name == "http"
            assert services[0].http_title == "后台登录"
            assert services[0].favicon_hash == "999"
            assert sorted(c.name for c in components) == ["nginx", "php"]

    def test_persist_host_without_open_ports_marks_dead(self, cfg):
        report = HostReport(host="10.0.0.2", elapsed=0.1)
        report.ports = [make_port(80, state="closed")]
        assert persist_host_report(report, cfg) == 0

        engine = create_db_engine(cfg.database)
        with session_scope(engine) as session:
            asset = session.execute(select(Asset)).scalars().one()
            assert asset.alive is False
