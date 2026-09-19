"""服务层与解析层的测试。

这三个模块（`services/host`、`services/subdomain`、`discover/crtsh`）
之前是 **0% 覆盖率** —— 因为它们「看起来」需要网络和数据库。

实际上里面的**聚合与解析逻辑是纯函数**，完全可测。
而恰恰是这一层最容易出 bug：项目里发现的两个真实缺陷
（报告的跨任务聚合、target 归一化）都出在这一层。

这份测试就是为了补上这个盲区。
"""

from __future__ import annotations

import pytest

from asp.config import Config
from asp.core.http import Response
from asp.discover.base import DiscoveredAsset
from asp.discover.crtsh import CrtshSource
from asp.discover.fingerprint import (
    CATEGORY_MIDDLEWARE,
    ComponentResult,
)
from asp.discover.portscan import PortResult, ServiceInfo
from asp.services.host import HostReport, _extract_title, _scheme_for
from asp.services.subdomain import SubdomainReport


def make_component(name: str, confidence: float, evidence: str = "e") -> ComponentResult:
    return ComponentResult(
        name=name,
        version="1.0",
        category=CATEGORY_MIDDLEWARE,
        confidence=confidence,
        evidence=[evidence],
    )


def make_port(port: int, service: str = "http", state: str = "open") -> PortResult:
    return PortResult(
        host="127.0.0.1",
        port=port,
        state=state,
        service=ServiceInfo(name=service),
    )


# ══════════════════════════════════════════════════════ HostReport


class TestHostReport:
    def test_open_ports_filters_closed(self):
        report = HostReport(host="127.0.0.1")
        report.ports = [
            make_port(80, state="open"),
            make_port(81, state="closed"),
            make_port(443, state="open"),
            make_port(8080, state="filtered"),
        ]
        assert report.open_ports == [80, 443]

    def test_open_ports_empty(self):
        assert HostReport(host="x").open_ports == []

    def test_by_service_counts_only_open(self):
        report = HostReport(host="127.0.0.1")
        report.ports = [
            make_port(80, "http", state="open"),
            make_port(8080, "http", state="open"),
            make_port(3306, "mysql", state="open"),
            make_port(81, "http", state="closed"),   # 不计入
        ]
        assert report.by_service() == {"http": 2, "mysql": 1}

    def test_by_service_uses_unknown_for_unnamed(self):
        report = HostReport(host="x")
        report.ports = [make_port(135, service="")]
        assert report.by_service() == {"unknown": 1}

    # ── 回归测试：all_components 必须幂等且无副作用 ──────────────

    def test_all_components_is_idempotent(self):
        """★ 回归测试：反复读取不该累积置信度。

        真实 bug：`all_components` 是 property，但最初实现里
        `existing.confidence += item.confidence` 直接改了原始对象 ——
        于是每读一次置信度就涨一次：

            第 1 次 0.60 → 第 2 次 0.90 → 第 3 次 1.00

        后果是同一份报告被多次读取（生成日志 + 写数据库）会得到不同数值。
        **property 应该无副作用**。
        """
        report = HostReport(host="127.0.0.1")
        report.components = {
            8080: [make_component("Nginx", 0.3, "a")],
            443: [make_component("Nginx", 0.3, "b")],
        }

        readings = [
            [c for c in report.all_components if c.name == "Nginx"][0].confidence
            for _ in range(5)
        ]

        assert len(set(readings)) == 1, f"非幂等：连续读取得到不同值 {readings}"
        assert readings[0] == pytest.approx(0.6), "两个 0.3 应该累加成 0.6"

    def test_all_components_does_not_mutate_source(self):
        """★ 回归测试：聚合过程不能污染原始的 ComponentResult 对象。"""
        original = make_component("Nginx", 0.3, "a")
        report = HostReport(host="127.0.0.1")
        report.components = {8080: [original], 443: [make_component("Nginx", 0.3, "b")]}

        # 反复读取（结果丢弃 —— 这条测试关注的是「有没有副作用」，
        # 而不是读到了什么）
        _ = report.all_components
        _ = report.all_components

        assert original.confidence == pytest.approx(0.3), "原始对象被修改了"
        assert original.evidence == ["a"], "原始对象的 evidence 被追加了"

    def test_all_components_merges_by_name(self):
        report = HostReport(host="x")
        report.components = {
            80: [make_component("Nginx", 0.4, "header:nginx")],
            443: [make_component("Nginx", 0.4, "body:nginx")],
        }
        merged = report.all_components
        assert len(merged) == 1
        assert merged[0].confidence == pytest.approx(0.8)
        assert set(merged[0].evidence) == {"header:nginx", "body:nginx"}

    def test_all_components_confidence_capped_at_one(self):
        report = HostReport(host="x")
        report.components = {
            80: [make_component("Nginx", 0.9, "e1")],
            443: [make_component("Nginx", 0.9, "e2")],
        }
        assert report.all_components[0].confidence == 1.0

    def test_all_components_sorted_by_confidence_desc(self):
        report = HostReport(host="x")
        report.components = {
            80: [make_component("Weak", 0.3, "e")],
            443: [make_component("Strong", 0.9, "e")],
        }
        names = [c.name for c in report.all_components]
        assert names == ["Strong", "Weak"]

    def test_all_components_dedupes_identical_evidence(self):
        report = HostReport(host="x")
        report.components = {
            80: [make_component("Nginx", 0.4, "header:nginx")],
            443: [make_component("Nginx", 0.4, "header:nginx")],
        }
        assert report.all_components[0].evidence == ["header:nginx"]

    def test_all_components_empty(self):
        assert HostReport(host="x").all_components == []


# ══════════════════════════════════════════════════════ 辅助函数


class TestHostHelpers:
    @pytest.mark.parametrize(
        "port, expected",
        [(443, "https"), (8443, "https"), (80, "http"), (8080, "http"), (3306, "http")],
    )
    def test_scheme_for(self, port, expected):
        assert _scheme_for(port) == expected

    def test_extract_title_normal(self):
        html = "<html><head><title>VulnLab 靶场</title></head></html>"
        assert _extract_title(html) == "VulnLab 靶场"

    def test_extract_title_collapses_whitespace(self):
        html = "<title>\n    Hello   World\n  </title>"
        assert _extract_title(html) == "Hello World"

    def test_extract_title_case_insensitive(self):
        assert _extract_title("<TITLE>UPPER</TITLE>") == "UPPER"

    def test_extract_title_missing(self):
        assert _extract_title("<html>no title</html>") == ""

    def test_extract_title_empty_banner(self):
        assert _extract_title("") == ""


# ══════════════════════════════════════════════════════ SubdomainReport


def asset(value: str, sources: str, source: str = "crtsh") -> DiscoveredAsset:
    return DiscoveredAsset(value=value, source=source, metadata={"sources": sources})


class TestSubdomainReport:
    def test_count(self):
        report = SubdomainReport(root="example.com")
        assert report.count == 0
        report.assets = [asset("a.example.com", "crtsh")]
        assert report.count == 1

    def test_by_source_counts_each_source(self):
        report = SubdomainReport(root="example.com")
        report.assets = [
            asset("a.example.com", "crtsh"),
            asset("b.example.com", "crtsh,brute"),
            asset("c.example.com", "brute"),
        ]
        assert report.by_source() == {"crtsh": 2, "brute": 2}

    def test_multi_source_only_returns_confirmed_by_multiple(self):
        report = SubdomainReport(root="example.com")
        report.assets = [
            asset("a.example.com", "crtsh"),
            asset("b.example.com", "crtsh,brute"),
            asset("c.example.com", "brute"),
        ]
        multi = report.multi_source()
        assert len(multi) == 1
        assert multi[0].value == "b.example.com"

    def test_multi_source_empty_when_single_source(self):
        report = SubdomainReport(root="example.com")
        report.assets = [asset("a.example.com", "crtsh")]
        assert report.multi_source() == []

    def test_multi_source_handles_missing_metadata(self):
        """没有 sources 元数据时不该抛异常。"""
        report = SubdomainReport(root="example.com")
        report.assets = [DiscoveredAsset(value="a.example.com", source="crtsh")]
        assert report.multi_source() == []


# ══════════════════════════════════════════════════════ crt.sh 解析


@pytest.fixture
def crtsh() -> CrtshSource:
    return CrtshSource(Config())


class TestCrtshParseRecords:
    def test_parses_name_value(self, crtsh: CrtshSource):
        records = [{"name_value": "a.example.com", "common_name": "a.example.com"}]
        assets = crtsh._parse_records(records, "example.com")
        assert [a.value for a in assets] == ["a.example.com"]

    def test_parses_multiline_name_value(self, crtsh: CrtshSource):
        """name_value 是换行分隔的多值字段 —— 不拆分会漏掉大量子域名。"""
        records = [{"name_value": "a.example.com\nb.example.com\nc.example.com"}]
        assets = crtsh._parse_records(records, "example.com")
        assert {a.value for a in assets} == {"a.example.com", "b.example.com", "c.example.com"}

    def test_parses_common_name_too(self, crtsh: CrtshSource):
        """common_name 是另一个字段，也要看 —— 只看 name_value 会漏。"""
        records = [{"name_value": "a.example.com", "common_name": "cn.example.com"}]
        assets = crtsh._parse_records(records, "example.com")
        assert {a.value for a in assets} == {"a.example.com", "cn.example.com"}

    def test_strips_wildcard_prefix(self, crtsh: CrtshSource):
        records = [{"name_value": "*.example.com"}]
        assets = crtsh._parse_records(records, "example.com")
        assert [a.value for a in assets] == ["example.com"]

    def test_filters_unrelated_domains(self, crtsh: CrtshSource):
        """只保留目标域名的子域 —— CT 日志里会混入同一证书的无关域名。"""
        records = [{"name_value": "a.example.com\nevil.com\nother.org"}]
        assets = crtsh._parse_records(records, "example.com")
        assert [a.value for a in assets] == ["a.example.com"]

    def test_deduplicates_within_records(self, crtsh: CrtshSource):
        records = [
            {"name_value": "a.example.com"},
            {"name_value": "a.example.com", "common_name": "a.example.com"},
        ]
        assets = crtsh._parse_records(records, "example.com")
        assert len(assets) == 1

    def test_skips_non_dict_records(self, crtsh: CrtshSource):
        """CT 接口偶尔返回非字典元素，不该让解析崩掉。"""
        records = ["garbage", None, 123, {"name_value": "a.example.com"}]
        assets = crtsh._parse_records(records, "example.com")
        assert [a.value for a in assets] == ["a.example.com"]

    def test_skips_missing_fields(self, crtsh: CrtshSource):
        records = [{"issuer_name": "Let's Encrypt"}, {"name_value": "a.example.com"}]
        assert [a.value for a in crtsh._parse_records(records, "example.com")] == [
            "a.example.com"
        ]

    def test_keeps_certificate_metadata(self, crtsh: CrtshSource):
        """证书信息要保留 —— 报告里能看出「这个域名什么时候被签过证书」。"""
        records = [
            {
                "name_value": "a.example.com",
                "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                "not_before": "2026-01-01T00:00:00",
            }
        ]
        assets = crtsh._parse_records(records, "example.com")
        assert "Let's Encrypt" in assets[0].metadata["issuer"]
        assert assets[0].metadata["not_before"].startswith("2026-01-01")

    def test_rejects_invalid_domain_format(self, crtsh: CrtshSource):
        records = [{"name_value": "not a domain\na.example.com"}]
        assets = crtsh._parse_records(records, "example.com")
        assert [a.value for a in assets] == ["a.example.com"]

    def test_normalizes_case_and_trailing_dot(self, crtsh: CrtshSource):
        records = [{"name_value": "A.Example.COM."}]
        assets = crtsh._parse_records(records, "example.com")
        assert [a.value for a in assets] == ["a.example.com"]

    def test_handles_name_value_as_list(self, crtsh: CrtshSource):
        """某些版本的 CT 接口把 name_value 返回成列表 —— 应被安全忽略而不是崩溃。"""
        records = [{"name_value": ["a.example.com", "b.example.com"]}]
        # 列表不是 str，实现会跳过它 —— 不崩就是合格
        assert crtsh._parse_records(records, "example.com") == []

    def test_empty_records(self, crtsh: CrtshSource):
        assert crtsh._parse_records([], "example.com") == []


# ══════════════════════════════════════════════════════ Response 便捷方法


class TestResponseHelpers:
    """HTTP Response 的几个便捷属性 —— 之前 44% 覆盖率，不少分支没测到。"""

    def test_ok_means_no_transport_error_not_2xx(self):
        """`ok` 表示「请求成功完成」（网络层面），**与 HTTP 状态码无关**。

        这是刻意的设计，不是疏漏：扫描场景里 404 / 500 都是**有效响应** ——
        它们恰恰说明「服务在那儿，只是这个路径不对」。
        真正需要区分的是「拿到了响应」和「压根没连上」。

        如果把 ok 实现成 `200 <= status < 300`，那所有 404 探测都会
        被当成「请求失败」，路径枚举就没法做了。

        （我最初写这条测试时按 2xx 的直觉来断言，结果挂了 ——
        这反而说明这条语义值得写清楚。）
        """
        # 有响应就是 ok，哪怕状态码是错误码
        assert Response(url="u", status=404, headers={}, content=b"").ok
        assert Response(url="u", status=500, headers={}, content=b"").ok
        assert Response(url="u", status=302, headers={}, content=b"").ok
        assert Response(url="u", status=200, headers={}, content=b"").ok

        # 网络层失败才是 not ok
        assert not Response(
            url="u", status=0, headers={}, content=b"", error="连接超时"
        ).ok

    def test_text_decodes_utf8(self):
        resp = Response(url="u", status=200, headers={}, content="中文".encode())
        assert resp.text == "中文"

    def test_text_ignores_invalid_bytes(self):
        """非法字节不该让解码抛异常 —— 扫描场景里经常遇到非 UTF-8 响应。"""
        resp = Response(url="u", status=200, headers={}, content=b"\xff\xfe valid")
        assert isinstance(resp.text, str)

    def test_header_is_case_insensitive(self):
        resp = Response(
            url="u", status=200, headers={"Content-Type": "application/json"}, content=b""
        )
        assert resp.header("content-type") == "application/json"
        assert resp.header("CONTENT-TYPE") == "application/json"

    def test_header_default_when_missing(self):
        resp = Response(url="u", status=200, headers={}, content=b"")
        assert resp.header("X-Missing") == ""
        assert resp.header("X-Missing", "fallback") == "fallback"
