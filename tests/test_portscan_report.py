"""端口扫描与报告渲染的测试（离线）。

这两块原来覆盖率 59% / 67%，缺口都在「真跑一遍」的路径上：
端口扫描要真连 socket，报告要把数据库里的关系拼起来。

端口部分用假 StreamReader/Writer 替换 `asyncio.open_connection`；
报告部分直接构造 SQLite 数据 —— 不 mock ORM，测的是真实的关联与去重逻辑。
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

import asp.discover.portscan as portscan_mod
from asp.config import Config
from asp.core.database import (
    Asset,
    Component,
    Port,
    ScanTask,
    Service,
    Vuln,
    create_db_engine,
    init_db,
    session_scope,
)
from asp.discover.portscan import _probe_http, _read_banner, scan_host, scan_port
from asp.report import load_target_report, render, to_html, to_json, to_markdown

# ---------------------------------------------------------------- 假流


class FakeReader:
    def __init__(self, data: bytes = b"", exc: Exception | None = None) -> None:
        self.data = data
        self.exc = exc

    async def read(self, n: int) -> bytes:
        if self.exc:
            raise self.exc
        return self.data


class FakeWriter:
    def __init__(self, *, fail_write: bool = False, fail_drain: bool = False, fail_close: bool = False) -> None:
        self.written = b""
        self.fail_write = fail_write
        self.fail_drain = fail_drain
        self.fail_close = fail_close

    def write(self, data: bytes) -> None:
        if self.fail_write:
            raise ConnectionError("broken pipe")
        self.written += data

    async def drain(self) -> None:
        if self.fail_drain:
            raise OSError("drain failed")

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        if self.fail_close:
            raise TimeoutError


def patch_connect(monkeypatch, behaviour):
    async def fake_connect(host, port):
        result = behaviour(port)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(portscan_mod.asyncio, "open_connection", fake_connect)


# ---------------------------------------------------------------- 单端口


class TestScanPort:
    def test_timeout_is_filtered_not_closed(self, monkeypatch):
        """超时代表被防火墙丢包，和明确关闭是两回事，不能混为一谈。"""
        patch_connect(monkeypatch, lambda port: TimeoutError())

        result = asyncio.run(scan_port("10.0.0.1", 80))
        assert result.state == "filtered"
        assert "超时" in result.error

    def test_connection_refused_is_closed(self, monkeypatch):
        patch_connect(monkeypatch, lambda port: ConnectionRefusedError())

        result = asyncio.run(scan_port("10.0.0.1", 80))
        assert result.state == "closed"

    def test_dns_error_is_error_state(self, monkeypatch):
        import socket

        patch_connect(monkeypatch, lambda port: socket.gaierror("no such host"))

        result = asyncio.run(scan_port("nope.invalid", 80))
        assert result.state == "error"
        assert "域名解析失败" in result.error

    def test_windows_wrapped_refusal_is_closed(self, monkeypatch):
        """Windows 上连接被拒常被包成 OSError(winerror=10061)。"""

        class WinError(OSError):
            winerror = 10061

        patch_connect(monkeypatch, lambda port: WinError())
        assert asyncio.run(scan_port("10.0.0.1", 80)).state == "closed"

    def test_other_oserror_is_error(self, monkeypatch):
        patch_connect(monkeypatch, lambda port: OSError("too many open files"))

        result = asyncio.run(scan_port("10.0.0.1", 80))
        assert result.state == "error"
        assert "too many" in result.error

    def test_open_port_reads_banner_and_fingerprints(self, monkeypatch):
        reader = FakeReader(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        writer = FakeWriter()
        patch_connect(monkeypatch, lambda port: (reader, writer))

        result = asyncio.run(scan_port("10.0.0.1", 22))

        assert result.is_open
        assert result.service.name == "ssh"
        assert "OpenSSH" in result.service.product
        assert "8.9" in result.service.version

    def test_open_port_without_banner_on_http_port_sends_request(self, monkeypatch):
        """HTTP 服务不会主动发 banner，必须由客户端先发请求。"""
        reader = FakeReader(b"")
        writer = FakeWriter()
        patch_connect(monkeypatch, lambda port: (reader, writer))

        # 第一次静默读返回空，_probe_http 会写请求再读一次；用同一个 reader 模拟空响应
        result = asyncio.run(scan_port("10.0.0.1", 80))

        assert result.is_open
        assert b"GET / HTTP/1.0" in writer.written
        assert b"Host: 10.0.0.1" in writer.written

    def test_grab_banner_false_skips_probe(self, monkeypatch):
        reader = FakeReader(b"SSH-2.0-x\r\n")
        writer = FakeWriter()
        patch_connect(monkeypatch, lambda port: (reader, writer))

        result = asyncio.run(scan_port("10.0.0.1", 22, grab_banner=False))
        assert result.banner == ""
        assert writer.written == b""

    def test_writer_close_failure_is_swallowed(self, monkeypatch):
        patch_connect(monkeypatch, lambda port: (FakeReader(b"x"), FakeWriter(fail_close=True)))

        result = asyncio.run(scan_port("10.0.0.1", 22))
        assert result.is_open


class TestBannerHelpers:
    def test_read_banner_timeout_returns_empty(self):
        reader = FakeReader(exc=TimeoutError())
        assert asyncio.run(_read_banner(reader, 0.01)) == ""

    def test_read_banner_decodes_with_errors_ignored(self):
        reader = FakeReader(b"ok\xff\xfe")
        assert asyncio.run(_read_banner(reader, 1)) == "ok"

    def test_probe_http_write_failure_returns_empty(self):
        result = asyncio.run(
            _probe_http(FakeWriter(fail_write=True), FakeReader(b"x"), "h", 80)
        )
        assert result == ""

    def test_probe_http_drain_failure_returns_empty(self):
        result = asyncio.run(
            _probe_http(FakeWriter(fail_drain=True), FakeReader(b"x"), "h", 80)
        )
        assert result == ""


# ---------------------------------------------------------------- 整机


class TestScanHost:
    def test_filters_closed_and_sorts(self, monkeypatch):
        async def fake_scan_port(host, port, **kwargs):
            from asp.discover.portscan import PortResult

            state = {80: "open", 22: "closed", 3306: "open", 8080: "error"}[port]
            return PortResult(host=host, port=port, state=state)

        monkeypatch.setattr(portscan_mod, "scan_port", fake_scan_port)

        results = asyncio.run(scan_host("10.0.0.1", [80, 22, 3306, 8080]))
        assert [r.port for r in results] == [80, 3306, 8080]

    def test_empty_port_list_returns_early(self):
        assert asyncio.run(scan_host("10.0.0.1", [])) == []

    def test_progress_is_logged(self, monkeypatch, caplog):
        """进度日志每 N 个端口一条 —— 大范围扫描时靠它判断卡在哪。"""
        from asp.discover.portscan import PortResult

        async def fake_scan_port(host, port, **kwargs):
            return PortResult(host=host, port=port, state="open")

        monkeypatch.setattr(portscan_mod, "scan_port", fake_scan_port)

        with caplog.at_level("INFO"):
            asyncio.run(scan_host("10.0.0.1", [80, 81], progress_every=1))
        assert any("portscan_progress" in r.message or "portscan_progress" in r.msg for r in caplog.records)


# ---------------------------------------------------------------- 报告


@pytest.fixture
def cfg(tmp_path) -> Config:
    config = Config()
    config.database = str(tmp_path / "report.db")
    return config


def seed_database(cfg: Config) -> None:
    """造两次扫描：第一次有 old/www + 端口组件漏洞，第二次有 www/new。"""
    engine = create_db_engine(cfg.database)
    init_db(engine)

    with session_scope(engine) as session:
        start = datetime.now(UTC) - timedelta(seconds=5)
        first = ScanTask(target="example.com", status="success", started_at=start, finished_at=start + timedelta(seconds=1.5))
        session.add(first)
        session.flush()

        old = Asset(task_id=first.id, type="domain", value="old.example.com", alive=True, root_domain="example.com")
        www1 = Asset(task_id=first.id, type="domain", value="www.example.com", alive=True, root_domain="example.com")
        session.add_all([old, www1])
        session.flush()

        port = Port(asset_id=www1.id, number=443, protocol="tcp", state="open", banner="HTTP/1.1 200 OK")
        session.add(port)
        session.flush()

        service = Service(port_id=port.id, name="http", product="nginx", version="1.24", http_title="官网")
        session.add(service)
        session.flush()

        component = Component(
            service_id=service.id, name="nginx", version="1.24", category="server", confidence=0.9, evidence="Server 头"
        )
        session.add(component)
        session.flush()

        # 挂在组件上的漏洞
        session.add(
            Vuln(
                task_id=first.id,
                component_id=component.id,
                poc_id="poc-a",
                name="组件漏洞",
                severity="high",
                target="https://www.example.com/x",
                evidence="证据 A",
                confidence=0.8,
            )
        )
        # 独立 PoC 扫描产生的漏洞：没有组件，只有 task
        session.add(
            Vuln(
                task_id=first.id,
                poc_id="poc-b",
                name="独立漏洞",
                severity="critical",
                target="https://www.example.com/y",
                evidence="证据 B",
            )
        )

        second = ScanTask(target="example.com", status="success", started_at=start, finished_at=start + timedelta(seconds=2))
        session.add(second)
        session.flush()
        www2 = Asset(task_id=second.id, type="domain", value="www.example.com", alive=True, root_domain="example.com")
        new = Asset(task_id=second.id, type="domain", value="new.example.com", alive=True, root_domain="example.com")
        session.add_all([www2, new])

        # 无关任务不能混进报告
        session.add(ScanTask(target="other.com", status="success"))
        session.commit()


class TestLoadTargetReport:
    def test_no_task(self, cfg):
        data = load_target_report(cfg, "nothing.com")
        assert data["has_data"] is False
        assert data["assets"] == []

    def test_aggregates_across_tasks_and_dedupes(self, cfg):
        seed_database(cfg)
        data = load_target_report(cfg, "example.com")

        assert data["has_data"] is True
        values = [a["value"] for a in data["assets"]]
        assert values == ["new.example.com", "old.example.com", "www.example.com"]
        assert data["stats"]["asset_count"] == 3

        # 端口挂在第一次任务的 asset 上，必须仍能查到（这是修过的 bug）
        assert data["stats"]["open_port_count"] == 1
        assert data["ports"][0]["service"] == "http"
        assert data["ports"][0]["title"] == "官网"
        assert data["stats"]["component_count"] == 1

        # 两条漏洞：一条挂组件、一条只有 task_id
        assert data["stats"]["vuln_count"] == 2
        assert data["stats"]["by_severity"] == {"critical": 1, "high": 1}
        assert data["stats"]["by_category"] == {"server": 1}

        # 相比上次扫描：old 消失，new 新增
        assert data["diff"]["added"] == ["new.example.com"]
        assert data["diff"]["removed"] == ["old.example.com"]


class TestRender:
    def test_json_roundtrip(self, cfg):
        seed_database(cfg)
        data = load_target_report(cfg, "example.com")

        import json

        assert json.loads(to_json(data))["stats"]["asset_count"] == 3

    def test_markdown_contains_sections(self, cfg):
        seed_database(cfg)
        md = to_markdown(load_target_report(cfg, "example.com"))

        assert "# 攻击面测绘报告 · example.com" in md
        assert "## 概览" in md
        assert "nginx" in md
        assert "相比上次扫描" in md

    def test_markdown_without_data(self, cfg):
        md = to_markdown(load_target_report(cfg, "empty.com"))
        assert "暂无扫描记录" in md

    def test_html_contains_stats(self, cfg):
        seed_database(cfg)
        html = to_html(load_target_report(cfg, "example.com"))
        assert "<!DOCTYPE html>" in html
        assert "example.com" in html

    def test_render_dispatch_and_unknown_format(self, cfg):
        data = load_target_report(cfg, "empty.com")
        assert render(data, "MD").startswith("#")
        assert render(data, "json").lstrip().startswith("{")
        with pytest.raises(ValueError, match="不支持的报告格式"):
            render(data, "xml")
