"""CLI 命令层的测试（离线）。

单元测试通过不代表命令能跑 —— 参数到函数的接线、退出码、输出格式都在 cli.py 里，
而这一层原来的覆盖率只有 49%。历史上最坑的一个 bug 就在这层：
`poc run --json` 忘了 print，终端一片空白，管道下游拿到空字符串。

这里用真实的 `build_parser()` 解析参数，只把服务层函数替换掉，
所以连「参数名写错」「退出码约定」也能一并测到。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import asp.cli as cli
from asp.config import Config
from asp.discover.base import DiscoveredAsset
from asp.discover.fingerprint import CATEGORY_MIDDLEWARE, ComponentResult
from asp.discover.portscan import PortResult, ServiceInfo
from asp.services.host import HostReport
from asp.services.subdomain import SubdomainReport


def parse(argv: list[str]):
    return cli.build_parser().parse_args(argv)


@pytest.fixture
def cfg(tmp_path) -> Config:
    config = Config()
    config.database = str(tmp_path / "cli.db")
    return config


def make_report() -> SubdomainReport:
    report = SubdomainReport(root="example.com", sources_used=["crtsh", "brute"], elapsed=1.5)
    report.wildcard_ips = {"9.9.9.9"}
    first = DiscoveredAsset(value="www.example.com", source="crtsh", resolved_ip="1.1.1.1")
    first.metadata["sources"] = "crtsh,brute"
    second = DiscoveredAsset(value="api.example.com", source="crtsh", resolved_ip="1.1.1.2")
    second.metadata["sources"] = "crtsh"
    report.assets = [first, second]
    return report


def make_host_report(open_ports: bool = True) -> HostReport:
    report = HostReport(host="10.0.0.1", elapsed=1.2)
    report.components = {}
    if open_ports:
        report.ports = [
            PortResult(
                host="10.0.0.1",
                port=80,
                state="open",
                service=ServiceInfo(name="http", product="nginx", version="1.24"),
                banner="HTTP/1.1 200 OK\nServer: nginx",
            )
        ]
        report.components = {
            80: [
                ComponentResult(
                    name="nginx",
                    version="1.24",
                    category=CATEGORY_MIDDLEWARE,
                    confidence=0.9,
                    evidence=["Server 头"],
                )
            ]
        }
        report.favicons = {80: 123456}
    else:
        report.ports = [
            PortResult(host="10.0.0.1", port=80, state="closed", service=ServiceInfo(name=""))
        ]
    return report


# ---------------------------------------------------------------- subdomain


class TestSubdomainCommand:
    def test_json_output_contains_assets_and_wildcard(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "collect_subdomains", _async_return(make_report()))

        code = cli.cmd_subdomain(parse(["subdomain", "example.com", "--json"]), cfg)

        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["count"] == 2
        assert payload["wildcard_ips"] == ["9.9.9.9"]
        assert payload["by_source"] == {"crtsh": 2, "brute": 1}
        assert payload["assets"][0]["value"] == "www.example.com"

    def test_table_output_marks_multi_source(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "collect_subdomains", _async_return(make_report()))

        assert cli.cmd_subdomain(parse(["subdomain", "example.com"]), cfg) == 0
        out = capsys.readouterr().out
        assert "泛解析基线" in out
        assert "多源交叉确认: 1 条" in out
        assert "www.example.com" in out

    def test_empty_result_prints_hint_not_table(self, cfg, monkeypatch, capsys):
        empty = SubdomainReport(root="example.com")
        monkeypatch.setattr(cli, "collect_subdomains", _async_return(empty))

        assert cli.cmd_subdomain(parse(["subdomain", "example.com"]), cfg) == 0
        assert "(未发现存活子域名)" in capsys.readouterr().out

    def test_save_and_output_file(self, cfg, monkeypatch, tmp_path):
        monkeypatch.setattr(cli, "collect_subdomains", _async_return(make_report()))
        saved: list[str] = []
        monkeypatch.setattr(cli, "persist_report", lambda report, config: saved.append(report.root) or 2)

        out = tmp_path / "sub.txt"
        code = cli.cmd_subdomain(
            parse(["subdomain", "example.com", "--save", "-o", str(out)]), cfg
        )

        assert code == 0
        assert saved == ["example.com"]
        assert out.read_text(encoding="utf-8").splitlines() == [
            "www.example.com",
            "api.example.com",
        ]


# ---------------------------------------------------------------- diff


class TestDiffCommand:
    def test_json_and_table(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "diff_tasks",
            lambda config, domain, limit=2: {
                "added": ["new.example.com"],
                "removed": ["old.example.com"],
                "unchanged": ["keep.example.com"],
            },
        )

        assert cli.cmd_diff(parse(["diff", "example.com", "--json"]), cfg) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["added"] == ["new.example.com"]

        assert cli.cmd_diff(parse(["diff", "example.com"]), cfg) == 0
        out = capsys.readouterr().out
        assert "+ new.example.com" in out
        assert "- old.example.com" in out
        assert "未变: 1" in out


# ---------------------------------------------------------------- portscan


class TestPortscanCommand:
    def test_json_output(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "scan_and_fingerprint", _async_return(make_host_report()))

        assert cli.cmd_portscan(parse(["portscan", "10.0.0.1", "--json"]), cfg) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["open_ports"] == [80]
        assert payload["components"][0]["name"] == "nginx"
        assert payload["favicons"] == {"80": 123456}

    def test_table_output(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "scan_and_fingerprint", _async_return(make_host_report()))

        assert cli.cmd_portscan(parse(["portscan", "10.0.0.1"]), cfg) == 0
        out = capsys.readouterr().out
        assert "识别到的组件" in out
        assert "favicon 哈希" in out
        assert "nginx" in out

    def test_no_open_port(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(
            cli, "scan_and_fingerprint", _async_return(make_host_report(open_ports=False))
        )

        assert cli.cmd_portscan(parse(["portscan", "10.0.0.1"]), cfg) == 0
        assert "(无开放端口)" in capsys.readouterr().out

    def test_save_writes_db(self, cfg, monkeypatch):
        monkeypatch.setattr(cli, "scan_and_fingerprint", _async_return(make_host_report()))
        called: list[str] = []
        monkeypatch.setattr(cli, "persist_host_report", lambda report, config: called.append(report.host) or 1)

        assert cli.cmd_portscan(parse(["portscan", "10.0.0.1", "--save"]), cfg) == 0
        assert called == ["10.0.0.1"]


# ---------------------------------------------------------------- report


class TestReportCommand:
    def test_missing_data_returns_1(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "load_target_report", lambda config, target: {"has_data": False})

        assert cli.cmd_report(parse(["report", "example.com"]), cfg) == 1
        assert "没有任何扫描记录" in capsys.readouterr().out

    def test_bad_format_returns_2(self, cfg, monkeypatch, capsys):
        """argparse 会先拦掉非法格式，这里直接构造参数，测命令层的防御分支。"""
        monkeypatch.setattr(
            cli,
            "load_target_report",
            lambda config, target: {"has_data": True, "stats": {}},
        )

        def boom(data, fmt):
            raise ValueError("不支持的格式: xml")

        monkeypatch.setattr(cli, "render_report", boom)
        args = SimpleNamespace(target="example.com", format="xml", output=None)

        assert cli.cmd_report(args, cfg) == 2
        assert "不支持的格式" in capsys.readouterr().err

    def test_writes_file(self, cfg, monkeypatch, tmp_path):
        monkeypatch.setattr(
            cli,
            "load_target_report",
            lambda config, target: {"has_data": True, "stats": {"asset_count": 1}},
        )
        monkeypatch.setattr(cli, "render_report", lambda data, fmt: "# 报告")

        out = tmp_path / "r.md"
        code = cli.cmd_report(parse(["report", "example.com", "-f", "md", "-o", str(out)]), cfg)

        assert code == 0
        assert out.read_text(encoding="utf-8") == "# 报告"


# ---------------------------------------------------------------- triage


class TestTriageCommand:
    def test_self_test_json_uses_heuristic(self, cfg, capsys):
        """无 key 时必须走启发式降级，且 JSON 里有准确率字段。"""
        code = cli.cmd_triage(
            parse(["triage", "--self-test", "--provider", "heuristic", "--json"]), cfg
        )

        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["provider"] == "heuristic"
        assert "accuracy" in payload and payload["total"] >= 6

    def test_self_test_text_and_hint(self, cfg, capsys):
        code = cli.cmd_triage(parse(["triage", "--self-test", "--provider", "heuristic"]), cfg)
        out = capsys.readouterr().out

        assert code == 0
        assert "研判效果评估" in out
        assert "启发式降级模式" in out

    def test_no_target_returns_2(self, cfg, capsys):
        assert cli.cmd_triage(parse(["triage"]), cfg) == 2
        assert "请指定目标" in capsys.readouterr().err

    def test_no_vulns_returns_1(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "_load_findings", lambda config, target: [])

        assert cli.cmd_triage(parse(["triage", "example.com", "--provider", "heuristic"]), cfg) == 1
        assert "没有漏洞记录" in capsys.readouterr().out

    def test_judges_findings_in_json(self, cfg, monkeypatch, capsys):
        vuln = SimpleNamespace(
            poc_id="poc-demo",
            name="演示漏洞",
            severity="high",
            target="http://example.com/x",
            evidence="HTTP 200 查询结果",
            confidence=0.9,
            verified=True,
        )
        monkeypatch.setattr(cli, "_load_findings", lambda config, target: [vuln])

        code = cli.cmd_triage(
            parse(["triage", "example.com", "--provider", "heuristic", "--json"]), cfg
        )

        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["total"] == 1
        assert payload["items"][0]["poc_id"] == "poc-demo"
        assert "verdict" in payload["items"][0]

    def test_truncates_to_max_findings(self, cfg, monkeypatch, capsys, caplog):
        cfg.llm.max_findings = 1
        vulns = [
            SimpleNamespace(poc_id=f"p{i}", name="n", severity="low", target="http://x", evidence="")
            for i in range(3)
        ]
        monkeypatch.setattr(cli, "_load_findings", lambda config, target: vulns)

        assert cli.cmd_triage(parse(["triage", "example.com", "--provider", "heuristic"]), cfg) == 0
        assert "研判前        1 条" in capsys.readouterr().out


# ---------------------------------------------------------------- main 分发


class TestMainDispatch:
    def test_config_error_returns_2(self, tmp_path, capsys):
        bad = tmp_path / "bad.yaml"
        bad.write_text("http: [unclosed\n", encoding="utf-8")

        assert cli.main(["-c", str(bad), "poc", "list"]) == 2
        assert "配置错误" in capsys.readouterr().err

    def test_asp_error_returns_2(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "load_config", lambda path: cfg)
        monkeypatch.setattr(cli, "setup_logging", lambda *a, **k: None)

        def boom(args, config):
            raise cli.AspError("炸了")

        monkeypatch.setattr(cli, "cmd_poc_list", boom)
        assert cli.main(["poc", "list"]) == 2

    def test_keyboard_interrupt_returns_130(self, cfg, monkeypatch, capsys):
        monkeypatch.setattr(cli, "load_config", lambda path: cfg)
        monkeypatch.setattr(cli, "setup_logging", lambda *a, **k: None)

        def interrupt(args, config):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "cmd_poc_list", interrupt)
        assert cli.main(["poc", "list"]) == 130
        assert "已中断" in capsys.readouterr().err


def _async_return(value):
    async def _inner(*args, **kwargs):
        return value

    return _inner
