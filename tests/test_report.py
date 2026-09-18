"""报告生成测试。

覆盖重点：
- target 归一化（决定了不同扫描链路能否聚合到同一份报告）
- 三种格式的渲染
- **HTML 转义**（报告是把扫描数据渲染成 HTML，
  如果没转义，一个精心构造的资产名就能在报告里执行脚本 ——
  这是「安全工具自身被 XSS」的自指漏洞）
"""

from __future__ import annotations

import json

import pytest

from asp.report import (
    RENDERERS,
    load_target_report,
    render,
    to_html,
    to_json,
    to_markdown,
)
from asp.services.vuln import normalize_target

# ----------------------------------------------------- target 归一化


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("http://1.2.3.4:8080/path", "1.2.3.4"),
        ("https://example.com/", "example.com"),
        ("example.com", "example.com"),
        ("example.com:443", "example.com"),
        ("EXAMPLE.COM.", "example.com"),
        ("http://example.com/a/b?c=d", "example.com"),
        ("https://user:pass@example.com/x", "example.com"),
        ("[::1]:8080", "::1"),
        ("  127.0.0.1  ", "127.0.0.1"),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


def test_normalize_target_keeps_ipv6_intact():
    """IPv6 未加方括号时含多个冒号，不能被当成 host:port 切掉。"""
    assert normalize_target("::1") == "::1"
    assert normalize_target("fe80::1") == "fe80::1"


def test_normalize_target_aggregates_url_and_host():
    """这是它存在的意义：同一个主机的不同写法必须归一到同一个值。"""
    forms = [
        "http://127.0.0.1:8080/sqli/low.php",
        "http://127.0.0.1/",
        "127.0.0.1:8080",
        "127.0.0.1",
    ]
    assert len({normalize_target(f) for f in forms}) == 1


# ----------------------------------------------------- 测试数据


def sample_report() -> dict:
    """构造一份最小可用的报告数据。"""
    return {
        "target": "127.0.0.1",
        "generated_at": "2026-09-17 12:00:00",
        "has_data": True,
        "task_id": 1,
        "scanned_at": "2026-09-17 11:59:00",
        "duration": 4.7,
        "assets": [
            {
                "value": "127.0.0.1",
                "type": "ip",
                "root_domain": "127.0.0.1",
                "resolved_ip": "",
                "source": "",
                "alive": True,
            }
        ],
        "ports": [
            {
                "host": "127.0.0.1",
                "number": 8080,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "nginx",
                "version": "1.24.0",
                "title": "测试站点",
                "banner": "HTTP/1.0 200 OK",
            }
        ],
        "components": [
            {
                "name": "PHP",
                "version": "7.3.4",
                "category": "language",
                "confidence": 0.5,
                "evidence": "header:X-Powered-By: PHP",
            }
        ],
        "vulns": [
            {
                "poc_id": "vulnlab-sqli-low-union",
                "name": "SQL 注入（low 档）",
                "severity": "high",
                "target": "http://127.0.0.1:8080/sqli/low.php?id=1",
                "confidence": 1.0,
                "verified": True,
                "evidence": "hit='VULNLAB_POC_MARKER'",
            }
        ],
        "diff": {"added": ["127.0.0.1"], "removed": []},
        "stats": {
            "asset_count": 1,
            "open_port_count": 1,
            "component_count": 1,
            "vuln_count": 1,
            "by_severity": {"high": 1},
            "by_category": {"language": 1},
        },
    }


def empty_report() -> dict:
    return {
        "target": "empty.example",
        "generated_at": "2026-09-17 12:00:00",
        "has_data": False,
        "assets": [],
        "ports": [],
        "components": [],
        "vulns": [],
        "stats": {},
        "diff": {},
    }


# ----------------------------------------------------- JSON


def test_to_json_is_valid_and_complete():
    data = sample_report()
    text = to_json(data)
    parsed = json.loads(text)
    assert parsed["target"] == "127.0.0.1"
    assert parsed["stats"]["vuln_count"] == 1
    assert len(parsed["ports"]) == 1


def test_to_json_keeps_chinese_readable():
    """ensure_ascii=False —— 中文不该被转义成 \\uXXXX（否则报告不可读）。"""
    text = to_json(sample_report())
    assert "SQL 注入" in text
    assert "\\u" not in text


# ----------------------------------------------------- Markdown


def test_to_markdown_contains_key_sections():
    text = to_markdown(sample_report())
    assert "# 攻击面测绘报告" in text
    assert "## 概览" in text
    assert "## 漏洞详情" in text
    assert "## 开放端口与服务" in text
    assert "## 识别到的组件" in text
    assert "## 资产清单" in text


def test_to_markdown_shows_severity_in_chinese():
    text = to_markdown(sample_report())
    assert "高危" in text


def test_to_markdown_shows_diff():
    text = to_markdown(sample_report())
    assert "相比上次扫描的变化" in text
    assert "新增 1 项" in text


def test_to_markdown_empty_data():
    text = to_markdown(empty_report())
    assert "暂无扫描记录" in text


def test_to_markdown_has_disclaimer():
    """免责声明必须出现在报告里 —— 这是工具的责任边界。"""
    assert "授权" in to_markdown(sample_report())


# ----------------------------------------------------- HTML


def test_to_html_is_complete_document():
    text = to_html(sample_report())
    assert text.startswith("<!DOCTYPE html>")
    assert "</html>" in text
    assert 'lang="zh-CN"' in text
    assert 'charset="utf-8"' in text


def test_to_html_is_self_contained():
    """报告要能当附件直接发出去，所以不能引用任何外部资源。"""
    text = to_html(sample_report())
    assert "<link" not in text
    assert "<script" not in text
    assert "http://cdn" not in text and "https://cdn" not in text


def test_to_html_shows_stats():
    text = to_html(sample_report())
    for label in ["资产数", "开放端口", "识别组件", "发现漏洞"]:
        assert label in text
    assert "高危" in text


def test_to_html_escapes_malicious_asset_names():
    """⚠️ 关键安全测试：报告渲染必须转义，否则扫描结果能反过来 XSS 报告。

    场景：我们扫到一个资产，它的名字里带 <script>。如果不转义，
    打开报告的人就会被执行脚本 —— 这是「安全工具自身被攻击」的典型形态。
    """
    data = sample_report()
    payload = '<script>alert("xss")</script>'
    data["assets"][0]["value"] = payload
    data["components"][0]["name"] = payload
    data["vulns"][0]["target"] = payload
    data["vulns"][0]["evidence"] = payload
    data["target"] = payload

    text = to_html(data)

    assert "<script>alert" not in text, "HTML 报告存在 XSS 漏洞：未经转义就渲染了扫描数据"
    assert "&lt;script&gt;" in text, "应该以转义后的形式展示原始内容"


def test_to_html_escapes_in_title_too():
    data = sample_report()
    data["target"] = "</title><script>alert(1)</script>"

    text = to_html(data)
    assert "<script>alert" not in text
    assert "</title><script>" not in text


def test_to_html_empty_data():
    text = to_html(empty_report())
    assert "暂无扫描记录" in text


# ----------------------------------------------------- 统一入口


def test_render_dispatches_all_formats():
    data = sample_report()
    assert render(data, "json") == to_json(data)
    assert render(data, "md") == to_markdown(data)
    assert render(data, "markdown") == to_markdown(data)
    assert render(data, "html") == to_html(data)


def test_render_is_case_insensitive():
    data = sample_report()
    assert render(data, "HTML") == to_html(data)
    assert render(data, "  Json  ") == to_json(data)


def test_render_rejects_unknown_format():
    with pytest.raises(ValueError, match="不支持的报告格式"):
        render(sample_report(), "pdf")


def test_renderers_registry_covers_documented_formats():
    for fmt in ["json", "md", "markdown", "html"]:
        assert fmt in RENDERERS


# ----------------------------------------------------- 从数据库加载


def test_load_target_report_without_data(tmp_path):
    """数据库里没有该目标时，应返回 has_data=False 而不是抛异常。"""
    from asp.config import Config

    config = Config.from_dict({"database": str(tmp_path / "empty.db")})
    data = load_target_report(config, "nonexistent.example")
    assert data["has_data"] is False
    assert data["target"] == "nonexistent.example"
