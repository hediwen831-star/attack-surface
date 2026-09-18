"""端口扫描与服务识别测试。

覆盖重点：
- 端口表达式解析（含边界与非法输入）
- 服务指纹匹配
- **两条来自实测的误报回归**：
  ① MySQL 握手包不能被误判为 telnet
  ② telnet 规则不能过于宽松地匹配任意含 "password" 的内容
"""

from __future__ import annotations

import pytest

from asp.discover.portscan import (
    TOP_PORTS,
    fingerprint_service,
    parse_ports,
)

# --------------------------------------------------------------- 端口解析


def test_parse_ports_none_returns_top():
    assert parse_ports(None) == list(TOP_PORTS)


def test_parse_ports_keyword_top():
    assert parse_ports("top") == list(TOP_PORTS)
    assert parse_ports("TOP") == list(TOP_PORTS)


def test_parse_ports_single():
    assert parse_ports("80") == [80]


def test_parse_ports_list():
    assert parse_ports("80,443,8080") == [80, 443, 8080]


def test_parse_ports_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_ports_mixed():
    assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_reversed_range_is_normalized():
    """写反的范围应该被自动纠正，而不是报错或产生空列表。"""
    assert parse_ports("90-88") == [88, 89, 90]


def test_parse_ports_sequence_input():
    assert parse_ports([443, 80, 80]) == [80, 443]


def test_parse_ports_deduplicates():
    assert parse_ports("80,80,80-82") == [80, 81, 82]


def test_parse_ports_rejects_out_of_range():
    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("0")


def test_parse_ports_all_is_full_range():
    ports = parse_ports("all")
    assert len(ports) == 65535
    assert ports[0] == 1
    assert ports[-1] == 65535


# --------------------------------------------------------------- 服务识别


def test_fingerprint_ssh():
    banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    info = fingerprint_service(banner)
    assert info.name == "ssh"
    assert info.product == "OpenSSH"
    assert info.version == "8.2p1"


def test_fingerprint_http_nginx():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"
    info = fingerprint_service(banner)
    assert info.name == "http"
    assert info.product.lower() == "nginx"
    assert info.version == "1.24.0"


def test_fingerprint_http_apache():
    banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"
    info = fingerprint_service(banner)
    assert info.name == "http"
    assert info.product.startswith("Apache")


def test_fingerprint_http_fallback_without_server_header():
    """没有 Server 头也要能识别出这是 HTTP —— 否则会退化成一堆 unknown。"""
    banner = "HTTP/1.0 200 OK\r\nContent-Type: text/html"
    assert fingerprint_service(banner).name == "http"


def test_fingerprint_ftp():
    banner = "220 (vsFTPd 3.0.3)\r\n"
    info = fingerprint_service(banner)
    assert info.name == "ftp"
    assert "vsFTPd" in info.product


def test_fingerprint_empty_returns_unknown():
    info = fingerprint_service("")
    assert info.name == ""
    assert info.display == "unknown"


def test_fingerprint_evidence_recorded():
    """命中依据要留痕 —— 否则误报无法追溯。"""
    info = fingerprint_service("SSH-2.0-OpenSSH_9.0")
    assert info.evidence
    assert "ssh" in info.evidence


def test_fingerprint_display_format():
    assert fingerprint_service("SSH-2.0-OpenSSH_9.0").display == "ssh (OpenSSH 9.0)"


# ------------------------------------------------- 实测误报回归（重点）


def test_mysql_banner_is_not_telnet():
    """回归测试：MySQL 握手包曾被误判成 telnet。

    真实原因：MySQL 握手包里有 "mysql_native_password" 这个字符串，
    而最初的 telnet 规则是 ``^(?:.*?(?:login|password))`` ——
    它能匹配任意位置出现的 "password"，于是 3306 端口被报成 telnet。

    这个 bug 的教训是：**兜底型规则越宽松，误报越难排查**
    （因为看起来确实"匹配到了内容"）。
    """
    # 构造接近真实的 MySQL 8.x 握手包
    banner = (
        "\n"
        "8.0.35\x00"
        "\x15\x00\x00\x00"                       # 连接 ID
        "\x01\x02\x03\x04\x05\x06\x07\x08"        # challenge
        "\x00"
        "\xff\xf7"                               # capability flags
        "\x21"                                   # 字符集
        "\x02\x00"
        "\xff\x81"                               # status flags
        "\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "mysql_native_password\x00"
    )
    info = fingerprint_service(banner)

    assert info.name == "mysql", f"MySQL 握手包被误判为 {info.name}"
    assert info.version == "8.0.35"


def test_mysql_caching_sha2_not_telnet():
    """MySQL 8 默认用 caching_sha2_password，同样不能误判。"""
    banner = "\n8.4.10\x00\x0c\x00\x00\x00" + "A" * 20 + "\x00caching_sha2_password\x00"
    info = fingerprint_service(banner)
    assert info.name == "mysql"
    assert info.version == "8.4.10"


def test_telnet_rule_requires_line_start_prompt():
    """telnet 规则必须只在「行首就是登录提示」时命中。"""
    # 真正的 telnet 提示
    assert fingerprint_service("Ubuntu 22.04\r\nlogin: ").name == "telnet"
    assert fingerprint_service("Password: ").name == "telnet"

    # 只是正文里提到 password 的，不应命中
    assert fingerprint_service("this page mentions a password field").name != "telnet"
    assert fingerprint_service("mysql_native_password").name != "telnet"


def test_no_rule_matches_arbitrary_binary():
    """随机的二进制噪声不该被任何规则匹配成具体服务。

    这条测试守的是「不要为了覆盖率而写过分宽松的兜底规则」。
    """
    noise = bytes(range(256)).decode("latin-1")
    info = fingerprint_service(noise)
    # 允许识别不出（name 为空），但不该被认成某个具体协议
    assert info.name not in {"telnet", "ftp", "smtp", "mysql", "redis", "vnc"}


def test_top_ports_are_valid_and_unique():
    """内置端口表自检：范围合法、无重复。"""
    assert len(TOP_PORTS) == len(set(TOP_PORTS)), "内置端口表存在重复项"
    assert all(1 <= p <= 65535 for p in TOP_PORTS)
    assert 80 in TOP_PORTS and 443 in TOP_PORTS and 22 in TOP_PORTS
    assert 8080 in TOP_PORTS, "靶场默认端口应该在默认扫描范围内"
