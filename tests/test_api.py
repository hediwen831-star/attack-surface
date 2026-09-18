"""Web API 测试。

覆盖重点：
- 只读端点的正常路径
- **绑定安全检查**（这是这个模块最重要的安全属性）
- **Token 认证**（会发起扫描的端点必须受保护）
- 看板页面可访问

依赖 fastapi 时自动跳过（它是可选依赖，不进运行时）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="Web 接口是可选依赖：pip install -e \".[api]\"")
pytest.importorskip("httpx", reason="TestClient 需要 httpx")

from fastapi.testclient import TestClient  # noqa: E402

from asp.api.app import check_bind_safety, create_app  # noqa: E402
from asp.config import Config  # noqa: E402


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """用临时数据库的配置，保证测试互不干扰。"""
    return Config.from_dict({"database": str(tmp_path / "api_test.db")})


@pytest.fixture
def client(config: Config) -> TestClient:
    return TestClient(create_app(config))


@pytest.fixture
def auth_client(config: Config) -> TestClient:
    """启用了 token 的客户端。"""
    return TestClient(create_app(config, token="secret-token-123"))


# ---------------------------------------------------------- 绑定安全检查


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_without_token_is_allowed(host):
    """本机绑定不需要 token —— 这是默认且安全的用法。"""
    check_bind_safety(host, None)   # 不应抛异常


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])
def test_public_bind_without_token_is_rejected(host):
    """绑定到外部地址但没设 token —— 必须拒绝启动。

    这个接口能发起主动扫描，无认证地暴露等于把工具变成别人的攻击跳板，
    而且流量从使用者的 IP 出去。所以这里是「拒绝启动」而不是「打印警告」——
    警告没人看。
    """
    with pytest.raises(SystemExit) as exc:
        check_bind_safety(host, None)
    assert "拒绝启动" in str(exc.value)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10"])
def test_public_bind_with_token_is_allowed(host):
    """设了 token 就允许对外绑定。"""
    check_bind_safety(host, "some-token")


# ---------------------------------------------------------- 只读端点


def test_health(client: TestClient):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert data["auth_required"] is False
    assert data["capabilities"]["poc_engine"] is True


def test_health_reports_auth_required(auth_client: TestClient):
    assert auth_client.get("/api/health").json()["auth_required"] is True


def test_stats_on_empty_database(client: TestClient):
    data = client.get("/api/stats").json()
    assert data["targets"] == 0
    assert data["assets"] == 0
    assert data["vulns"] == 0
    assert data["by_severity"] == {}


def test_targets_on_empty_database(client: TestClient):
    data = client.get("/api/targets").json()
    assert data["targets"] == []


def test_target_detail_not_found(client: TestClient):
    r = client.get("/api/targets/nonexistent.example")
    assert r.status_code == 404
    assert "没有扫描记录" in r.json()["detail"]


def test_pocs_listing(client: TestClient):
    data = client.get("/api/pocs").json()
    assert data["count"] >= 5
    ids = {p["id"] for p in data["pocs"]}
    assert "git-config-exposure" in ids
    # 每条都要有严重级别，前端要用来着色
    assert all(p["severity"] for p in data["pocs"])


def test_report_endpoint_rejects_bad_format(client: TestClient):
    r = client.get("/api/targets/x/report?format=pdf")
    assert r.status_code == 422      # FastAPI 的 pattern 校验


def test_dashboard_html(client: TestClient):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "ASP" in r.text
    assert "攻击面" in r.text


def test_openapi_schema_available(client: TestClient):
    """接口文档可访问 —— 这是 FastAPI 的免费产出，也是给别人看的门面。"""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    for expected in ["/api/health", "/api/targets", "/api/scan/poc"]:
        assert expected in paths


# ---------------------------------------------------------- Token 认证


def test_scan_endpoints_require_token_when_configured(auth_client: TestClient):
    """配置了 token 时，扫描端点必须鉴权 —— 这是安全边界。"""
    endpoints = [
        ("/api/scan/subdomain", {"domain": "example.com"}),
        ("/api/scan/portscan", {"host": "127.0.0.1"}),
        ("/api/scan/poc", {"target": "http://127.0.0.1"}),
    ]
    for path, payload in endpoints:
        r = auth_client.post(path, json=payload)
        assert r.status_code == 401, f"{path} 在未鉴权时不应放行"
        assert "X-API-Token" in r.json()["detail"]


def test_scan_endpoints_reject_wrong_token(auth_client: TestClient):
    r = auth_client.post(
        "/api/scan/subdomain",
        json={"domain": "example.com"},
        headers={"X-API-Token": "wrong-token"},
    )
    assert r.status_code == 401


def test_readonly_endpoints_do_not_require_token(auth_client: TestClient):
    """只读端点不强制鉴权 —— 看报告本身不产生任何网络流量。"""
    assert auth_client.get("/api/health").status_code == 200
    assert auth_client.get("/api/stats").status_code == 200
    assert auth_client.get("/api/targets").status_code == 200
    assert auth_client.get("/api/pocs").status_code == 200
    assert auth_client.get("/").status_code == 200


def test_token_uses_constant_time_comparison(auth_client: TestClient):
    """用 hmac.compare_digest 而非 == —— 避免通过响应时间侧信道爆破 token。

    这里无法直接测时序，但可以确认不同长度的错误 token 都被拒绝，
    且不会因为前缀匹配而放行。
    """
    for bad in ["s", "secret", "secret-token-12", "secret-token-1234", ""]:
        r = auth_client.post(
            "/api/scan/subdomain",
            json={"domain": "example.com"},
            headers={"X-API-Token": bad},
        )
        assert r.status_code == 401, f"错误 token {bad!r} 不应通过"


# ---------------------------------------------------------- 请求校验


def test_request_validation_rejects_empty_domain(client: TestClient):
    r = client.post("/api/scan/subdomain", json={"domain": ""})
    assert r.status_code == 422


def test_request_validation_rejects_missing_field(client: TestClient):
    r = client.post("/api/scan/portscan", json={})
    assert r.status_code == 422


def test_scan_poc_rejects_empty_result_set(client: TestClient):
    """指定了不存在的 PoC ID 时应返回 400 而不是静默成功。

    「没匹配到任何 PoC」和「扫描完成但没发现漏洞」是完全不同的结论，
    混在一起会让人误以为扫过了。
    """
    r = client.post(
        "/api/scan/poc",
        json={"target": "http://127.0.0.1:1", "poc_ids": ["no-such-poc-id"]},
    )
    assert r.status_code == 400
    assert "没有匹配的 PoC" in r.json()["detail"]
