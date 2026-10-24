"""资产层真值评测（离线，不依赖网络）。

守护的是 `benchmark/asset/cases.yaml` 里那批泛解析场景的预期行为：
枚举结果保留哪些子域名、过滤哪些噪音，必须与用例定义一致。

已知局限（CDN 同 IP 过杀）不在断言里假装通过 —— 它是独立的用例，
断言明确要求「这一例目前会失败」，等算法改进后再改断言。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark.asset.evaluate_asset import load_cases, run_all, summarize  # noqa: E402


def test_asset_cases_offline() -> None:
    import asyncio

    cases = load_cases()
    results = asyncio.run(run_all())

    assert len(results) == len(cases)

    normal_failures = [r for r in results if not r["known_limitation"] and not r["pass"]]
    assert not normal_failures, f"资产层用例未通过：{[r['id'] for r in normal_failures]}"

    summary = summarize(results, cases)
    assert summary["TPR_excl_known"] == 1.0
    assert summary["FPR"] == 0.0


def test_cdn_same_ip_rescued_by_http() -> None:
    """同 IP 但页面不同：HTTP 二次判定应把真实域名留下。"""
    import asyncio

    results = asyncio.run(run_all())
    cdn = next(r for r in results if r["id"] == "wildcard-cdn-same-ip")

    assert cdn["pass"]
    assert cdn["alive_actual"] == ["www"]


def test_cdn_http_down_is_known_limitation() -> None:
    """HTTP 探测不可用时退回纯 IP 比对，过杀属已知局限。"""
    import asyncio

    results = asyncio.run(run_all())
    down = next(r for r in results if r["id"] == "wildcard-cdn-http-down")

    assert down["known_limitation"] is True
    assert down["over_filtered"] == ["www"]
    assert not down["pass"]
