#!/usr/bin/env python3
"""资产层评测：泛解析条件下的子域名枚举。

应用层评测在 vulnlab，这里测的是「哪些资产是活的」。泛解析会让枚举器
把编造的子域名全记成资产，后面所有检测都建立在假目标上。

用例在 cases.yaml，跑的是 detect_wildcard 和 BruteForceSource.fetch，
只把 DNS 解析换成按用例作答的假解析器，所以离线可跑、结果可复现。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

import asp.discover.bruteforce as brute_mod  # noqa: E402
from asp.config import Config  # noqa: E402
from asp.discover.bruteforce import BruteForceSource  # noqa: E402

CASES = Path(__file__).resolve().parent / "cases.yaml"


def load_cases() -> list[dict]:
    try:
        import yaml  # noqa: PLC0415
    except ModuleNotFoundError:
        raise SystemExit("[依赖缺失] 需要 PyYAML：pip install pyyaml") from None
    return yaml.safe_load(CASES.read_text(encoding="utf-8"))["cases"]


def make_resolver(case: dict):
    """按用例构造一个假的 DNS 解析器。"""
    zone = case.get("zone") or f"{case['id']}.test"
    records = case.get("records") or {}
    wildcard = case.get("wildcard") or []
    hijack = case.get("hijack") or {}
    hijack_labels = set(hijack.get("labels") or [])
    hijack_ips = hijack.get("ips") or []

    async def resolve(hostname: str, timeout: float = 1.0) -> set[str]:
        label = hostname[: -len(zone) - 1] if hostname.endswith("." + zone) else hostname
        if label in records:
            return set(records[label])
        if label in hijack_labels:
            return set(hijack_ips)
        # 探测泛解析用的随机标签：只要有 wildcard 就一律解析成功
        if label.startswith("asp-probe-"):
            return set(wildcard)
        if wildcard:
            return set(wildcard)
        return set()

    return resolve


async def run_case(case: dict) -> dict:
    """跑一个用例：走生产代码（detect_wildcard + BruteForceSource.fetch），只替换 DNS。"""
    zone = f"{case['id']}.test"
    resolver = make_resolver({**case, "zone": zone})

    original = brute_mod.resolve_host
    brute_mod.resolve_host = resolver
    try:
        config = Config()
        config.discover.brute_concurrency = 8
        source = BruteForceSource(config)
        source.words = list(case.get("wordlist") or [])
        assets = await source.fetch(zone)
        kept = [a.value[: -len(zone) - 1] for a in assets]
        # fetch 内部已经做了泛解析基线检测，这里直接取生产路径的结果
        wildcard_ips = source.wildcard_ips
    finally:
        brute_mod.resolve_host = original

    expect = case["expect"]
    alive_expected = set(expect.get("alive") or [])
    filtered_expected = set(expect.get("filtered") or [])
    kept_set = set(kept)

    return {
        "id": case["id"],
        "description": case.get("description", ""),
        "trap": case.get("trap", ""),
        "known_limitation": bool(case.get("known_limitation")),
        "known_limitation_note": case.get("known_limitation_note", ""),
        "wildcard_expected": bool(expect.get("wildcard")),
        "wildcard_detected": bool(wildcard_ips),
        "wildcard_ips": sorted(wildcard_ips),
        "alive_expected": sorted(alive_expected),
        "alive_actual": sorted(kept_set),
        "over_filtered": sorted(alive_expected - kept_set),
        "missed_noise": sorted(kept_set & filtered_expected),
        "pass": (
            bool(wildcard_ips) == bool(expect.get("wildcard"))
            and kept_set == alive_expected
        ),
    }


async def run_all() -> list[dict]:
    return [await run_case(case) for case in load_cases()]


def summarize(results: list[dict], cases: list[dict]) -> dict:
    real_total = sum(len(r["alive_expected"]) for r in results)
    over_filtered = sum(len(r["over_filtered"]) for r in results)
    noise_kept = sum(len(r["missed_noise"]) for r in results)
    noise_total = sum(len(c["expect"].get("filtered") or []) for c in cases)
    wildcard_ok = sum(1 for r in results if r["wildcard_detected"] == r["wildcard_expected"])

    # 已知局限用例单独计：它们失败是预期内的，不能混进 TPR/FPR 的分母里假装通过。
    known = [r for r in results if r["known_limitation"]]
    normal = [r for r in results if not r["known_limitation"]]
    normal_real = sum(len(r["alive_expected"]) for r in normal)
    normal_over = sum(len(r["over_filtered"]) for r in normal)

    return {
        "cases": len(results),
        "wildcard_detection_accuracy": f"{wildcard_ok}/{len(results)}",
        "real_assets": real_total,
        "over_filtered": over_filtered,
        "noise_total": noise_total,
        "noise_kept": noise_kept,
        "TPR": round((real_total - over_filtered) / real_total, 4) if real_total else None,
        "TPR_excl_known": round((normal_real - normal_over) / normal_real, 4) if normal_real else None,
        "FPR": round(noise_kept / noise_total, 4) if noise_total else None,
        "passed": sum(1 for r in results if r["pass"]),
        "known_limitations": len(known),
        "known_limitation_failures": sum(1 for r in known if not r["pass"]),
    }


def render_markdown(summary: dict, results: list[dict]) -> str:
    lines = [
        "# 资产层评测：泛解析与子域名枚举",
        "",
        f"- 用例 {summary['cases']} 个，通过 {summary['passed']}",
        f"- 泛解析判定正确 {summary['wildcard_detection_accuracy']}",
        f"- 真实资产 {summary['real_assets']} 个，被误杀 {summary['over_filtered']} → TPR {summary['TPR'] * 100:.1f}%"
        f"（剔除已知局限后 {summary['TPR_excl_known'] * 100:.1f}%）",
        f"- 泛解析噪音 {summary['noise_total']} 个，漏过滤 {summary['noise_kept']} → FPR {summary['FPR'] * 100:.1f}%",
        "",
        "| 用例 | 考察点 | 泛解析判定 | 保留 | 过杀 | 漏杀 | 结论 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| `{r['id']}` | {r['trap']} | "
            f"{'有' if r['wildcard_detected'] else '无'} | "
            f"{', '.join(r['alive_actual']) or '—'} | "
            f"{', '.join(r['over_filtered']) or '—'} | "
            f"{', '.join(r['missed_noise']) or '—'} | "
            f"{'通过' if r['pass'] else ('已知局限' if r['known_limitation'] else '不符')} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="资产层真值评测")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out-dir", default=str(Path(__file__).resolve().parent / "results"))
    args = parser.parse_args()

    started = time.time()
    cases = load_cases()
    results = asyncio.run(run_all())
    summary = summarize(results, cases)
    elapsed = time.time() - started

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    payload = {"summary": summary, "results": results, "elapsed_sec": round(elapsed, 2)}
    (out_dir / f"asset-{stamp}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / f"asset-{stamp}.md").write_text(render_markdown(summary, results), encoding="utf-8")

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print()
        print("=" * 76)
        print("  资产层评测：泛解析与子域名枚举")
        print("=" * 76)
        print(f"  用例 {summary['cases']}，通过 {summary['passed']}")
        print(f"  泛解析判定 {summary['wildcard_detection_accuracy']}")
        print(f"  TPR {summary['TPR'] * 100:.1f}%   FPR {summary['FPR'] * 100:.1f}%")
        print()
        for r in results:
            mark = "[通过]" if r["pass"] else "[不符]"
            print(f"  {mark} {r['id']:<26} 保留={r['alive_actual']}")
            if r["over_filtered"]:
                label = "过杀（已知局限）" if r["known_limitation"] else "过杀"
                print(f"          {label}: {r['over_filtered']}")
            if r["missed_noise"]:
                print(f"          漏杀: {r['missed_noise']}")
        print()
        print(f"  结果写入 {out_dir}/asset-{stamp}.json")
        print()

    # 只有「非已知局限」的用例失败才算不通过
    return 0 if summary["passed"] + summary["known_limitation_failures"] == summary["cases"] else 1


if __name__ == "__main__":
    sys.exit(main())
