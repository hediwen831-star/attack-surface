#!/usr/bin/env python3
"""用无头浏览器批量截靶场截图。

为什么用脚本而不是手工截：截图会随页面改版过期，手工重截 20 张要半小时，
而且尺寸、缩放、滚动位置每次都不一样，拼在 README 里很乱。脚本跑一遍几秒钟。

依赖本机装了 Chrome 或 Edge，以及 Pillow（只用来做无损压缩）。

用法：

    # 先起靶场与看板
    php -S 127.0.0.1:8080 -t html &
    python -m asp.cli -c <带 demo 数据库的配置> serve --port 8088 &

    python tools/shots.py --lab http://127.0.0.1:8080 \
        --dashboard http://127.0.0.1:8088 --out docs/images
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]

SCENES = [
    "sqli", "xss", "cmdi", "ssti", "lfi", "xxe", "upload", "csrf",
    "ssrf", "jwt", "idor", "idor-session", "unserialize",
]

#: 三档对比：一个场景截 low / medium / high 三张，用来展示防护差异
COMPARISONS = ["xss", "cmdi"]

WIDTH = 1280
HEIGHT = 900
MAX_KB = 200


def find_browser() -> str:
    for path in CANDIDATES:
        if Path(path).is_file():
            return path
    raise SystemExit("找不到 Chrome/Edge，无法截图")


def shoot(browser: str, url: str, out: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "shot.png"
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=1",
            f"--window-size={WIDTH},{HEIGHT}",
            "--virtual-time-budget=1500",
            f"--screenshot={raw}",
            url,
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
        if not raw.is_file():
            raise SystemExit(
                f"截图失败：{url}\n{proc.stderr.decode('utf-8', 'ignore')[-400:]}"
            )

        from PIL import Image  # 延迟导入，没装 Pillow 时只影响压缩

        image = Image.open(raw).convert("RGB")
        if image.width > WIDTH:
            image = image.resize((WIDTH, int(image.height * WIDTH / image.width)))
        image.save(out, format="PNG", optimize=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="批量截取靶场与看板截图")
    parser.add_argument("--lab", default="http://127.0.0.1:8080")
    parser.add_argument("--dashboard", default="http://127.0.0.1:8088")
    parser.add_argument("--out", default="docs/images")
    args = parser.parse_args()

    browser = find_browser()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[tuple[str, Path]] = [
        (f"{args.lab}/", out_dir / "lab-index.png"),
        (f"{args.dashboard}/", out_dir / "dashboard.png"),
    ]
    jobs += [(f"{args.lab}/{scene}/low.php", out_dir / f"lab-{scene}-low.png") for scene in SCENES]
    for scene in COMPARISONS:
        for tier in ("medium", "high"):
            jobs.append((f"{args.lab}/{scene}/{tier}.php", out_dir / f"lab-{scene}-{tier}.png"))

    for url, path in jobs:
        shoot(browser, url, path)
        size_kb = path.stat().st_size / 1024
        flag = "  ← 超过 200KB" if size_kb > MAX_KB else ""
        print(f"{path.name:32} {size_kb:6.1f} KB{flag}")

    print(f"\n共 {len(jobs)} 张，输出到 {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
