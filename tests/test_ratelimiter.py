"""令牌桶限速器测试。

**为什么这个组件值得单独写测试**：

限速是「工具不把目标打挂」的底线。它出错的后果不是功能异常，
而是**静默地对目标发起远超预期的请求量** —— 用户看不到任何报错，
只会在目标方投诉时才发现。

而它又特别容易写错（令牌补充的时机、容量的上限、并发下的竞争），
所以哪怕是纯时间逻辑，也要覆盖到。
"""

from __future__ import annotations

import asyncio
import time

import pytest

from asp.core.http import RateLimiter


class TestRateLimiterInit:
    def test_rejects_non_positive_rate(self):
        with pytest.raises(ValueError, match="rate"):
            RateLimiter(rate=0)
        with pytest.raises(ValueError, match="rate"):
            RateLimiter(rate=-1)

    def test_default_burst_equals_rate(self):
        """默认桶容量 = rate，即最多允许 1 秒的突发量。"""
        assert RateLimiter(rate=10).capacity == 10
        assert RateLimiter(rate=50).capacity == 50

    def test_default_burst_minimum_one(self):
        """rate 很小时容量至少为 1 —— 否则永远拿不到令牌。"""
        assert RateLimiter(rate=0.1).capacity == 1

    def test_explicit_burst(self):
        assert RateLimiter(rate=10, burst=3).capacity == 3

    def test_starts_with_full_bucket(self):
        limiter = RateLimiter(rate=10, burst=5)
        assert limiter._tokens == 5


class TestRateLimiterAcquire:
    async def test_first_acquires_are_not_blocked(self):
        """桶是满的 —— 前 N 次（N = 容量）请求应该瞬间完成，不阻塞。"""
        limiter = RateLimiter(rate=1000, burst=10)

        started = time.monotonic()
        for _ in range(10):
            await limiter.acquire()
        elapsed = time.monotonic() - started

        assert elapsed < 0.1, f"桶满时不该阻塞，实际耗时 {elapsed:.3f}s"

    async def test_blocks_after_bucket_empty(self):
        """桶空之后必须等待 —— 这是限速生效的直接证据。"""
        # rate=50 → 补一个令牌需要 20ms
        limiter = RateLimiter(rate=50, burst=1)
        await limiter.acquire()          # 用掉唯一的令牌

        started = time.monotonic()
        await limiter.acquire()          # 必须等令牌补充
        elapsed = time.monotonic() - started

        assert elapsed >= 0.015, f"桶空后应阻塞约 20ms，实际 {elapsed * 1000:.1f}ms"

    async def test_overall_rate_is_limited(self):
        """★ 核心断言：连续 N 次的总体速率不超过配置值。

        这条才是限速真正要保证的东西 —— 单次阻塞时长可能因为
        调度误差不精确，但整体速率必须受控。
        """
        rate = 100.0                 # 100 QPS
        count = 20
        limiter = RateLimiter(rate=rate, burst=1)

        started = time.monotonic()
        for _ in range(count):
            await limiter.acquire()
        elapsed = time.monotonic() - started

        # 桶初始有 1 个令牌，所以实际需要补 count-1 个
        expected_min = (count - 1) / rate
        assert elapsed >= expected_min * 0.8, (
            f"速率超过配置：{count} 次耗时 {elapsed:.3f}s，"
            f"理论上至少 {expected_min:.3f}s"
        )

    async def test_tokens_never_exceed_capacity(self):
        """长时间空闲后，令牌不该无限累积 —— 否则一次突发就能打挂目标。"""
        limiter = RateLimiter(rate=1000, burst=3)
        await asyncio.sleep(0.05)         # 足够补满很多次
        await limiter.acquire(tokens=1)

        # 如果容量没封顶，池子里会有 50 个令牌
        assert limiter._tokens <= limiter.capacity

    async def test_acquire_multiple_tokens(self):
        """一次要多个令牌也要正确扣减。"""
        limiter = RateLimiter(rate=1000, burst=5)
        await limiter.acquire(tokens=3)
        assert limiter._tokens == pytest.approx(2, abs=0.1)

    async def test_rejects_request_larger_than_capacity(self):
        """★ 回归测试：请求的令牌数超过桶容量时必须抛异常，不能死循环。

        真实 bug：`acquire(tokens=4)` 配 `burst=2` 会让 while 循环永远转下去 ——
        因为令牌补充被容量封顶，永远补不到 4，于是无限 sleep。

        表现是「测试卡住不动」，而不是报错。**能静默死循环的 API 比会抛异常的
        API 危险得多**，所以现在显式拒绝。
        """
        limiter = RateLimiter(rate=1000, burst=2)

        with pytest.raises(ValueError, match="超过桶容量"):
            await asyncio.wait_for(limiter.acquire(tokens=4), timeout=1.0)

    async def test_accepts_request_equal_to_capacity(self):
        """恰好等于容量的请求是合法的边界。"""
        limiter = RateLimiter(rate=1000, burst=5)
        await asyncio.wait_for(limiter.acquire(tokens=5), timeout=1.0)
        assert limiter._tokens == pytest.approx(0, abs=0.1)

    async def test_concurrent_acquires_are_serialized(self):
        """并发调用下总速率仍受控 —— 锁必须真的起作用。"""
        rate = 200.0
        limiter = RateLimiter(rate=rate, burst=1)

        started = time.monotonic()
        await asyncio.gather(*(limiter.acquire() for _ in range(10)))
        elapsed = time.monotonic() - started

        expected_min = 9 / rate          # 10 次里第一次不等待
        assert elapsed >= expected_min * 0.8, (
            f"并发下限速失效：10 次并发耗时 {elapsed:.3f}s，至少应 {expected_min:.3f}s"
        )

    async def test_zero_rate_rejected_before_use(self):
        """构造时就该拒绝非法配置，而不是等到运行时除零。"""
        with pytest.raises(ValueError):
            RateLimiter(rate=0)
