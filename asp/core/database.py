"""资产数据模型（SQLAlchemy 2.0）。

为什么是「六表关联」而不是一张大宽表？

测绘的本质是**同一份资产的多次观测**：
- 一个域名可能解析到多个 IP（CDN、多机房）
- 一个 IP 可能开放多个端口
- 一个端口对应一个服务
- 一个服务由多个组件构成（中间件 + 框架）
- 一个组件可能命中多个漏洞

如果压成一张宽表，资产去重、变更 diff、按维度统计全部没法做。
关系模型让「新增了哪些 IP」「哪个组件的漏洞数最多」这类查询变成一句 SQL，
这正是攻击面管理区别于「扫一遍就忘」的地方。

表结构：

    ScanTask  ──< Asset(domain) ──< Asset(ip) ──< Port ──< Service ──< Component
                                                                        │
                                                                        └──< Vuln
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
)

from ..logger import get_logger

logger = get_logger("core.database")


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。"""


def _utcnow() -> datetime:
    """统一使用带时区的 UTC 时间 —— 避免 naive datetime 带来的时区坑。"""
    return datetime.now(UTC)


class ScanTask(Base):
    """一次扫描任务。

    保留任务维度是为了支持「资产变更 diff」：
    对比两次任务的资产集合，就能回答「本次新增了什么」。
    """

    __tablename__ = "scan_task"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    """扫描目标（根域名或 CIDR）。"""

    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    """状态机：pending → running → success / failed / cancelled。

    支持断点续跑的前提就是任务状态可持久化。
    """

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    stats: Mapped[str] = mapped_column(Text, default="{}")
    """统计信息 JSON：各阶段耗时、发现数量等。"""

    assets: Mapped[list[Asset]] = relationship(back_populates="task", cascade="all, delete-orphan")

    @property
    def duration(self) -> float | None:
        """任务耗时（秒）。未完成时为 None。"""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def set_stats(self, **kwargs: Any) -> None:
        """合并写入统计字段。"""
        current = json.loads(self.stats or "{}")
        current.update(kwargs)
        self.stats = json.dumps(current, ensure_ascii=False)

    def get_stats(self) -> dict[str, Any]:
        """读取统计字段。"""
        return json.loads(self.stats or "{}")


class Asset(Base):
    """资产 —— 域名或 IP。

    设计取舍：为什么域名和 IP 用同一张表 + type 字段？
    它们共享大量属性（来源、首次发现时间、关联任务），
    拆两张表会带来大量重复逻辑，而 type 字段足以区分。
    """

    __tablename__ = "asset"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("scan_task.id"), index=True)

    type: Mapped[str] = mapped_column(String(10), index=True)
    """``domain`` 或 ``ip``。"""

    value: Mapped[str] = mapped_column(String(255), index=True)
    """域名本身，或 IP 字符串。"""

    root_domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    """所属根域名 —— 方便按根域名聚合统计。"""

    resolved_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    """域名解析结果（仅 type=domain 有意义）。"""

    source: Mapped[str] = mapped_column(String(50), default="")
    """首次发现该资产的来源（crtsh / brute / ...），用于可信度评估。"""

    alive: Mapped[bool] = mapped_column(Boolean, default=False)
    """是否存活（能解析 / 能连通）。"""

    fingerprint: Mapped[str] = mapped_column(String(128), default="", index=True)
    """资产指纹哈希 —— 用于跨任务去重。"""

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    task: Mapped[ScanTask] = relationship(back_populates="assets")
    ports: Mapped[list[Port]] = relationship(back_populates="asset", cascade="all, delete-orphan")

    @staticmethod
    def make_fingerprint(value: str, asset_type: str) -> str:
        """生成资产指纹。

        用「类型 + 规范化值」做哈希，保证同一资产在不同任务中指纹一致。
        """
        import hashlib

        normalized = value.strip().lower().rstrip(".")
        return hashlib.sha256(f"{asset_type}:{normalized}".encode()).hexdigest()[:32]

    def __repr__(self) -> str:
        return f"<Asset {self.type} {self.value} alive={self.alive}>"


class Port(Base):
    """端口。"""

    __tablename__ = "port"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    number: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(10), default="open")
    banner: Mapped[str] = mapped_column(Text, default="")
    """原始 banner —— 指纹识别的一手材料，必须保留。"""

    asset: Mapped[Asset] = relationship(back_populates="ports")
    service: Mapped[Service | None] = relationship(
        back_populates="port", cascade="all, delete-orphan", uselist=False
    )

    def __repr__(self) -> str:
        return f"<Port {self.number}/{self.protocol} {self.state}>"


class Service(Base):
    """服务 —— 端口上运行的东西。"""

    __tablename__ = "service"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("port.id"), index=True, unique=True)

    name: Mapped[str] = mapped_column(String(64), default="", index=True)
    """服务名，如 http / ssh / mysql。"""

    product: Mapped[str] = mapped_column(String(128), default="")
    """产品名，如 nginx / Apache httpd / OpenSSH。"""

    version: Mapped[str] = mapped_column(String(64), default="")
    """版本号。"""

    http_title: Mapped[str] = mapped_column(String(255), default="")
    """HTTP 页面标题 —— 人工审阅时最直观的信息。"""

    http_status: Mapped[int] = mapped_column(Integer, default=0)
    server_header: Mapped[str] = mapped_column(String(255), default="")
    favicon_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    """favicon 的 mmh3 哈希 —— 识别同源系统与 CMS 的强特征。"""

    port: Mapped[Port] = relationship(back_populates="service")
    components: Mapped[list[Component]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Service {self.product} {self.version} title={self.http_title[:20]!r}>"


class Component(Base):
    """组件 —— Web 应用/中间件/框架，漏洞的挂载点。"""

    __tablename__ = "component"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("service.id"), index=True)

    name: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    category: Mapped[str] = mapped_column(String(32), default="")
    """类别：cms / framework / middleware / language / javascript。"""

    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    """置信度 0~1。多规则命中则累加 —— 单一弱特征不应直接判定。"""

    evidence: Mapped[str] = mapped_column(Text, default="")
    """命中证据（哪个规则、匹配到什么），误报排查时靠它。"""

    service: Mapped[Service] = relationship(back_populates="components")
    vulns: Mapped[list[Vuln]] = relationship(back_populates="component", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Component {self.name} {self.version} conf={self.confidence:.2f}>"


class Vuln(Base):
    """漏洞命中记录。"""

    __tablename__ = "vuln"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("component.id"), index=True, nullable=True)

    poc_id: Mapped[str] = mapped_column(String(128), index=True)
    """命中的 PoC 标识。"""

    name: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    """实际请求的 URL。"""

    matched_at: Mapped[str] = mapped_column(String(512), default="")
    """命中的具体位置（URL / header / body 片段）。"""

    evidence: Mapped[str] = mapped_column(Text, default="")
    """原始响应片段 —— 报告里必须能拿出证据，不能只有「存在漏洞」四个字。"""

    detail: Mapped[str] = mapped_column(Text, default="{}")
    """附加信息 JSON（提取器结果、请求摘要）。"""

    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    """置信度。多条件二次验证通过则为 1.0，单条件命中适当降低。"""

    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    """是否经过二次验证。"""

    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    component: Mapped[Component | None] = relationship(back_populates="vulns")

    def __repr__(self) -> str:
        return f"<Vuln {self.poc_id} @ {self.target} conf={self.confidence:.2f}>"


# --------------------------------------------------------------------- 引擎


def create_db_engine(database: str | Path = "asp.db", *, echo: bool = False) -> Engine:
    """创建数据库引擎。

    对 SQLite 开启 WAL 模式：扫描是「多协程写 + 前端读」的场景，
    默认的 journal 模式会让读被写阻塞，WAL 允许读写并发。
    """
    url = f"sqlite:///{database}" if not str(database).startswith("sqlite") else str(database)
    engine = create_engine(url, echo=echo, future=True)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _record):  # pragma: no cover - 依赖驱动
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def init_db(engine: Engine) -> None:
    """建表（幂等）。"""
    Base.metadata.create_all(engine)


def session_scope(engine: Engine) -> Session:
    """创建一个会话 —— 调用方负责 commit/close。"""
    return Session(engine)


__all__ = [
    "Base",
    "ScanTask",
    "Asset",
    "Port",
    "Service",
    "Component",
    "Vuln",
    "create_db_engine",
    "init_db",
    "session_scope",
]
