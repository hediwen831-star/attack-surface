"""端口扫描与服务识别。

## 为什么不用 nmap / masscan

这不是「造轮子」，而是刻意的分层：

| | nmap / masscan | 本模块 |
|---|---|---|
| 定位 | 完整的网络扫描引擎 | 轻量探测 + 结果结构化 |
| 依赖 | 需要单独安装二进制 | 纯 Python，零依赖 |
| 目标场景 | 大批量、复杂探测 | 与资产模型直接对接、可编排 |

真实项目里的做法是**两者都要**：本模块负责「快速连通性判断 + 服务初判」，
需要深度探测时再把 nmap 作为可选后端接进来（见 `NMAP_BACKEND` 说明）。

## 两阶段 banner 抓取

朴素做法是「连上就读」，但不同服务的握手方式完全不同：

| 服务类型 | 行为 | 抓取策略 |
|---|---|---|
| SSH / FTP / SMTP / MySQL | **服务端主动发 banner** | 连上直接读 |
| HTTP / HTTPS | 服务端等客户端先说话 | 需要主动发 `GET / HTTP/1.0` |

所以采用两阶段：先「静默读」，超时没数据再按端口类型发探测包。

## 已知局限（诚实写出来）

- 只做 TCP connect 扫描（`asyncio.open_connection`），不做 SYN 半开扫描。
  优点是不需要 root/管理员权限，缺点是会在目标留下完整连接记录，更容易被日志发现。
- 不做 UDP 扫描。UDP 无连接，需要发特定载荷并等待 ICMP 或响应，误判率高，
  且需要原始套接字权限。
- 不做操作系统识别（TCP/IP 栈指纹），那需要构造异常包，属于原始套接字范畴。
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from ..logger import get_logger

logger = get_logger("discover.portscan")

#: 默认扫描的常见端口（按服务重要性排序，而非端口号大小）。
#: 这是「先扫最可能出货的」思路 —— 全端口扫描 65535 个端口在授权测试里
#: 既慢又容易触发告警，先扫常见端口再按需扩大是更专业的做法。
TOP_PORTS: tuple[int, ...] = (
    # Web
    80, 443, 8080, 8443, 8000, 8888, 8081, 8082, 9000, 9090, 9080,
    # 远程管理
    22, 3389, 5900, 5985, 5986, 23, 513,
    # 数据库
    3306, 5432, 6379, 27017, 1433, 1521, 11211, 9200, 9300,
    # 中间件与消息队列
    8086, 8161, 5672, 15672, 2181, 9092, 8083,
    # 文件与目录服务
    21, 445, 139, 2049, 873,
    # 邮件
    25, 110, 143, 465, 587, 993, 995,
    # 容器与编排
    2375, 2376, 6443, 10250, 10255,
    # 其他常见
    161, 389, 636, 111, 135, 53, 123, 1900, 5000, 7001, 7002,
)

#: 需要主动发 HTTP 请求才能拿到 banner 的端口
HTTP_LIKE_PORTS: frozenset[int] = frozenset(
    {80, 443, 8080, 8443, 8000, 8888, 8081, 8082, 9000, 9090, 9080,
     8086, 8161, 15672, 9200, 9300, 5000, 7001, 7002, 10250}
)

DEFAULT_TIMEOUT = 3.0
BANNER_READ_TIMEOUT = 2.0
MAX_BANNER_BYTES = 8192


# --------------------------------------------------------------- 服务指纹


@dataclass(slots=True)
class ServiceRule:
    """一条服务识别规则。

    `pattern` 里用命名组提取产品与版本，例如：

        SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        → product=OpenSSH  version=8.2p1
    """

    name: str
    pattern: re.Pattern[str]
    product_group: str = "product"
    version_group: str = "version"


#: 服务识别规则表。
#:
#: 顺序有意义：**先匹配特征最强的**。比如 HTTP 响应里也可能出现 "Apache"、
#: "MySQL" 之类的字样（错误页里），所以先把带明确协议标识的规则放前面。
SERVICE_RULES: tuple[ServiceRule, ...] = (
    # ---- 应用层协议，banner 自带协议名，最可靠 ----
    ServiceRule(
        "ssh",
        re.compile(r"^SSH-(?P<proto>[\d.]+)-(?P<product>[\w.-]+)_(?P<version>[\w.\-p]+)", re.M),
    ),
    ServiceRule(
        "ftp",
        re.compile(r"^(?:220[- ].*?)?(?P<product>vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Microsoft FTP)[/ ]?(?P<version>[\d.p]+)?", re.I | re.M),
    ),
    ServiceRule(
        "smtp",
        re.compile(r"^220[- ].*?(?P<product>Postfix|Exim|Sendmail|Exchange|hMailServer)", re.I | re.M),
    ),
    ServiceRule(
        "mysql",
        # MySQL 握手包结构：\x0a + 版本字符串 + \x00 + 连接ID(4 字节) + ... + 认证插件名
        # 中间会夹非控制字节（连接 ID 可能含任意值），所以必须允许任意字节，
        # 用「.{0,60}?」而不是「[\x00-\x1f]*」—— 后者是实测踩到的坑：
        # 规则写太严会匹配不上，然后这个包就被更宽松的 telnet 规则捞走了。
        re.compile(
            r"\x0a(?P<version>\d+\.\d+\.\d+).{0,60}?"
            r"(?P<product>mysql_native_password|caching_sha2_password|MariaDB)",
            re.S,
        ),
    ),
    ServiceRule(
        "redis",
        re.compile(r"^-ERR unknown command.*?(?P<product>redis)", re.I | re.M),
    ),
    ServiceRule(
        "redis",
        re.compile(r"(?P<product>redis_version):(?P<version>[\d.]+)", re.I),
    ),
    ServiceRule(
        "telnet",
        # ⚠️ 这条规则必须严格限定为「行首就是登录提示」。
        # 最初的版本写的是 `^(?:.*?(?:login|password))`，结果 MySQL 握手包里的
        # "mysql_native_password" 命中了它 —— 3306 端口被报成 telnet。
        # 教训：兜底型规则越宽松，造成的误报越难排查（因为看起来"确实匹配到了"）。
        re.compile(r"^(?:Username:|login:|Password:|Welcome to .{0,40}login)", re.I | re.M),
    ),
    ServiceRule(
        "vnc",
        re.compile(r"^RFB (?P<version>\d{3}\.\d{3})", re.M),
    ),
    ServiceRule(
        "mongodb",
        re.compile(r"(?P<product>mongodb|MongoDB)", re.I),
    ),
    ServiceRule(
        "memcached",
        re.compile(r"^(?P<version>\d+\.\d+\.\d+)$", re.M),
    ),
    # ---- HTTP 响应头中的 Server 字段 ----
    ServiceRule(
        "http",
        re.compile(
            r"Server:\s*(?P<product>nginx|Apache(?:/[\d.]+)?|Microsoft-IIS|Tomcat|Jetty|Caddy|gunicorn|uvicorn|Kestrel|lighttpd|openresty)"
            r"(?:[/ ](?P<version>[\d.\w\-]+))?",
            re.I,
        ),
    ),
    ServiceRule(
        "http",
        re.compile(r"Server:\s*(?P<product>[\w./\-]+)(?:[/ ](?P<version>[\d.]+))?", re.I),
    ),
    # ---- 兜底：至少识别出是 HTTP ----
    ServiceRule("http", re.compile(r"^HTTP/1\.[01] \d{3}", re.M)),
    # ---- 其他端口的粗粒度判断 ----
    ServiceRule("smb", re.compile(r"(?P<product>SMB|Samba)", re.I)),
    ServiceRule("rdp", re.compile(r"(?P<product>Remote Desktop|RDP|TermDD)", re.I)),
    ServiceRule("ldap", re.compile(r"(?P<product>LDAP)", re.I)),
)


@dataclass(slots=True)
class ServiceInfo:
    """识别出的服务信息。"""

    name: str = ""
    product: str = ""
    version: str = ""
    evidence: str = ""
    """命中依据（规则名 + 匹配到的片段），用于人工复核。"""

    @property
    def display(self) -> str:
        """人类可读的描述。"""
        if not self.name:
            return "unknown"
        if self.product and self.version:
            return f"{self.name} ({self.product} {self.version})"
        if self.product:
            return f"{self.name} ({self.product})"
        return self.name


def fingerprint_service(banner: str) -> ServiceInfo:
    """从 banner 中识别服务。

    逐条尝试规则，命中即返回 —— 先匹配到的规则优先级最高（规则表已按可靠性排序）。
    """
    if not banner:
        return ServiceInfo()

    for rule in SERVICE_RULES:
        match = rule.pattern.search(banner)
        if not match:
            continue

        groups = match.groupdict()
        product = (groups.get(rule.product_group) or "").strip()
        version = (groups.get(rule.version_group) or "").strip()

        # 兜底规则可能匹配到 "Server: xxx" 里任意值，做个长度保护
        if len(product) > 64:
            product = product[:64]

        return ServiceInfo(
            name=rule.name,
            product=product,
            version=version,
            evidence=f"{rule.name}:{match.group(0)[:80].strip()}",
        )

    return ServiceInfo()


# ------------------------------------------------------------------ 端口解析


def parse_ports(spec: str | Sequence[int] | None) -> list[int]:
    """解析端口表达式。

    支持的写法：
        "80"              → [80]
        "80,443"          → [80, 443]
        "1-1024"          → [1..1024]
        "22,80,8000-8010" → 混合
        "top" 或 None     → 内置常见端口表
        "all"             → 1..65535

    Raises:
        ValueError: 端口超范围或表达式非法。
    """
    if spec is None:
        return list(TOP_PORTS)
    if isinstance(spec, (list, tuple, set)):
        return sorted({int(p) for p in spec})

    text = str(spec).strip().lower()
    if text in ("top", "common", ""):
        return list(TOP_PORTS)
    if text == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"端口超出 1-65535 范围: {sorted(invalid)[:5]}")
    return sorted(ports)


# ------------------------------------------------------------------ 扫描


@dataclass(slots=True)
class PortResult:
    """单个端口的扫描结果。"""

    host: str
    port: int
    state: str = "closed"
    """``open`` / ``closed`` / ``filtered`` / ``error``。"""

    banner: str = ""
    service: ServiceInfo = field(default_factory=ServiceInfo)
    elapsed: float = 0.0
    error: str = ""

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "state": self.state,
            "service": self.service.name,
            "product": self.service.product,
            "version": self.service.version,
            "banner": self.banner[:200],
            "elapsed": round(self.elapsed, 3),
            "error": self.error,
        }


async def _read_banner(
    reader: asyncio.StreamReader, timeout: float = BANNER_READ_TIMEOUT
) -> str:
    """读取服务端 banner。

    「读到一点就返回」而不是「读满才返回」：很多服务发完 banner 就等待输入，
    如果一直等到 EOF 会白等一个完整超时。
    """
    try:
        chunk = await asyncio.wait_for(reader.read(MAX_BANNER_BYTES), timeout)
    except (TimeoutError, ConnectionError, OSError):
        return ""
    return chunk.decode("utf-8", errors="ignore")


async def _probe_http(
    writer: asyncio.StreamWriter, reader: asyncio.StreamReader, host: str, port: int
) -> str:
    """对疑似 HTTP 端口主动发请求。

    Host 头用实际 host：虚拟主机环境下不同的 Host 会返回不同站点，
    用 IP 可能拿到默认站点甚至直接 404，导致指纹失真。
    """
    request = (
        f"GET / HTTP/1.0\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (compatible; ASP/0.1)\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        writer.write(request.encode())
        await writer.drain()
    except (ConnectionError, OSError):
        return ""
    return await _read_banner(reader)


async def scan_port(
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    grab_banner: bool = True,
) -> PortResult:
    """扫描单个端口。

    三态区分很重要：
    - ``closed``：收到 RST，端口明确关闭
    - ``filtered``：超时无响应，通常意味着被防火墙丢包
    - ``error``：本机层面的错误（如文件描述符耗尽、DNS 失败）

    把 ``filtered`` 和 ``closed`` 混为一谈，会让人误以为「没有服务」，
    而实际上可能是「有服务但被防火墙挡了」—— 这两者的处置方式完全不同。
    """
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout
        )
    except TimeoutError:
        return PortResult(host, port, "filtered", elapsed=time.monotonic() - started,
                          error="连接超时（可能被防火墙过滤）")
    except (ConnectionRefusedError, ConnectionResetError):
        return PortResult(host, port, "closed", elapsed=time.monotonic() - started)
    except socket.gaierror as exc:
        return PortResult(host, port, "error", elapsed=time.monotonic() - started,
                          error=f"域名解析失败: {exc}")
    except OSError as exc:
        # Windows 上连接被拒可能是 ConnectionRefusedError 的包装，统一按 closed 处理
        state = "closed" if getattr(exc, "winerror", None) in (10061, 10054) else "error"
        return PortResult(host, port, state, elapsed=time.monotonic() - started, error=str(exc))

    banner = ""
    try:
        if grab_banner:
            # 阶段 1：静默读（SSH/FTP/SMTP 这类会主动发 banner）
            banner = await _read_banner(reader, min(BANNER_READ_TIMEOUT, timeout))

            # 阶段 2：没读到内容且端口像 HTTP，就主动发请求
            if not banner and port in HTTP_LIKE_PORTS:
                banner = await _probe_http(writer, reader, host, port)
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except (TimeoutError, ConnectionError, OSError):
            pass

    return PortResult(
        host=host,
        port=port,
        state="open",
        banner=banner,
        service=fingerprint_service(banner),
        elapsed=time.monotonic() - started,
    )


async def scan_host(
    host: str,
    ports: Iterable[int] | None = None,
    *,
    concurrency: int = 200,
    timeout: float = DEFAULT_TIMEOUT,
    grab_banner: bool = True,
    progress_every: int = 200,
) -> list[PortResult]:
    """并发扫描一台主机的多个端口。

    并发策略：用一个全局信号量而不是「分批 gather」。
    分批会在批次边界产生等待毛刺 —— 每批里最慢的端口会拖住整批的收尾。

    Args:
        host: 目标主机（IP 或域名）。
        ports: 端口列表，None 则用内置常见端口表。
        concurrency: 同时进行的连接数上限。
        timeout: 单端口连接超时。
        grab_banner: 是否抓取 banner 并做服务识别。
        progress_every: 每完成多少个端口输出一次进度（0 表示不输出）。

    Returns:
        按端口号排序的结果列表（只包含 open / error 状态，closed 会被过滤）。
    """
    port_list = list(ports) if ports is not None else list(TOP_PORTS)
    if not port_list:
        return []

    started = time.monotonic()
    semaphore = asyncio.Semaphore(concurrency)
    completed = 0
    lock = asyncio.Lock()

    async def _run(port: int) -> PortResult:
        nonlocal completed
        async with semaphore:
            result = await scan_port(host, port, timeout=timeout, grab_banner=grab_banner)
        async with lock:
            completed += 1
            if progress_every and completed % progress_every == 0:
                logger.info(
                    "portscan_progress host=%s done=%d/%d open=%d",
                    host, completed, len(port_list), open_count[0],
                )
        if result.is_open:
            async with lock:
                open_count[0] += 1
        return result

    open_count = [0]
    results = await asyncio.gather(*(_run(p) for p in port_list))

    # 只保留 open 与 error（closed 是绝大多数，没必要都返回）
    interesting = [r for r in results if r.state in ("open", "error")]
    interesting.sort(key=lambda r: r.port)

    elapsed = time.monotonic() - started
    logger.info(
        "portscan_done host=%s scanned=%d open=%d closed=%d filtered=%d elapsed=%.2fs",
        host,
        len(port_list),
        sum(1 for r in results if r.state == "open"),
        sum(1 for r in results if r.state == "closed"),
        sum(1 for r in results if r.state == "filtered"),
        elapsed,
    )
    return interesting


__all__ = [
    "PortResult",
    "ServiceInfo",
    "ServiceRule",
    "SERVICE_RULES",
    "TOP_PORTS",
    "HTTP_LIKE_PORTS",
    "scan_port",
    "scan_host",
    "parse_ports",
    "fingerprint_service",
]
