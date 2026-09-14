"""字典爆破资产源（含泛解析检测）。

## 为什么这个模块比看起来复杂

朴素实现是「读字典 → 逐个解析 → 解析成功的就记下来」。
这个实现在**配了泛解析的域名上会彻底失效**：

    # DNS 配置
    *.example.com.    IN    A    1.2.3.4

此时 ``anything.example.com`` 都能解析成功。
哪怕用 1 万个词的字典，也会得到 1 万条「存在」的结论 —— 全是误报。
攻击面报告里混进一万条垃圾资产，等于这份报告不可用。

## 泛解析检测算法

1. **基线探测**：随机生成 N 个一定不存在的子域名（如 ``asp-probe-7f3a2b``）
2. **解析基线**：并发解析这些随机域名
3. **判定**：若有 ≥2 个随机域名解析成功，且解析结果高度一致 → 判定存在泛解析
4. **记录基线**：把命中的 IP 集合存为 ``wildcard_ips``
5. **过滤**：爆破时，解析成功的域名若其 IP 全部落在 ``wildcard_ips`` 内 → 丢弃

## 已知局限（诚实说明，README 里也写）

- **只检测顶层泛解析**。若只有 ``*.sub.example.com`` 是泛解析（两级泛解析），
  需要递归到该层级再做一次基线检测。当前实现未覆盖。
- **泛解析 + 真实记录混用**：若泛解析指向 1.2.3.4，而 ``mail.example.com``
  真实指向 5.6.7.8，则 ``mail`` 会被正确保留（因为 IP 不在基线内）——这种情况处理正确。
- **CDN 场景**：泛解析指向 CDN，真实域名也走同一 CDN 时 IP 会重合，
  此时会误杀真实资产。业界做法是叠加 HTTP 响应差异比对，本项目暂未实现。
"""

from __future__ import annotations

import asyncio
import random
import socket
import string
from pathlib import Path

from ..logger import get_logger
from .base import DiscoveredAsset, Source

logger = get_logger("discover.bruteforce")

#: 探测泛解析用的随机标签数量。3 个是准确性与耗时的平衡点：
#: 1 个可能撞上偶然存在的域名，5 个收益递减但固定增加 5 次 DNS 查询。
WILDCARD_PROBE_COUNT = 3

#: 单次 DNS 查询超时（秒）。DNS 通常 50ms 内返回，5 秒足够。
DNS_TIMEOUT = 5.0

#: 内置常见子域名字典。放在代码里是为了「零配置即可运行」——
#: 演示和 CI 不该依赖外部字典文件的下载。
#:
#: 为什么用 `tuple(多行文本.split())` 而不是 list 字面量：
#: 字典是按经验持续维护的资产，自然文本形式可以直接阅读、增删、review，
#: 而 300 个带引号的字面量元素读起来是灾难。
BUILTIN_WORDLIST: tuple[str, ...] = tuple(
    """
www mail smtp pop pop3 imap webmail ns ns1 ns2
ns3 ns4 dns dns1 dns2 mx mx1 autodiscover autoconfig m
mobile wap h5 www1 www2 www3 www4 web web1 web2
api api1 api2 api3 open api-dev api-test apis gateway gw
app apps test testing test1 test2 dev development develop dev1
dev2 dev3 uat sit sit1 staging stage stg pre prod
production preprod release beta alpha demo sandbox lab admin administrator
manage manager management cp cpanel whm panel dashboard console oa
erp crm hr hrm finance caiwu kehu account accounts member
members user users login sso auth oauth auth2 id passport
sign signin signup register shop mall store market pay payment
wallet cashier order orders trade blog news forum bbs wiki
doc docs help support service services faq static static1 static2
assets res resource resources img images image pic pics pic1
photo photos upload uploads download downloads file files ftp ftps
sftp share nas storage disk drive cloud pan oss s3
cos backup bak backups video videos media stream live push
rtmp hls cdn cdn1 cdn2 edge cache db database mysql
mysql1 postgres postgresql oracle mssql redis mongodb mongo es elasticsearch
solr kafka rabbitmq mq mqtt zk zookeeper etcd consul git
gitlab github gitea svn repo repos code coding ci cd
jenkins hudson harbor nexus artifactory registry docker k8s kube kubernetes
swarm rancher monitor monitoring grafana prometheus zabbix nagios cacti kibana
log logs elk metric metrics status health healthz actuator actuator1
swagger redoc graphql soap rpc rmi dubbo thrift grpc ws
websocket socket intranet internal office work workbench workmail portal home
home1 my my1 vpn sslvpn openvpn ipsec remote rd nat
proxy lb haproxy nginx apache httpd tomcat jboss weblogic jetty
resin was websphere phpmyadmin pma adminer phpinfo server-status server-info jenkins2
sonar jira confluence bitbucket bamboo teamcity azure aws aliyun mail1
mail2 mail3 mail4 mail5 mail6 smtp1 smtp2 smtp3 pop1 imap1
mailgw mailgate mx2 mx3 spf dkim dmarc exchange owa ews
lync skype teams sharepoint onedrive sms notify notice message push1
push2 im chat room meeting conference campus edu learn study
train exam course class student teacher info data bi report
reports analytics stat stats tracking ad ads internal1 old new
new1 temp tmp tmp1
    """.split()  # noqa: C409, SIM905 - 见上方注释：多行文本形式更易维护
)



async def resolve_host(hostname: str, timeout: float = DNS_TIMEOUT) -> set[str]:
    """异步解析域名，返回 IP 集合。

    实现取舍：用标准库 ``loop.getaddrinfo`` 而非 ``aiodns``。
    - ``aiodns`` 需要编译 c-ares，Windows 上安装容易翻车
    - ``getaddrinfo`` 底层走线程池，虽然不是「真异步」，
      但 DNS 查询本身极快（通常 <50ms），实测 200 并发下不是瓶颈
    - 零额外依赖 → 别人 clone 下来就能跑，不用先配环境

    Args:
        hostname: 要解析的域名。
        timeout: 超时秒数。

    Returns:
        解析到的 IP 地址集合。失败或超时返回空集合（不抛异常）——
        「解析失败」在爆破场景里是常态，不该用异常表达。
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except (TimeoutError, socket.gaierror, OSError, UnicodeError):
        return set()
    return {info[4][0] for info in infos}


def _random_label(length: int = 10) -> str:
    """生成随机 DNS 标签。

    用 ``asp-probe-`` 前缀 + 随机串，而不是纯随机：
    这样万一真的产生了脏数据，域名管理员一看就知道是我们探测的 ——
    扫描器的基本礼貌，也避免被误认为是恶意域名生成算法（DGA）流量。
    """
    alphabet = string.ascii_lowercase + string.digits
    suffix = "".join(random.choices(alphabet, k=length))
    return f"asp-probe-{suffix}"


async def detect_wildcard(
    domain: str, *, probes: int = WILDCARD_PROBE_COUNT, concurrency: int = 20
) -> set[str]:
    """检测根域名是否存在泛解析，返回泛解析指向的 IP 集合。

    返回空集合表示不存在泛解析。

    Example:
        >>> await detect_wildcard("example.com")
        {'1.2.3.4'}      # 存在泛解析，指向 1.2.3.4
        set()            # 不存在泛解析
    """
    labels = [_random_label() for _ in range(probes)]
    hosts = [f"{label}.{domain}" for label in labels]

    semaphore = asyncio.Semaphore(concurrency)

    async def _probe(host: str) -> set[str]:
        async with semaphore:
            return await resolve_host(host)

    results = await asyncio.gather(*(_probe(h) for h in hosts))

    # 统计每个 IP 被多少个随机域名解析到
    counter: dict[str, int] = {}
    for ips in results:
        for ip in ips:
            counter[ip] = counter.get(ip, 0) + 1

    # 判定阈值：至少 2 个随机域名解析到同一 IP，才认定为泛解析。
    # 为什么不是 1 个？单个随机域名偶然解析成功可能是运营商 DNS 劫持
    # （国内校园网/运营商把不存在的域名劫持到广告页），
    # 要求 2 个以上同时命中同一 IP 才能排除这种偶发噪声。
    wildcard_ips = {ip for ip, hits in counter.items() if hits >= 2}

    if wildcard_ips:
        logger.warning(
            "wildcard_detected domain=%s ips=%s probes=%d",
            domain,
            ",".join(sorted(wildcard_ips)),
            probes,
        )
    else:
        logger.info("wildcard_absent domain=%s probes=%d", domain, probes)

    return wildcard_ips


def load_wordlist(path: str | Path | None) -> list[str]:
    """加载字典文件，为空则用内置字典。

    忽略空行与 ``#`` 注释行 —— 允许在字典里写注释是实用的小设计。
    """
    if path is None:
        return list(BUILTIN_WORDLIST)

    wordlist_path = Path(path)
    if not wordlist_path.exists():
        logger.warning("wordlist_missing path=%s fallback=builtin", wordlist_path)
        return list(BUILTIN_WORDLIST)

    words = []
    for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        words.append(line)
    return words or list(BUILTIN_WORDLIST)


class BruteForceSource(Source):
    """基于字典的 DNS 爆破源。

    与 ``CrtshSource`` 互补：
    - crt.sh 覆盖广但滞后（依赖证书签发）
    - 爆破实时性强，能发现刚部署、还没签证书的环境（如内网测试站）

    代价是**主动**行为 —— 会在目标 DNS 上留下查询记录，
    且查询量 = 字典大小。所以必须限速，且适合作为补充而非主力。
    """

    name = "brute"
    requires_network = True

    def __init__(
        self,
        config,
        client=None,
        *,
        wordlist: str | Path | None = None,
        concurrency: int | None = None,
        extra_ips: set[str] | None = None,
    ) -> None:
        """
        Args:
            config: 全局配置。
            client: 未使用（DNS 查询不走 HTTP）。保留是为了接口统一。
            wordlist: 字典路径，None 则用内置字典。
            concurrency: 并发数，None 则取配置里的 ``brute_concurrency``。
            extra_ips: 额外的泛解析 IP 集合（通常来自更强的检测方法，
                如 HTTP 响应体比对），与内置检测结果合并。
        """
        super().__init__(config, client)
        self.words = load_wordlist(wordlist)
        self.concurrency = concurrency or config.discover.brute_concurrency
        self.extra_ips = extra_ips or set()
        self.wildcard_ips: set[str] = set()

    async def fetch(self, domain: str) -> list[DiscoveredAsset]:
        """先做泛解析基线检测，再爆破。"""
        # 步骤 1：建立泛解析基线。
        # 注意：这一步必须在爆破之前 —— 顺序反了就没法过滤。
        self.wildcard_ips = await detect_wildcard(domain, concurrency=self.concurrency)
        self.wildcard_ips |= self.extra_ips

        logger.info(
            "brute_start domain=%s words=%d concurrency=%d wildcard_ips=%d",
            domain,
            len(self.words),
            self.concurrency,
            len(self.wildcard_ips),
        )

        # 步骤 2：并发爆破。
        # 用信号量而不是「分批 gather」：分批会在批次边界产生等待毛刺，
        # 信号量能让调度器始终跑满并发。
        semaphore = asyncio.Semaphore(self.concurrency)
        hosts = [f"{word}.{domain}" for word in dict.fromkeys(self.words)]

        async def _probe(host: str) -> DiscoveredAsset | None:
            async with semaphore:
                ips = await resolve_host(host)

            if not ips:
                return None

            # 步骤 3：泛解析过滤 —— 核心逻辑
            # 只有当「该域名解析出的所有 IP」都落在泛解析基线里，
            # 才判定为泛解析产生的假资产。
            # 用 issubset 而非 isdisjoint 的原因：
            # 若域名解析出 {泛解析IP, 真实IP} 两个地址，说明它同时有真实记录，
            # 应该保留（宁可多留，不可漏掉真实资产）。
            if self.wildcard_ips and ips.issubset(self.wildcard_ips):
                return None

            return DiscoveredAsset(
                value=host,
                source=self.name,
                type="domain",
                resolved_ip=sorted(ips)[0],
                metadata={"all_ips": ",".join(sorted(ips))},
            )

        results = await asyncio.gather(*(_probe(h) for h in hosts))
        alive = [item for item in results if item is not None]

        filtered = len(hosts) - len(alive)
        logger.info(
            "brute_done domain=%s probed=%d alive=%d filtered=%d",
            domain,
            len(hosts),
            len(alive),
            filtered,
        )
        return alive


__all__ = [
    "BruteForceSource",
    "detect_wildcard",
    "resolve_host",
    "load_wordlist",
    "BUILTIN_WORDLIST",
]
