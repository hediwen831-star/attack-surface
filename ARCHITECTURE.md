# 架构与技术栈详解

> 这份文档回答三个问题：**用了什么**、**为什么用它**、**核心逻辑是怎么跑的**。
>
> 设计取舍的论证过程，基本都在这里。

---

## 一、技术栈总表

### 1.1 运行时与语言

| 技术 | 版本要求 | 用在哪 | 为什么是它 |
|---|---|---|---|
| **Python** | ≥ 3.11 | 全部 | 见 [3.1](#31-为什么用-asyncio-而不是多线程) |
| **asyncio** | 标准库 | 全部 IO 路径 | 测绘是极端 IO 密集型任务 |
| **sqlite3** | 标准库 | 数据持久化 | 零配置，单文件，WAL 支持读写并发 |

**为什么要求 3.11 而不是更低的版本？**

代码里用到了几个 3.11+ 才稳定的特性：

```python
from __future__ import annotations        # 3.7+，但配合 dataclass 的类型解析在 3.11 才无歧义

@dataclass(slots=True)                      # 3.10+，省内存
class DiscoveredAsset: ...

x: str | None = None                        # 3.10+ 的联合类型语法
```

另外 3.11 的 asyncio 有显著的性能改进（任务创建开销降低约 60%），
对「几千个并发协程」的场景是实打实的收益。

### 1.2 第三方依赖（运行时只有 3 个）

| 依赖 | 用途 | 为什么不用替代方案 |
|---|---|---|
| **httpx** ≥ 0.27 | 异步 HTTP 客户端 | 见 [3.2](#32-为什么用-httpx-而不是-aiohttp-requests) |
| **SQLAlchemy** ≥ 2.0 | ORM 与查询构建 | 见 [3.4](#34-为什么用-orm-而不是手写-sql) |
| **PyYAML** ≥ 6.0 | PoC 文件解析 | 事实标准，无可替代 |

**刻意没有引入的东西**（这是有意识的选择，不是遗漏）：

| 没用的 | 本来可以解决什么 | 为什么不用 |
|---|---|---|
| `click` / `typer` | CLI 参数解析 | `argparse` 是标准库，能力足够；少一个依赖就少一次现场装包事故 |
| `aiohttp` | HTTP | httpx 的 API 更现代，且同时支持同步/异步 |
| `aiodns` | 异步 DNS | 需要编译 c-ares，Windows 上安装容易翻车 |
| `tabulate` / `rich` | 表格与终端美化 | 自研表格输出对 CJK 宽字符的对齐控制更精确（见下） |
| `pydantic` | 配置校验 | 手写校验逻辑更透明，且避免 pydantic v1/v2 的迁移坑 |
| `numpy` / `pandas` | 数据分析 | 用不上。为了「显得专业」引入重型依赖是负分 |
| `loguru` | 日志 | 标准库 `logging` 配自定义 Formatter 足够 |

> **关于表格对齐**：`tabulate` 这类库按字符数计算宽度，
> 但中文在终端里占 2 列而 ASCII 占 1 列，导致中文表格永远对不齐。
> 自研的 `_pad()` 按 `ord(ch) > 0x2E80` 判断宽字符，实际效果见 README 的截图。

### 1.3 开发与质量工具

| 工具 | 用途 | 配置位置 |
|---|---|---|
| **pytest** ≥ 8.0 | 单元测试（112 个用例） | `pyproject.toml` |
| **pytest-asyncio** | 异步测试支持 | `asyncio_mode = "auto"` |
| **ruff** | lint + 部分格式化 | `[tool.ruff]`，零告警 |
| **GitHub Actions** | CI（3 个 Python 版本矩阵） | `.github/workflows/ci.yml` |
| **setuptools + pyproject.toml** | 打包（PEP 621） | `[project]` 段 |
| **Docker / Docker Compose** | 隔离部署 | `Dockerfile` |

### 1.4 外部数据源与协议

| 来源 | 协议 | 性质 | 局限 |
|---|---|---|---|
| **crt.sh** | HTTPS + JSON | **被动**（不触碰目标） | 滞后于证书签发；高负载时返回 HTML 错误页 |
| **DNS** | UDP/TCP 53 | **主动**（会查目标权威 DNS） | 查询量 = 字典大小，必须限速 |
| **目标 HTTP 服务** | HTTP/HTTPS | 主动 | 必须遵守限速与 Robot 礼仪 |

---

## 二、架构分层

```
┌──────────────────────────────────────────────────────────────────────┐
│  表现层  cli.py                                                       │
│  subdomain │ diff │ poc list │ poc run │ init                        │
│  职责：参数解析、输出格式化（表格/JSON）、退出码语义化                    │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ 调用
┌────────────────────────────▼─────────────────────────────────────────┐
│  编排层  services/subdomain.py                                        │
│  职责：多源并发调度 → 聚合去重 → 解析验证 → 持久化 → 变更 diff           │
│  这一层不关心「怎么发现」，只关心「怎么把发现的结果组织好」                 │
└───────┬──────────────────────────────────────────┬───────────────────┘
        │                                          │
┌───────▼──────────────────┐          ┌────────────▼────────────────────┐
│  能力层  discover/        │          │  能力层  plugins/               │
│                          │          │                                │
│  Source (ABC)            │          │  loader.py   YAML → PoC 对象     │
│   ├ CrtshSource          │          │  matchers.py 匹配器 + 提取器     │
│   └ BruteForceSource     │          │              + 白名单 DSL        │
│       └ 泛解析基线检测    │          │  engine.py   执行 + 负向对照     │
│                          │          │                                │
│  新增源 = 实现 fetch()    │          │  新增检测 = 写一个 YAML          │
└───────┬──────────────────┘          └────────────┬────────────────────┘
        │                                          │
        └──────────────────┬───────────────────────┘
                           │ 依赖
┌──────────────────────────▼───────────────────────────────────────────┐
│  基础设施层  core/                                                    │
│                                                                      │
│  http.py        AsyncHttpClient —— 令牌桶限速 + 信号量并发 + 退避重试   │
│  database.py    七张表 ORM 模型 + WAL 配置                            │
│  config.py      配置加载 / 强校验 / 环境变量覆盖                       │
│  logger.py      结构化日志                                            │
│  exceptions.py  异常树（区分可重试与不可重试）                          │
└──────────────────────────────────────────────────────────────────────┘
```

**分层的实际收益**：新增一个资产源，只需要在 `discover/` 下写一个类实现 `fetch()`，
然后在 `SOURCE_REGISTRY` 里注册一行 —— 编排层、CLI、日志、去重、落库全部自动生效。

---

## 三、关键技术决策

### 3.1 为什么用 asyncio 而不是多线程

**任务特征**：一次子域名收集要发几百次 DNS 查询 + 几十次 HTTP 请求，
每次耗时几十到几千毫秒，**几乎全是在等**。

| 维度 | 多线程 | asyncio |
|---|---|---|
| 单任务内存 | 线程栈约 1 MB（默认） | 协程约几 KB |
| 200 并发内存 | ~200 MB | ~1 MB |
| 上下文切换 | 内核态调度，有成本 | 用户态，几乎免费 |
| 超时控制 | 需要额外的机制 | `asyncio.wait_for` 天然支持 |
| 取消传播 | 笨拙 | `Task.cancel()` 自动向上冒泡 |
| 调试体验 | 栈回溯清晰 | **较差**（这是真实代价） |

**踩过的坑**：asyncio 里任何同步阻塞调用都会拖垮整个事件循环。
所以 DNS 解析用的是 `loop.getaddrinfo()`（内部走线程池）而不是自己写 socket ——
标准库已经把这个坑填好了，没必要重造。

**为什么要显式写 `strict=False`**：Python 3.10+ 的 `zip()` 支持 `strict` 参数，
默认 False 表示「按短的截断」。在 DSL 连接符那里，`connectors` 天然比 `predicates` 少一个
（N 个谓词有 N-1 个连接符），截断是**设计意图**而非 bug。显式写出来是为了让读代码的人
不用去数长度，也为了让 ruff 的 B905 规则闭嘴。

### 3.2 为什么用 httpx 而不是 aiohttp / requests

| 方案 | 问题 |
|---|---|
| `requests` | 同步阻塞，在 asyncio 里会卡死事件循环 |
| `aiohttp` | 能力没问题，但 API 设计偏底层；且它的 ClientSession 生命周期管理容易出错 |
| **`httpx`** | 同一套 API 同时支持同步与异步；超时/重试/SSL 配置更直观；对 HTTP/2 有支持 |

实际选它的决定性理由：**调试成本**。
出问题时能直接把 `async with httpx.AsyncClient(...)` 换成 `httpx.Client(...)` 复现，
不需要重写请求逻辑。

### 3.3 为什么自研 DSL 而不用 `eval`

这是整个项目**最重要的一条安全决策**。

一个检测引擎里最容易埋雷的地方就是「让用户写表达式」。如果用 `eval()` 执行 YAML 里的条件，
我们加载的就不是数据，而是**任意代码** —— 任何一条从社区下载的 PoC 都能在你机器上执行命令。

**「一个安全工具自身有 RCE」是最难看的漏洞。**

所以实现的是一套**白名单语法的小解析器**，只认四种谓词：

```
status == 200                       比较运算符：== != > < >= <=
contains(body, 'root:')             子串包含
len(body) > 1024                    长度比较
regex(header, 'Server: .*nginx')    正则匹配
```

实现方式是用正则精确匹配每种谓词的**完整形态**，匹配不上就抛 `PluginError`：

```python
_DSL_PREDICATES = [
    (re.compile(r"^status\s*(==|!=|>=|<=|>|<)\s*(\d+)$"), ...),
    (re.compile(r"^contains\(\s*(\w+)\s*,\s*['\"](.+?)['\"]\s*\)$", re.DOTALL), ...),
    ...
]
```

**没有任何路径能构造出任意 Python 表达式。** 这条边界由测试 `test_dsl_rejects_non_whitelisted_syntax` 守着：

```python
dangerous = [
    "__import__('os').system('id')",
    "eval('1+1')",
    "open('/etc/passwd').read()",
    "(lambda: 1)()",
]
for expression in dangerous:
    with pytest.raises(PluginError):
        match_dsl({"dsl": [expression]}, make_response())
```

**表达能力受限是安全特性，不是缺陷。**

### 3.4 为什么用 ORM 而不是手写 SQL

这个项目的数据模型天然是关系型的：一个域名 → 多个 IP → 多个端口 → 多个服务 → 多个组件 → 多个漏洞。
用 ORM 换来的好处：

1. **表结构即代码** —— 改模型就改一个类，不用同步维护建表 SQL 和查询语句
2. **`cascade="all, delete-orphan"`** —— 删除一个任务自动清掉它的全部关联资产，不会留孤儿数据
3. **查询构建器** —— `diff_tasks()` 里那句 `select(...).where(...).order_by(...).limit(...)` 是编译期可查的

代价是 ORM 有学习成本和少量性能开销。但对这个量级（万级资产）完全不是瓶颈，
且换来的是「三个月后还能看懂自己的代码」。

### 3.5 为什么 SQLite 要开 WAL

```python
cursor.execute("PRAGMA journal_mode=WAL")
```

默认的 journal 模式是「写的时候读被阻塞」。而扫描器的实际使用场景是：

```
扫描进程持续写入资产  ←→  前端/CLI 同时在读进度与结果
```

WAL（Write-Ahead Logging）允许**读写并发**：
写操作进 WAL 文件，读操作读主库 + WAL，两者互不阻塞。

另外两条 PRAGMA 也有理由：
- `synchronous=NORMAL` —— 扫描数据丢一两条无所谓，换来数倍写入速度
- `foreign_keys=ON` —— SQLite **默认不启用外键约束**，不显式打开的话 `ForeignKey` 声明是装饰品

### 3.6 为什么配置文件要「未知字段直接报错」

```python
unknown = set(raw) - known
if unknown:
    raise ConfigError("配置中存在未知字段", unknown=sorted(unknown), allowed=sorted(known))
```

很多配置系统对拼错的 key 是静默忽略的。于是用户写了 `concurency: 300`（拼错），
程序用默认值 100 跑了一小时，谁也不知道为什么没生效。

**拼错的配置应该立刻炸掉，而不是静默降级。**

### 3.7 为什么异常要分「可重试」和「不可重试」

```python
class AspError(Exception):
    retryable: bool = False

class SourceTimeoutError(SourceError):
    retryable = True          # 超时 → 值得重试

class RateLimitError(HttpError):
    retryable = True          # 限速 → 退避后重试

class PoCParseError(PluginError):
    ...                       # YAML 写错了 → 重试一万次还是错
```

这个字段让调度器能做决策：**该重试的重试，该放弃的立刻放弃**。
把「网络抖动」和「配置写错」都当成同一种「失败」，是很多脚本型工具的常见毛病。

---

## 四、核心算法原理

### 4.1 泛解析（Wildcard DNS）检测与过滤

**问题**：如果域名配置了

```
*.example.com.    IN    A    1.2.3.4
```

那么 `anything-random-xyz.example.com` 也能解析成功。用 364 个词的字典爆破，
会得到 364 条「存在」的结论 —— 全是假资产。报告里混进几百条垃圾，等于报告不可用。

**算法**：

```
步骤 1  生成 3 个随机标签：asp-probe-a1b2c3 / asp-probe-d4e5f6 / asp-probe-g7h8i9
步骤 2  并发解析这 3 个一定不存在的域名
步骤 3  统计每个 IP 被多少个随机域名解析到
步骤 4  若某 IP 被 ≥ 2 个随机域名解析到 → 判定为泛解析，记入 wildcard_ips
步骤 5  爆破时，解析结果【全部落在】wildcard_ips 内 → 丢弃
```

**为什么阈值是 ≥2 而不是 ≥1？**

单个随机域名偶然解析成功，可能是运营商 DNS 劫持 ——
国内校园网/运营商经常把不存在的域名劫持到广告页。
要求两个**独立的**随机域名命中**同一个** IP，才能排除这种偶发噪声。

**为什么判定用 `issubset` 而不是 `isdisjoint`？**

考虑这个情况：

```
mail.example.com  →  {1.2.3.4 (泛解析IP), 5.6.7.8 (真实记录)}
```

| 判定方式 | 结果 | 后果 |
|---|---|---|
| `isdisjoint`（无交集才保留） | 与泛解析集合有交集 → **丢弃** | ❌ **漏掉一条真实资产** |
| `issubset`（全部在集合内才丢弃） | 并非全部在集合内 → **保留** | ✅ 正确 |

```python
if self.wildcard_ips and ips.issubset(self.wildcard_ips):
    return None      # 全部 IP 都是泛解析产生的 → 丢弃
return asset         # 有真实 IP → 保留
```

**宁可多留一条假资产让人工复核，也不漏掉一条真实资产。**
误报可以筛掉，漏报没法补救 —— 这是安全工具的基本态度。

**已知局限**（诚实写在代码注释和 README 里）：
- 只检测顶层泛解析。若只有 `*.sub.example.com` 是泛解析（两级），当前实现不覆盖
- CDN 场景：泛解析与真实记录都指向同一 CDN 时，用 `issubset` 会误杀真实资产。
  业界解法是叠加 HTTP 响应内容差异比对，本项目未实现

### 4.2 负向对照校验（Negative Control）

**问题**：很多站点对所有路径都返回 200 + 同一个页面（SPA 的 index.html 回退、
自定义 404、WAF 拦截页）。此时一个只写了 `status: [200]` 的 PoC 会命中**所有** URL。

**解法**：命中之后，再发一个请求到**同目录下的随机路径**做对照。

```
命中的是: GET /admin/config.php      → 200 + "[core]"
对照请求: GET /admin/asp-ctl-a1b2c3  → 200 + "[core]"    ← 同样命中
                                              ↓
                       对照也命中 → 这是「页面的通用特征」而非「该路径的特殊特征」
                                              ↓
                                        判定为误报，丢弃
```

对照 URL 的关键设计：**保留目录，只替换最后一段**。

```python
def _random_control_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path
    directory = path.rsplit("/", 1)[0] if "/" in path.rsplit("?", 1)[0][1:] else ""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{parsed.scheme}://{parsed.netloc}{directory}/{CONTROL_PREFIX}{suffix}"
```

为什么要同目录：如果应用有「统一 200 回退」，对照请求也会落到同一个路由上，
从而暴露误报。如果对照请求打到根目录，可能被完全不同的处理逻辑接住，对照就失去意义了。

这一步把结论从「这个特征出现了」升级为「这个特征**只在这个路径**出现」。

**代价**：对照请求会让流量翻倍。所以留了 `--no-control` 开关，
对脆弱目标可以关掉（代价是误报增多）。

### 4.3 白名单 DSL 的解析流程

```
输入: "status == 200 && contains(body, 'uid=')"

步骤 1  按 && / || 切分（保留分隔符）
        → predicates: ["status == 200", "contains(body, 'uid=')"]
        → connectors: ["&&"]

步骤 2  逐个谓词去白名单里匹配
        "status == 200"            → 命中第 1 条规则 → 求值
        "contains(body, 'uid=')"   → 命中第 2 条规则 → 求值

步骤 3  用连接符组合结果（左到右求值）
        True && True → True

若任一步骤匹配不上 → 抛 PluginError，并把支持的语法列出来
```

**为什么用左到右求值而不是实现完整的运算符优先级？**

PoC 的可读性比 DSL 的表达能力更重要。真有复杂逻辑，应该拆成多个 matcher 用
`matchers-condition: and/or` 组合 —— 那样读起来更清楚，也能逐个看到命中证据。

### 4.4 置信度分级

单纯返回 `True/False` 的信息量太低。报告里 30 条「存在漏洞」，
用户不知道先从哪条看起。

```python
if condition == "and":
    confidence = 1.0                              # 多重独立特征同时成立
else:
    ratio = len(hits) / len(results)
    confidence = round(min(0.8, 0.4 + ratio * 0.4), 2)   # 单项命中上限 0.8
```

**为什么 `or` 条件下单个匹配器命中时上限是 0.8？**

因为单一特征（尤其单个关键词）的误报率显著高于多特征组合。
本项目的 Swagger PoC 就是活生生的例子：只匹配关键词 `swagger` 时误报了 3 次
（因为 404 页面回显了请求路径）。

实测的三级置信度：

```
1.00  vulnlab-sqli-low-union      ← status + word + negative 三重条件全中
0.80  sql-injection-error-based   ← or 条件单条命中
0.60  （修复前的 swagger PoC）      ← or 条件命中 2/5
```

**给结论附上「我有多确定」，比给一个武断的布尔值有用得多。**

### 4.5 资产变更 diff

```python
current  = 本次任务的资产集合
baseline = 上次任务的资产集合

added     = current - baseline      # 新增资产 → 可能是新上线的服务，要关注
removed   = baseline - current      # 消失的资产 → 可能是下线，也可能是宕机
unchanged = current & baseline
```

**为什么要保留历史快照而不是每次覆盖？**

因为「一次扫描的快照」和「持续的资产变化监控」是两种完全不同的产品能力。
前者只能回答「现在有什么」，后者能回答「**相比上次，多了什么**」——
而新增资产往往正是最需要关注的（新上线的服务、临时开的后门端口）。

---

## 五、数据模型

```
ScanTask ──< Asset ──< Port ──< Service ──< Component ──< Vuln
   │
   └─ 每次扫描一条记录，是 diff 的基础
```

| 表 | 核心字段 | 设计说明 |
|---|---|---|
| `scan_task` | target / status / started_at / stats(JSON) | 状态机 `pending → running → success/failed/cancelled`，支持断点续跑 |
| `asset` | type / value / root_domain / resolved_ip / source / fingerprint | **域名和 IP 共用一张表** + `type` 区分；`fingerprint` = `sha256(type:normalized_value)[:32]` 用于跨任务去重 |
| `port` | number / protocol / state / banner | **保留原始 banner** —— 它是指纹识别的一手材料，丢失后无法回溯 |
| `service` | name / product / version / http_title / favicon_hash | `favicon_hash` 是识别同源系统的强特征 |
| `component` | name / version / category / confidence / evidence | `confidence` 支持多规则累加 —— 单一弱特征不该直接判定 |
| `vuln` | poc_id / severity / target / matched_at / evidence / confidence / verified | **`evidence` 必须存** —— 报告里拿不出证据的漏洞等于没发现 |

**为什么域名和 IP 不拆两张表？**

它们共享大量属性（来源、首次发现时间、关联任务），拆开会导致大量重复逻辑。
`type` 字段足以区分，查询时加一个 `WHERE type = 'domain'` 就行。

---

## 六、代码规模与质量数据

| 指标 | 数值 |
|---|---|
| Python 源码 | 约 3,000 行（不含测试与文档） |
| 单元测试 | 112 个用例，约 1,250 行 |
| 测试是否依赖网络 | **否**，全部通过 monkeypatch 替换 DNS/HTTP |
| ruff 告警 | 0 |
| 运行时依赖 | 3 个 |
| CI | 3 个 Python 版本 × (lint + test + 打包校验) |
| 内置 PoC | 5 个（含带注释的模板） |
| 内置子域名字典 | 364 词 |

**为什么测试全部离线可跑？**

测绘工具天生依赖外部服务（crt.sh、DNS、目标站点）。
但**测试绝不能依赖** —— 否则 CI 会因为某个第三方站点抖动而变红，
红了三次之后就没人再信测试了，然后测试就成了摆设。

所以 DNS 与 HTTP 全部通过 `monkeypatch` 替换成可控的假实现。
比如泛解析过滤的测试，构造了一个「假 DNS 世界」：

```python
async def _resolve(hostname, timeout=5.0):
    if hostname == "mail.example.com":
        return {"1.2.3.4", "5.6.7.8"}    # 同时有泛解析 IP 和真实 IP
    if hostname.endswith(".example.com"):
        return {"1.2.3.4"}               # 泛解析兜底
    return set()

monkeypatch.setattr(bruteforce, "resolve_host", _resolve)
results = await source.fetch("example.com")
assert "mail.example.com" in values          # 真实资产保留
assert len(values) == 1                      # 泛解析假资产被全部过滤
```

---

## 七、与现有方案的关系

> 这一节的措辞是刻意保守的。**本项目不声称任何「首创」** ——
> 攻击面测绘、子域名枚举、YAML PoC 引擎都已有成熟方案。诚实说明差异，比夸大更有说服力。

### 7.1 同类项目（GitHub 实测数据，2026-09）

| 项目 | Stars | 定位 |
|---|---|---|
| [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | ★31,304 | YAML 模板驱动的漏洞扫描器（事实标准） |
| [owasp-amass/amass](https://github.com/owasp-amass/amass) | ★15,171 | 深度攻击面测绘与资产发现 |
| [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | ★14,440 | 被动的子域名枚举 |
| [1N3/Sn1per](https://github.com/1N3/Sn1per) | ★11,241 | 自动化渗透测试与 ASM 平台 |
| [OWASP/Nettacker](https://github.com/OWASP/Nettacker) | ★5,572 | 自动化渗透测试框架 |
| [jonrau1/ElectricEye](https://github.com/jonrau1/ElectricEye) | ★1,046 | 多云资产管理与安全配置审计 |
| [natlas/natlas](https://github.com/natlas/natlas) | ★660 | ASM 扫描与结果管理 |

### 7.2 本项目的真实定位

**不是「另一个扫描器」，而是「一个把扫描器内部机制完整实现出来的教学型平台」。**

功能覆盖度上，本项目远不如 amass 或 nuclei —— 这点必须承认。
它的价值在另外三个地方：

**① 每一层都自己能讲清楚**

用 amass 你只能回答「我用 amass 做了资产发现」。
用本项目你能回答「泛解析怎么判、为什么用 issubset 而不是 isdisjoint、
负向对照怎么设计、为什么 DSL 不能用 eval」——
**要的是后者。**

**② 自带可复现的评测基准（这是最稀缺的部分）**

搜索验证（2026-09，GitHub API）：

| 搜索词 | 命中仓库数 |
|---|---|
| `vulnerable application benchmark scanner` | **0** |
| `scanner evaluation benchmark web vulnerability` | **1**（★4） |

也就是说：**扫描器很多，漏洞靶场也很多（DVWA / bWAPP / juice-shop），
但把「靶场作为扫描器的效果评测基准」明确做出来的项目几乎没有。**

本项目的做法：靶场的 `high` 档（已修复）是天然的**误报诱饵** ——
扫描器若在这里报漏洞，说明它的判定逻辑有问题。

**一个只会说「到处都有漏洞」的扫描器，比什么都不报更糟。**
这句话有实测数据支撑：开发过程中本项目自己就在靶场上误报了 3 条。

**③ 零依赖约束下的完整实现**

运行时只有 3 个依赖，CLI 用标准库，DNS 用标准库，表格输出手写。
这不是「造轮子癖」，而是安全工具被部署到客户环境时的现实约束：
**少一个依赖就少一次「装不上」的现场事故。**

### 7.3 明确承认的局限

诚实地列出做不到的地方，比假装全能更可信：

- **规模**：单机 SQLite，未做过万级以上资产的压测
- **指纹库覆盖**：只有基础实现，没有 nuclei-templates 那样的社区规模
- **协议支持**：PoC 只支持 HTTP/DNS/TCP，没有 SMB / RDP 等内网协议的探测
- **泛解析**：只处理顶层，两级泛解析未覆盖
- **CDN 场景**：泛解析与真实记录指向同一 CDN 时会误杀
- **无分布式**：没有多节点协同扫描能力

---

## 八、延伸阅读

- [README.md](README.md) —— 项目概览与快速开始
- [docs/FAQ.md](docs/FAQ.md) —— 常见设计追问与回答要点
- 配套靶场 [vulnlab](../vulnlab) —— 作为本引擎的评测基准
