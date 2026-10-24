# 基准与评测（attack-surface）

应用层的误报量化在 `vulnlab` 仓库（39 个用例的真值清单 + 评测框架）。
这里放**资产层**和**研判层**两块，回答的是不同问题：

| 目录 | 测什么 | 数据 |
|---|---|---|
| `asset/` | 泛解析条件下，子域名枚举保留/过滤得对不对 | `cases.yaml` 6 个 zone，离线假 DNS |
| `llm/` | LLM 研判能不能把误报挑出来 | 内置 6 条标注样本，可换真实模型 |

## 资产层：泛解析

```bash
python benchmark/asset/evaluate_asset.py
```

跑的是生产代码（`detect_wildcard` + `BruteForceSource.fetch`），只把 DNS 解析
换成按用例作答的假解析器。结果写到 `asset/results/`。

当前结果：8 个用例，泛解析判定 8/8，真实资产 11 个误杀 1 个（TPR 90.9%），
噪音 14 个漏过滤 0 个（FPR 0%）。

CDN 同 IP 的过杀已经修掉：`BruteForceSource` 在 IP 落在泛解析基线时，
会再抓一次候选和随机标签的 HTTP 指纹，页面不同就保留（`wildcard-cdn-same-ip` 通过）。
反向也做了保护：所有主机返回同一张默认页时照样过滤（`wildcard-cdn-uniform-page` 通过），
避免把噪音救回来。

还剩 1 个误杀是 `wildcard-cdn-http-down`：HTTP 探测不可用（端口关闭/超时）时
退回纯 IP 比对，同 IP 的真实域名会被误杀。这是刻意选的降级方向——
宁可少留，也不把整片噪音放进来。要彻底解决得靠被动指纹（证书 SAN）。

八个用例对应八种情况：无泛解析、全泛解析、泛解析+真实记录混用、CDN 同 IP（页面不同）、
CDN 同 IP（页面相同）、CDN 但 HTTP 不可用、真实域名多 IP、运营商劫持单点误判。

顺带修了一个本机才暴露的问题：HTTP 客户端默认会继承 `HTTP_PROXY`，连不上的端口
会返回代理的 502，看起来像「有响应」。现在 `http.trust_env` 默认关闭，
要挂 Burp 时显式打开。

## 研判层：LLM 降噪

```bash
# 无 key 时的启发式基线
python -m asp.cli triage --self-test --provider heuristic --json

# 接真实模型（DeepSeek / 通义等 OpenAI 兼容接口）
export ASP_LLM_API_KEY=...
export ASP_LLM_BASE_URL=https://api.deepseek.com/v1
export ASP_LLM_MODEL=deepseek-chat
python -m asp.cli triage --self-test --provider openai --json
```

内置样本上的基线（`llm/results/heuristic-self-test.json`）：
准确率 83.3%、覆盖率 83.3%、误报召回 3/3、真漏洞识别 2/3（1 条判为 uncertain）。

样本只有 6 条，说明不了统计显著性；真实模型那组数据要等 API key 到位后补。
