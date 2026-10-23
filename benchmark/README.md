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

当前结果：6 个用例，泛解析判定 6/6，真实资产 10 个误杀 1 个（TPR 90%），
噪音 12 个漏过滤 0 个（FPR 0%）。

那 1 个误杀是 `wildcard-cdn-same-ip`：真实域名和泛解析指向同一 IP（CDN 场景），
纯 IP 比对分不出来。用例把它标成 `known_limitation: true`，不混进指标假装通过 ——
这条要等「HTTP 响应体比对」那层补上才能修。

六个用例分别对应六种失败模式：无泛解析、全泛解析、泛解析+真实记录混用、
CDN 同 IP 过杀、真实域名多 IP（必须用子集判断而非命中判断）、运营商劫持单点误判。

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
