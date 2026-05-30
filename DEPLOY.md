# DEPLOY.md — 部署指南 / Deployment Guide

把 MirrorTrace（合规版）真正跑起来：5 个 Apify actor + Schedule + Webhook + 静态托管的 `web/`。

> **诚实前提**：真实抓取需要 **你自己的 Apify 账号**。本仓库不含任何凭据。
> 当前 workspace 已绑定 `roger_1of1`。`<APIFY_TOKEN>` 仍是占位符；真实 token 不入库。
> 没有真实账号时，你仍可本地跑 `web/index.html` 的展示与合规闸门（见 §6）。

---

## 0. 前置条件

- Node.js 18+（actor 用 Crawlee / Playwright）
- 一个真实 [Apify](https://console.apify.com) 账号
- `apify-cli`：

```bash
npm i -g apify-cli
apify --version
```

---

## 1. 登录 Apify

```bash
apify login
# 交互式：粘贴你的 Personal API token（来自 Apify Console → Settings → Integrations）
# 验证：
apify info
```

如果你在 CI/无交互环境，用环境变量代替交互登录：

```bash
export APIFY_TOKEN="<APIFY_TOKEN>"   # 替换为你自己的 token
```

---

## 2. 推送 5 个 actor（staging + `apify push`）

核心 actor 复用 repo 根目录的 `shared/` 模块。先运行 staging helper，为每个 actor 生成独立的 Apify CLI 上传上下文，再逐个推送到 **你的** 账号。staging 目录位于系统临时目录，不含凭据。

```bash
# 从仓库根目录开始
node scripts/prepare-apify-push.js

apify push --dir /private/tmp/mirrortrace-apify-stage/policy-gate
apify push --dir /private/tmp/mirrortrace-apify-stage/discovery
apify push --dir /private/tmp/mirrortrace-apify-stage/crawler
apify push --dir /private/tmp/mirrortrace-apify-stage/diff-evidence
apify push --dir /private/tmp/mirrortrace-apify-stage/report-builder
```

A0 的 `.actor/web_server_openapi.json` 是 Standby tab 的 OpenAPI 3.x schema；Apify 云端 build 会验证它。

推送后，每个 actor 会以 `roger_1of1/mirrortrace-<name>` 的形式出现在 Apify Console。

> 验证 `scope_type` enum 是否生效：在 Console 里手动用一个非法 scope（如 `"private_person_tracking"`）触发 actor，平台应在 **input 校验阶段** 直接拒绝——这就是 compliance-as-code 的第一道闸。

---

## 3. 配置 policy-gate（A0）的 Standby + metamorph

A0 是 **Standby** actor（常驻、低延迟响应请求），通过 `Actor.metamorph()` 把 **通过合规闸门** 的请求变形成下游 actor。

### 3.1 开启 Standby

在 Apify Console → `mirrortrace-policy-gate` → **Standby** 标签：
- 开启 Standby 模式
- 记下 Standby URL（形如 `https://roger_1of1--mirrortrace-policy-gate.apify.actor/`）

### 3.2 设置 metamorph 目标（target actor IDs）

A0 需要知道每个下游 actor 的 ID 才能 metamorph。通过 **环境变量** 注入（Console → actor → Settings → Environment variables，或在 task 的 input 里传）：

```text
DISCOVERY_ACTOR_ID = roger_1of1/mirrortrace-discovery
CRAWLER_ACTOR_ID   = roger_1of1/mirrortrace-crawler
DIFF_ACTOR_ID      = roger_1of1/mirrortrace-diff-evidence
REPORT_ACTOR_ID    = roger_1of1/mirrortrace-report-builder
```

> 当前 workspace 的 Metamorph target username 已固定为 `roger_1of1`。
> metamorph 只在合规闸门 **通过后** 触发；被拒请求不会 metamorph，因此 **永远不会** 进入抓取层。

---

## 4. 创建 Schedule（定时任务）

用于周期性自我审计 / 已授权源监控。Apify Console → **Schedules** → Create。

**平台限制（务必遵守）：**
- ⏱️ 最小间隔 **1 分钟**（cron 不能比每分钟更频繁）
- 📦 单个 Schedule 最多 **10 个 actor + 10 个 task**

推荐做法：把"自我审计"封装成 **task**（actor + 预设 input），再把 task 挂到 Schedule。例如每天一次：

```text
Cron: 0 9 * * *        # 每天 09:00；注意 ≥ 1 分钟间隔
Tasks:
  - mirrortrace-policy-gate (task: self-audit-daily, input: { "scope_type": "self", ... })
```

CLI 方式（可选）创建 task：

```bash
apify call roger_1of1/mirrortrace-policy-gate --input ./demo/allowed-urls.json
# 验证一次性运行通过后，再在 Console 把它存为 task 并挂 Schedule
```

> Closure Mode 的核心是 **限频**：用 Schedule 替代"手动反复刷新"，让用户一天只看一次报告，而不是强迫性查看。

---

## 5. 接 Webhook（运行通知 + 输出健康）

Apify Console → 每个 actor / task → **Integrations → Webhooks**，或全局 Webhook。

订阅这些事件：

| 事件类型 | 用途 |
| --- | --- |
| `ACTOR.RUN.SUCCEEDED` | 运行成功 → 触发下游/通知用户报告就绪 |
| `ACTOR.RUN.FAILED` | 运行失败 → 告警 |
| `ACTOR.RUN.TIMED_OUT` | 超时 → 告警 + 检查退避是否过度 |
| `ACTOR.RUN.ABORTED` | 中止 → 审计 |

**输出健康（output health）**：在 `ACTOR.RUN.SUCCEEDED` 的 webhook 里附带 payload，让接收端校验 dataset 是否非空、报告字段是否完整、是否记录了"被限流/被拒绝"事件——成功 ≠ 有有效输出。

Webhook payload 用 Apify 模板变量，例如：

```json
{
  "eventType": "{{eventType}}",
  "runId": "{{resource.id}}",
  "actorId": "{{resource.actId}}",
  "status": "{{resource.status}}",
  "datasetId": "{{resource.defaultDatasetId}}"
}
```

> 接收端建议校验 HMAC 签名（Webhook 设置里可配 secret），避免伪造回调。

---

## 6. 托管 `web/`（静态展示页）

`web/index.html` 是 **自包含单页**，内置实时合规闸门，本地或任意静态托管均可。

### 本地（最简单）

```bash
python3 -m http.server 8080 --directory web
# 浏览器打开 http://localhost:8080
```

### 任意静态托管

`web/` 是纯静态资源，可直接丢到任意静态托管（GitHub Pages / Netlify / Vercel / S3+CloudFront / Cloudflare Pages 等）。无构建步骤，无后端依赖。

> 展示页的合规闸门是 **客户端演示**，用于讲解拒绝/放行逻辑；真实抓取仍由已部署的 actor（§2–§5）执行。

---

## 7. 设置 `APIFY_TOKEN`（汇总）

| 场景 | 怎么提供 token |
| --- | --- |
| 本地 CLI | `apify login`（推荐）或 `export APIFY_TOKEN=<APIFY_TOKEN>` |
| CI / 脚本 | 环境变量 `APIFY_TOKEN=<APIFY_TOKEN>` |
| MCP 客户端 | `Authorization: Bearer <APIFY_TOKEN>`（见 `mcp/client-config.example.json`） |
| Actor 间调用 | 平台自动注入，无需手填 |

**切勿** 把真实 token 提交进仓库。用占位符 + 环境变量/密钥管理。

---

## 8. 部署后自检清单

- [ ] 5 个 actor 都在 `roger_1of1/...` 下可见
- [ ] 非法 `scope_type`（如 `"private_person_tracking"`）被 input schema 拒绝
- [ ] policy-gate Standby 开启，4 个 metamorph 目标变量已填
- [ ] 一个 `demo/reject-cases.json` 请求被 A0 拒绝且 **未** 进入抓取
- [ ] 一个 `demo/allowed-urls.json` 请求走通 A2→A3→A5→A6
- [ ] crawler 遇 429 时退避 + 报告如实记录（不换指纹）
- [ ] Schedule 间隔 ≥ 1 分钟，单 schedule ≤ 10 actor + 10 task
- [ ] Webhook 覆盖 succeeded/failed/timed-out + 输出健康校验
- [ ] `web/` 可访问，合规闸门演示正常
