window.__EX_PLAN__ = {
  "product": {
    "name": "Ex-Ditector 合规版",
    "subtitle": "Self Footprint Audit Pro",
    "oneLiner": "把「想查别人」的冲动，反转成「审计自己 + 保全证据 + 戒断强迫性查看」的合规工具。",
    "inversion": {
      "headline": "这不是追踪前任的工具。",
      "body": "同样的 OSINT 能力，方向完全相反：不去窥探任何私人个体，而是审计你自己的公开数字足迹、保全涉及你本人的公开证据、监控你已授权或公开的对象（公众人物 / 品牌），并用 Closure Mode 把强迫性查看的冲动转化为自我保护。冲动 → 自我保护。窥探 → 戒断。",
      "points": [
        "不追踪任何私人个体（前任 / 暗恋对象 / 同事 / 陌生人）",
        "不做任何恋爱 / 暧昧 / 出轨推断",
        "不从头像推断性别或性取向",
        "不抓取私域社交数据，不绕过登录 / 验证码 / 封禁",
        "唯一服务对象：你自己，以及你合法授权或本就公开的实体"
      ]
    }
  },
  "scopeTypes": [
    { "id": "self", "label": "self · 我自己", "desc": "审计你本人的公开数字足迹。", "example": "搜索我自己的姓名在公开网页上的出现情况。" },
    { "id": "consented", "label": "consented · 已授权对象", "desc": "对方书面授权你代为审计其公开足迹。", "example": "在客户书面授权下，审计该客户品牌的公开提及。" },
    { "id": "public_figure", "label": "public_figure · 公众人物", "desc": "公职 / 名人在公共领域的公开言论与报道。", "example": "汇总某位政治人物的公开新闻报道与官方声明。" },
    { "id": "brand", "label": "brand · 品牌 / 机构", "desc": "公司、产品、机构的公开声誉监控。", "example": "监控某品牌在公开新闻与官网上的产品召回信息。" },
    { "id": "safety_evidence", "label": "safety_evidence · 安全证据", "desc": "保全涉及你本人的公开证据（骚扰 / 诽谤 / 诈骗）。", "example": "保全一条公开发布的、针对我本人的诽谤帖子作为证据。" }
  ],
  "prohibited": [
    { "id": "romance_inference", "label": "恋爱 / 暧昧 / 出轨推断" },
    { "id": "gender_from_image", "label": "从头像 / 图像推断性别或性取向" },
    { "id": "dating_app_presence", "label": "探测某人是否在交友 App 上活跃" },
    { "id": "private_person_tracking", "label": "追踪某个具名私人个体" }
  ],
  "architecture": {
    "nodes": [
      { "id": "A0", "title": "A0 · Policy Gate", "role": "合规闸门。每个请求先过这里：解析 scope_type，匹配 input_schema 枚举，命中 prohibited 模式即拒绝并返回合法替代任务。是整条流水线唯一的入口，compliance-as-code。" },
      { "id": "A2", "title": "A2 · Source Router (Metamorph)", "role": "根据合规请求的类型，把任务路由到对应的公开数据源 actor（搜索引擎 / 新闻 / 官网 / 公开档案）。用 Apify Metamorph 动态切换 actor，不预先硬编码全部分支。" },
      { "id": "A3", "title": "A3 · Adaptive Crawler", "role": "AdaptivePlaywrightCrawler：能抓的页面用纯 HTTP，需渲染的才升级到浏览器。只抓公开页面，遇到登录 / 验证码 / 封禁即停止——合规退避，绝不绕过。" },
      { "id": "A5", "title": "A5 · Evidence & Scoring", "role": "对采集到的公开证据做结构化：计算 exposure / evidence_quality / actionability / distress_risk 四项分数，建立可引用的 evidence index（URL + 时间戳 + 哈希）。" },
      { "id": "A6", "title": "A6 · Report & Closure", "role": "生成自我足迹报告，并接入 Closure Mode：折叠刺激性内容、冷却计时、「今天不打开」、移交可信联系人。" }
    ],
    "webhooks": [
      { "id": "WH1", "title": "Webhook · audit.completed", "role": "审计完成回调：把报告结构与证据索引推送给用户自己的端，不经第三方。" },
      { "id": "WH2", "title": "Webhook · policy.rejected", "role": "拒绝事件回调：记录被拒请求与原因，用于合规审计日志（只记元数据，不存被拒内容主体）。" }
    ],
    "flow": ["A0", "A2", "A3", "A5", "A6"]
  },
  "cards": [
    {
      "id": "metamorph",
      "title": "Metamorph 动态路由",
      "what": "用 Apify Actor.metamorph() 在运行时把当前 run 变形为下一个 actor，按 scope_type 把任务交给对应的公开数据源采集器，无需一个巨型 actor 硬编码所有分支。",
      "bonus": "合规加分：路由表本身就是白名单——只有列出的合法数据源 actor 才可达，非法源在路由层就不存在。"
    },
    {
      "id": "mcp",
      "title": "MCP 工具层白名单",
      "what": "把采集 / 检索能力封装为 MCP 工具，模型只能调用工具层显式暴露的工具集；每个工具自带 scope 约束。",
      "bonus": "合规加分：工具层是硬边界。模型即使被诱导，也调不出「追踪私人个体」这种不存在的工具。"
    },
    {
      "id": "schema",
      "title": "input_schema 枚举即合规",
      "what": "Actor 的 input_schema 把 scope_type 定义为固定枚举（self / consented / public_figure / brand / safety_evidence），非枚举值在输入校验阶段直接报错。",
      "bonus": "合规加分：Compliance-as-code。合规规则写进 schema，由平台强制执行，而不是靠运行时 if 判断或人工自觉。"
    },
    {
      "id": "adaptive",
      "title": "AdaptivePlaywrightCrawler",
      "what": "Crawlee 的自适应爬虫：先尝试轻量 HTTP，检测到需要 JS 渲染才升级到 Playwright 浏览器，自动在两种模式间选择。",
      "bonus": "合规加分：只处理公开可渲染页面；成本与指纹都最小化，不为了「拿到数据」而过度模拟真人。"
    },
    {
      "id": "backoff",
      "title": "合规退避，不是规避",
      "what": "遇到 429 / 封禁 / 验证码，执行指数退避并最终停止，把状态如实写进报告；绝不更换 IP、伪造指纹或破解验证码。",
      "bonus": "合规加分：退避是尊重对方服务条款的信号；规避才是越界。本工具明确选择前者。"
    }
  ],
  "report": {
    "label": "样例结构（模板，非真实抓取数据）",
    "scores": [
      { "key": "exposure_score", "label": "暴露度", "desc": "你的公开足迹在多大范围内可被检索到（0-100）。", "sample": "—" },
      { "key": "evidence_quality_score", "label": "证据质量", "desc": "已保全证据的可引用性：来源权威性 + 时间戳 + 完整性（0-100）。", "sample": "—" },
      { "key": "actionability_score", "label": "可行动性", "desc": "有多少条目附带明确的下一步（申请删除 / 报告 / 保全）（0-100）。", "sample": "—" },
      { "key": "distress_risk_score", "label": "困扰风险", "desc": "内容对你本人造成情绪困扰的风险，用于触发 Closure Mode（0-100）。", "sample": "—" }
    ],
    "evidenceIndexFields": [
      { "field": "source_url", "desc": "公开来源 URL（仅公开页面）" },
      { "field": "captured_at", "desc": "保全时间戳（ISO 8601）" },
      { "field": "content_hash", "desc": "内容哈希（SHA-256，用于完整性校验）" },
      { "field": "scope_type", "desc": "本条证据所属的合法 scope" },
      { "field": "subject", "desc": "证据主体（仅限 self / 已授权 / 公众人物 / 品牌）" },
      { "field": "recommended_action", "desc": "建议动作（保全 / 申请删除 / 上报平台 / 法律咨询）" }
    ]
  },
  "closureMode": {
    "headline": "Closure Mode · 戒断模式",
    "intro": "反向设计的 UI：当工具检测到强迫性查看冲动或高困扰内容，它不放大刺激，而是帮你停下来。",
    "features": [
      { "title": "折叠刺激性内容", "desc": "高 distress_risk 的条目默认折叠，需要明确二次确认才展开。" },
      { "title": "冷却计时", "desc": "短时间内重复查看同一对象时，强制冷却倒计时，打断强迫循环。" },
      { "title": "今天不打开", "desc": "一键把整个审计锁定到明天，附一句温和提醒。" },
      { "title": "移交可信联系人", "desc": "把查看 / 决策权移交给你设定的可信联系人，由对方代为把关。" }
    ]
  },
  "plan48h": [
    { "phase": "0-8h", "title": "Policy Gate + input_schema", "status": "done", "desc": "落地 A0 合规闸门与 scope_type 枚举，写出拒绝/接受逻辑与替代任务表。" },
    { "phase": "8-20h", "title": "Metamorph 路由 + 白名单源", "status": "in_progress", "desc": "A2 路由表 + 合法数据源 actor 接线，MCP 工具层白名单。" },
    { "phase": "20-32h", "title": "Adaptive 采集 + 退避", "status": "todo", "desc": "A3 自适应爬虫，合规退避逻辑，公开页面边界。" },
    { "phase": "32-40h", "title": "评分 + 证据索引", "status": "todo", "desc": "A5 四项评分与 evidence index 结构化。" },
    { "phase": "40-48h", "title": "报告 + Closure Mode + Demo", "status": "todo", "desc": "A6 报告生成、Closure Mode 反向 UI，打磨 demo。" }
  ]
}
;
