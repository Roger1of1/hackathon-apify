/* MirrorTrace 合规版 — app.js
 *
 * Clarity-first dashboard. The Policy Gate is REAL logic, not a simulation.
 * No preloader, no radio-dial/channel nav, no scroll-driven wheel — those were
 * removed because they violated the hard clarity red line ("明了,不要花哨让人疑惑").
 *
 * The self-exposure report is modelled on TWO reference architectures:
 *   - The Markup Blacklight (themarkup.org/blacklight): a privacy inspector that
 *     runs a fixed battery of checks and renders a grouped, plain-language
 *     inventory of "what this site can learn about you", each with a "why it
 *     matters". We INVERT it: grouped self-exposure finding categories, each with
 *     a plain explanation + suggested fix + evidence-quality note.
 *   - SpiderFoot (github.com/smicallef/spiderfoot): OSINT modules emit typed
 *     events; a correlation engine links co-occurring events into clusters. Our
 *     finding categories map 1:1 to detector modules + EVENT_TYPES
 *     (shared/detectors/event-types.js), and the cluster card mirrors the
 *     correlation engine's cluster keys (shared/enrich/cluster-keys.js).
 *
 * NO FAKE DATA: the report below shows the audit *schema* (template checks),
 * clearly labelled. Real findings (URL + timestamp + hash) only appear on a real
 * Apify run; this front-end never fabricates a scrape result or success.
 */
(function () {
  "use strict";

  const FALLBACK_PLAN = window.__MIRRORTRACE_PLAN__ || null;

  /* =========================================================================
   * POLICY GATE — the genuine compliance logic (mirrors A0 / input_schema).
   * window.MirrorTrace.runPolicyGate really rejects
   * stalking / private-individual / laundering inputs (tests stay green).
   * =======================================================================*/

  const LEGAL_SCOPES = ["self", "consented", "public_figure", "brand", "safety_evidence"];

  const PROHIBITED = [
    {
      id: "romance_inference",
      label: "恋爱 / 暧昧 / 出轨推断",
      reason: "请求涉及对私人关系的恋爱 / 暧昧 / 出轨推断。本工具不做任何关系性推断。",
      patterns: [
        /暧昧|出轨|劈腿|约会|约炮|恋爱|喜欢(我|他|她|对方)|是不是单身|有没有对象|有没有男(朋)?友|有没有女(朋)?友|脚踏两(只|条)船/i,
        /affair|cheat(ing)?|dating life|is .* single|has a (boy|girl)friend|romantic|crush|love interest/i
      ]
    },
    {
      id: "gender_from_image",
      label: "从头像 / 图像推断性别或性取向",
      reason: "请求要求从头像 / 图像推断性别或性取向。本工具不做任何基于图像的身份推断。",
      patterns: [
        /(头像|照片|图片|长相|外貌|样子|脸).{0,8}(性别|男的还是女的|是男是女|性取向|gay|同性恋|直男|直女)/i,
        /(性别|性取向|gay|是不是同性恋|是不是直).{0,8}(头像|照片|图片|长相|外貌|脸)/i,
        /(infer|guess|detect|determine).{0,20}(gender|sex|sexual orientation).{0,20}(avatar|photo|image|picture|face)/i,
        /(avatar|photo|image|picture|face).{0,20}(gender|sexual orientation|is .* (gay|straight))/i
      ]
    },
    {
      id: "dating_app_presence",
      label: "探测交友 App 活跃情况",
      reason: "请求要求探测某人是否在交友 / 约会 App 上活跃。这属于私域行为追踪，被禁止。",
      patterns: [
        /(tinder|bumble|探探|陌陌|soul|hinge|okcupid|grindr|交友(软件|app)|约会(软件|app)|相亲(软件|app))/i,
        /(在不在|有没有(用|注册)|是否(注册|活跃|刷)).{0,12}(交友|约会|相亲|tinder|bumble|探探|陌陌)/i,
        /(swipe|likes|matches|followers|comments).{0,18}(tinder|bumble|instagram|ig|facebook|fb)/i,
        /(tinder|bumble|instagram|ig|facebook|fb|微博|抖音|小红书)\s*(的)?\s*(followers?|likes?|comments?|matches|粉丝|关注|点赞|评论)/i
      ]
    },
    {
      id: "private_person_tracking",
      label: "追踪具名私人个体",
      reason: "请求指向追踪 / 监控某个私人个体（私人个体 / 暗恋对象 / 同事 / 陌生人等）。本工具只服务于你自己及合法授权 / 公开实体。",
      patterns: [
        /(私人个体|前男友|前女友|前夫|前妻|分手|复合)/i,
        /\b(ex[-\s]?(boyfriend|girlfriend|husband|wife|partner)?)\b/i,
        /(暗恋|心仪|喜欢的(那个)?(人|男生|女生)|那个(女生|男生|妹子|小哥))/i,
        /(跟踪|蹲点|监控|偷偷查|查一下(他|她)|扒一下(他|她)|人肉|起底)(?!.*(我自己|本人|品牌|公司|公众人物))/i,
        /(同事|邻居|室友|陌生人|那个(人|男的|女的)|某(人|个人)).{0,10}(住(在)?哪|在哪|电话|地址|行踪|每天)/i,
        /(stalk|track|monitor|spy on|dig up|locate)\s+(my|that|the|a|his|her)?\s*(coworker|colleague|neighbor|roommate|stranger|crush|guy|girl|person|him|her)/i,
        /(home address|where .* lives?|phone number|daily routine|whereabouts) of (my|a|that|the|his|her)/i
      ]
    }
  ];

  const SELF_SIGNALS = /(我自己|我本人|本人|我的(姓名|名字|名誉|足迹|信息)|关于我的|针对我(本人|的))/i;
  const PUBLIC_SIGNALS = /(公众人物|政治人物|官员|名人|品牌|公司|机构|企业|官网|新闻报道|公开(报道|声明|新闻|页面|资料)|召回|声誉)/i;
  const SAFETY_SIGNALS = /(诽谤|骚扰|诈骗|名誉(权)?|证据|保全|侵权|网暴|谣言)/i;
  const CONSENT_SIGNALS = /(授权|书面同意|委托|同意书|代为(审计|监控))/i;

  function runPolicyGate(freeText, scope) {
    const text = (freeText || "").trim();
    scope = (scope || "").trim();

    if (scope && !LEGAL_SCOPES.includes(scope)) {
      return {
        accepted: false,
        category: "schema_violation",
        reason: `scope_type "${scope}" 不在合法枚举内（self / consented / public_figure / brand / safety_evidence），input_schema 校验拒绝。`,
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    if (text) {
      const hits = [];
      for (const cat of PROHIBITED) {
        for (const re of cat.patterns) {
          if (re.test(text)) { hits.push(cat); break; }
        }
      }
      if (hits.length) {
        return {
          accepted: false,
          category: hits[0].id,
          reason: hits[0].reason + (scope ? `（即使标注为 scope=${scope}，合法 scope 也不能为越界请求洗白。）` : ""),
          matched: hits.map(h => ({ id: h.id, label: h.label })),
          alternatives: alternativesFor(hits[0].id)
        };
      }
    }

    if (!scope && !text) {
      return {
        accepted: false,
        category: "empty",
        reason: "未提供 scope_type，也未输入请求内容。请至少选择一个合法 scope 或描述你的请求。",
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    let effectiveScope = scope;
    if (!effectiveScope && text) {
      if (SELF_SIGNALS.test(text)) effectiveScope = "self";
      else if (SAFETY_SIGNALS.test(text) && SELF_SIGNALS.test(text)) effectiveScope = "safety_evidence";
      else if (SAFETY_SIGNALS.test(text)) effectiveScope = "safety_evidence";
      else if (CONSENT_SIGNALS.test(text)) effectiveScope = "consented";
      else if (PUBLIC_SIGNALS.test(text)) effectiveScope = "public_figure";
    }

    if (!effectiveScope) {
      return {
        accepted: false,
        category: "unscoped",
        reason: "无法确认该请求落入任一合法 scope（self / consented / public_figure / brand / safety_evidence）。闸门采用 fail-closed：无法证明合法即拒绝。请明确这是关于你自己、已授权对象、公众人物、品牌，还是涉及你本人的安全证据。",
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    return {
      accepted: true,
      category: "accepted",
      scope: effectiveScope,
      reason: scope
        ? `请求落入合法 scope "${effectiveScope}"，未命中任何 prohibited 模式。`
        : `从请求文本推断为合法 scope "${effectiveScope}"，未命中任何 prohibited 模式。`,
      pipeline: pipelineFor(effectiveScope)
    };
  }

  function pipelineFor(scope) {
    const subject = {
      self: "你自己的公开足迹",
      consented: "已书面授权对象的公开足迹",
      public_figure: "该公众人物在公共领域的公开言论/报道",
      brand: "该品牌/机构的公开声誉信息",
      safety_evidence: "涉及你本人的公开证据"
    }[scope];
    return [
      { step: "A0", text: `通过合规闸门：scope=${scope}，记录到合规审计日志（仅元数据）。` },
      { step: "A2", text: `Metamorph 把任务路由到白名单内的公开数据源 actor，目标=${subject}。` },
      { step: "A3", text: "AdaptivePlaywrightCrawler 仅抓取公开页面；遇登录/验证码/封禁即合规退避并如实记录。" },
      { step: "A5", text: "结构化证据，计算 exposure / evidence_quality / actionability / distress_risk 四项分数，建立可引用 evidence index。" },
      { step: "A6", text: "生成自我足迹报告，按 distress_risk 触发 Closure Mode（折叠/冷却/移交）。" }
    ];
  }

  const ALT_LIBRARY = {
    private_person_tracking: [
      "审计「我自己」的公开足迹：看看公开网络上能搜到关于我的哪些信息。",
      "保全涉及我本人的公开骚扰/诽谤内容作为证据（scope=safety_evidence）。",
      "监控某公众人物的公开新闻报道（scope=public_figure）。"
    ],
    romance_inference: [
      "审计「我自己」在公开网页上的名誉相关提及（scope=self）。",
      "保全一条针对我本人的公开诽谤帖作为证据（scope=safety_evidence）。"
    ],
    gender_from_image: [
      "审计我自己的公开头像在哪些公开页面被使用（scope=self）。",
      "监控某品牌官方账号的公开视觉资产（scope=brand）。"
    ],
    dating_app_presence: [
      "审计我自己的公开账号在搜索引擎中的可见度（scope=self）。",
      "在书面授权下审计某品牌的公开提及（scope=consented）。"
    ]
  };
  function alternativesFor(id) { return ALT_LIBRARY[id] || defaultAlternatives(); }
  function defaultAlternatives() {
    return [
      "审计「我自己」的公开数字足迹（scope=self）。",
      "保全涉及我本人的公开证据：骚扰/诽谤/诈骗（scope=safety_evidence）。",
      "监控某公众人物的公开报道（scope=public_figure）。",
      "在书面授权下监控某品牌的公开声誉（scope=brand / consented）。"
    ];
  }

  /* =========================================================================
   * RENDERING HELPERS
   * =======================================================================*/

  let PLAN = null;

  function el(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }
  function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

  function renderHero() {
    const p = PLAN.product;
    document.getElementById("heroOne").textContent = p.oneLiner;
    const inv = p.inversion;
    document.getElementById("invHead").textContent = inv.headline;
    document.getElementById("invBody").textContent = inv.body;
    const ul = document.getElementById("invPoints");
    inv.points.forEach(pt => ul.appendChild(el("li", null, esc(pt))));
  }

  function renderScopeSelect() {
    const sel = document.getElementById("scopeSelect");
    PLAN.scopeTypes.forEach(s => {
      const o = document.createElement("option");
      o.value = s.id; o.textContent = s.label; sel.appendChild(o);
    });
  }

  function renderPresets() {
    const row = document.getElementById("presetRow");
    const presets = [
      { t: "追踪某个私人个体", txt: "帮我追踪某个私人个体最近在干嘛，并推断其亲密关系", kind: "reject" },
      { t: "暧昧推断", txt: "看看这个人和我同事是不是有暧昧", kind: "reject" },
      { t: "头像猜性别", txt: "根据这个头像判断对方是男是女", kind: "reject" },
      { t: "交友 App 活跃", txt: "查他是不是在用 Tinder、Bumble", kind: "reject" },
      { t: "蹲点同事行踪", txt: "track my coworker's daily whereabouts and home address", kind: "reject" },
      { t: "审计我自己", txt: "搜索我自己的姓名在公开网页上的出现情况，评估我的暴露度", kind: "accept" },
      { t: "保全诽谤证据", txt: "保全一条公开发布的、针对我本人的诽谤帖子作为证据", kind: "accept" },
      { t: "监控公众人物", txt: "汇总某位政治人物的公开新闻报道与官方声明", kind: "accept" },
      { t: "品牌声誉", txt: "监控某品牌在公开新闻与官网上的产品召回信息", kind: "accept" }
    ];
    presets.forEach(p => {
      const b = el("button", "preset " + p.kind, esc(p.t));
      b.type = "button";
      b.addEventListener("click", () => {
        document.getElementById("requestInput").value = p.txt;
        document.getElementById("scopeSelect").value = "";
        doRun();
        document.getElementById("gateResult").scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
      row.appendChild(b);
    });
  }

  function renderResult(res) {
    const out = document.getElementById("gateResult");
    out.innerHTML = "";
    const v = el("div", "verdict " + (res.accepted ? "accept" : "reject"));

    // Plain-language verdict first (HIBP-style instant outcome), then the
    // one-line meaning, then the technical reason. Strong top-down hierarchy:
    // a first-time visitor reads big word → what it means → why.
    const head = el("div", "verdict-head");
    const mark = el("span", "verdict-mark", res.accepted ? "✓" : "⊘");
    const word = el("span", "verdict-word", res.accepted ? "可以做" : "已拒绝");
    head.appendChild(mark);
    head.appendChild(word);
    head.appendChild(el("span", "verdict-badge", res.accepted ? "compliant" : "blocked"));
    v.appendChild(head);

    // one-line "what this means" — plain language, no jargon
    v.appendChild(el("p", "verdict-meaning",
      res.accepted
        ? "这个请求落入合法范围，闸门放行，可以进入自审流水线。"
        : "这个请求越过了合规红线，闸门当场拦下，不会进行任何抓取。"));

    // technical reason, labelled so it reads as the supporting detail
    v.appendChild(el("p", "verdict-why-label", res.accepted ? "判定依据" : "为什么被拒"));
    v.appendChild(el("p", "verdict-reason", esc(res.reason)));

    if (res.accepted) {
      v.appendChild(el("span", "scope-tag", "scope_type = " + esc(res.scope)));
      v.appendChild(el("p", "verdict-sub", "流水线将执行（合规路径）"));
      const ul = el("ul", "pipe-list");
      res.pipeline.forEach(s => {
        const li = el("li");
        li.appendChild(el("span", "pstep", esc(s.step)));
        li.appendChild(el("span", null, esc(s.text)));
        ul.appendChild(li);
      });
      v.appendChild(ul);
    } else {
      if (res.matched && res.matched.length) {
        const wrap = el("div");
        wrap.appendChild(el("p", "verdict-sub", "命中 prohibited 类别"));
        res.matched.forEach(m => wrap.appendChild(el("span", "matched-tag", esc(m.label))));
        v.appendChild(wrap);
      }
      v.appendChild(el("p", "verdict-sub", "改做这些合法任务 →"));
      const ul = el("ul", "alt-list");
      (res.alternatives || []).forEach(a => {
        const li = el("li"); li.appendChild(el("span", null, esc(a))); ul.appendChild(li);
      });
      v.appendChild(ul);
    }
    out.appendChild(v);
  }

  function doRun() {
    const txt = document.getElementById("requestInput").value;
    const scope = document.getElementById("scopeSelect").value;
    const res = runPolicyGate(txt, scope);
    renderResult(res);
    updateReportForScope(res);
  }

  /* =========================================================================
   * SELF-EXPOSURE REPORT — grouped finding categories (Blacklight-style),
   * categories + event types from shared/detectors/event-types.js (SpiderFoot
   * module/event model). These are TEMPLATE checks (the audit schema), each
   * clearly flagged "模板检查项（无真实数据）". No scraped result is fabricated.
   *
   * The categories below mirror, 1:1, the detector modules that actually exist
   * in shared/detectors/* and the EVENT_TYPES they emit, so the UI and the
   * pipeline speak the same vocabulary.
   * =======================================================================*/

  const FINDING_GROUPS = [
    {
      id: "pii",
      icon: "◐",
      title: "公开 PII · 你自己发布的可识别信息",
      module: "sfp_pii  ·  pii-detector.js",
      desc: "你在自己控制的公开页面上发布的、可直接识别你的信息（邮箱 / 电话 / 地址 / 用户名 / 粗略位置）。检测，不推断。",
      items: [
        { name: "公开邮箱出现在你的页面上", event: "PII_EMAIL_PUBLIC", sev: "high", vis: "indexed",
          why: "搜索引擎可索引的邮箱便于第三方把你的多个账号串起来，也是垃圾邮件/钓鱼的入口。",
          fix: "用专用邮箱替换高敏页面上的主邮箱；核查哪些公开页面仍在展示它。" },
        { name: "公开电话号码", event: "PII_PHONE_PUBLIC", sev: "high", vis: "indexed",
          why: "公开电话可被用于社工、撞库找回与定位。", fix: "下线或改为联系表单；保留快照作为已处理记录。" },
        { name: "公开邮寄/家庭地址文本", event: "PII_POSTAL_PUBLIC", sev: "high", vis: "linked",
          why: "公开地址直接关系到人身安全。", fix: "联系站点移除；优先处理高排名页面。" },
        { name: "复用的公开用户名", event: "PII_HANDLE_PUBLIC", sev: "medium", vis: "indexed",
          why: "同一用户名让人从一个公开账号跳到你的其他公开账号。", fix: "区隔公私用户名，降低跨平台关联。" },
        { name: "自述的粗略位置（城市/单位）", event: "PII_GEO_HINT_PUBLIC", sev: "low", vis: "indexed",
          why: "粗略位置文本（非实时定位）与姓名同时出现会缩小你的可定位范围。", fix: "评估是否必须公开；统一对外展示口径。" }
      ]
    },
    {
      id: "tracker",
      icon: "◉",
      title: "第三方追踪器 · 你自己网站上的隐私泄露面",
      module: "sfp_tracker  ·  tracker-detector.js",
      desc: "这是 Blacklight 的核心检查项：你控制的站点上有哪些第三方追踪器，会泄露访客（也包括你）的信息。",
      items: [
        { name: "第三方追踪器脚本", event: "TRACKER_THIRD_PARTY", sev: "medium", vis: "indexed",
          why: "第三方脚本把访客行为回传给广告/数据中介。", fix: "审查并移除非必要的第三方脚本与标签。" },
        { name: "浏览器指纹采集", event: "TRACKER_FINGERPRINTING", sev: "high", vis: "indexed",
          why: "指纹采集即使禁用 Cookie 也能跨站识别访客。", fix: "移除指纹库；改用合规的隐私友好分析。" },
        { name: "会话录制（键鼠回放）", event: "TRACKER_SESSION_RECORDING", sev: "high", vis: "indexed",
          why: "会话录制可能连同表单内容一起被采集。", fix: "停用会话录制或严格脱敏。" },
        { name: "键盘记录式表单监听", event: "TRACKER_KEYLOGGING", sev: "high", vis: "indexed",
          why: "提交前即捕获输入会泄露未提交的敏感内容。", fix: "移除提交前监听的第三方表单脚本。" },
        { name: "第三方 Cookie", event: "COOKIE_THIRD_PARTY", sev: "low", vis: "indexed",
          why: "第三方 Cookie 用于跨站追踪访客。", fix: "限制为必要的第一方 Cookie。" },
        { name: "Referrer 泄露身份", event: "LEAK_REFERRER", sev: "medium", vis: "indexed",
          why: "URL/Referrer 可能把你的身份带给第三方域。", fix: "设置 referrer policy，避免在 URL 暴露标识。" }
      ]
    },
    {
      id: "secret",
      icon: "◈",
      title: "密钥泄露 · 你自己误发的凭证",
      module: "sfp_secret  ·  secret-leak-detector.js",
      desc: "你在自己控制的页面/仓库里误发的 API key / token / 私钥 / .env 赋值——安全卫生问题，应当轮换。借鉴 secret-scanning（TruffleHog / GitHub secret scanning），方向为自审。",
      items: [
        { name: "公开页面/仓库中的密钥", event: "SECRET_LEAK_PUBLIC", sev: "high", vis: "indexed",
          why: "公开的凭证可被直接滥用，应立即轮换。这是关于你自己的凭证，绝不涉及第三方密钥。",
          fix: "立即轮换凭证；从历史记录中清除；改用密钥管理。" }
      ]
    },
    {
      id: "breach",
      icon: "◍",
      title: "泄露库命中（k-匿名）· 你自己凭证的已知泄露",
      module: "sfp_breach  ·  breach-range-detector.js",
      desc: "用 HIBP 式 k-匿名 range 比对你自己的凭证是否出现在已知泄露中——我们绝不传输或存储完整明文，只比对哈希前缀范围。",
      items: [
        { name: "凭证命中泄露范围", event: "BREACH_RANGE_HIT", sev: "high", vis: "private",
          why: "出现在已知泄露中的凭证应停用并改密码。比对在 k-匿名桶内完成，桶内候选 ≥ k 才返回，不暴露具体后缀。",
          fix: "停用该凭证、改用唯一强密码、开启两步验证。" }
      ]
    },
    {
      id: "surface",
      icon: "◎",
      title: "可见账号与表面 · 你控制并暴露的入口",
      module: "sfp_accounts  ·  username-enum-detector.js（dual-use，仅 self/public_figure 经闸门校验）",
      desc: "你自己控制并公开暴露的档案 URL 与用户名。用户名枚举是 dual-use 技术，仅对 self / public_figure 开放，且必须经过合规闸门。",
      items: [
        { name: "公开档案 URL", event: "SELF_PROFILE_URL", sev: "low", vis: "indexed",
          why: "盘点你已知公开的档案入口，便于统一管理与处置。", fix: "整理对外档案清单；下线不再使用的旧档案。" },
        { name: "可枚举的公开用户名", event: "SELF_USERNAME", sev: "medium", vis: "indexed",
          why: "复用用户名提高了跨平台关联度。", fix: "区隔公私用户名；这是经闸门校验的 dual-use 枚举。" }
      ]
    }
  ];

  // The latest REAL produced report (synthetic-fixture or live pipeline output),
  // or null when none has loaded. When set, the report view renders its REAL
  // detector findings; when null, the view shows the honest template catalog.
  let LOADED_REPORT = null;

  // Flatten FINDING_GROUPS into an event_type -> metadata lookup, so a real
  // finding's event_type resolves to its category + "why it matters" + remediation
  // copy. This keeps ONE vocabulary shared by the template catalog and real report.
  const EVENT_META = (function buildEventMeta() {
    const m = {};
    FINDING_GROUPS.forEach(function (g) {
      g.items.forEach(function (it) {
        m[it.event] = {
          groupId: g.id, groupTitle: g.title, groupIcon: g.icon, module: g.module,
          name: it.name, why: it.why, fix: it.fix, sev: it.sev, vis: it.vis
        };
      });
    });
    return m;
  })();

  // Per-finding evidence-quality note (mirrors shared/enrich/evidence-quality.js +
  // k-anonymity.js framing): template checks have no real evidence yet.
  const SEV_LABEL = { high: "高", medium: "中", low: "低", info: "提示" };
  const VIS_LABEL = { indexed: "可被搜索引擎索引", linked: "顺链接可达", private: "通常不应外露" };

  // The "why this is a template, not a finding" banner copy.
  const SELF_NOTE =
    "scope=self：以下按类别列出第三方能轻易发现关于你的什么。这些是审计 schema 的模板检查项，" +
    "不是真实抓取结果——真实运行才会按 evidence index 填入带 URL+时间戳+哈希的条目。";
  const PUBLIC_FIGURE_NOTE =
    "scope=public_figure：只盘点该公众人物在公共领域的官方/公开表面（官网、新闻、公开声明）。" +
    "不触碰任何私域行为，不做身份/关系推断。以下为审计 schema 的模板检查项。";

  /* -------------------------------------------------------------------------
   * LIVE k-ANONYMITY DEMONSTRATOR (Have I Been Pwned "Pwned Passwords" range API)
   *
   * Mirrors the EXACT contract in shared/aux/kanon.js so the UI and the actor
   * agree byte-for-byte:
   *   sha1Hex(secret)  -> UPPERCASE hex SHA-1 of the UTF-8 string
   *   kAnonPair(secret) -> { hash, prefix: hash.slice(0,5), suffix: hash.slice(5) }
   *
   * The privacy mechanic (Troy Hunt, "Understanding Have I Been Pwned's Use of
   * SHA-1 and k-Anonymity"): only the 5-char PREFIX would ever be sent to the
   * range endpoint (16^5 = 1,048,576 buckets, so the prefix is shared by
   * thousands of hashes and the server cannot tell which one you asked about);
   * the 35-char SUFFIX is matched LOCALLY and never leaves the device.
   *
   * HONEST OFFLINE BEHAVIOUR: we do NOT query any breach corpus here and we
   * NEVER fabricate a breach count or a "pwned" verdict. This panel proves the
   * privacy MECHANIC (what leaves vs. what stays local), not a breach RESULT.
   * Hashing runs entirely in the browser via the Web Crypto SubtleCrypto API.
   * -----------------------------------------------------------------------*/

  // Browser SHA-1 -> uppercase hex (matches kanon.sha1Hex). Async because
  // crypto.subtle.digest returns a Promise. file:// and https:// expose a
  // SubtleCrypto; plain http:// on a remote origin may not (secure-context rule).
  async function sha1HexBrowser(input) {
    const s = typeof input === "string" ? input : String(input == null ? "" : input);
    const subtle = (window.crypto && window.crypto.subtle) || null;
    if (!subtle) throw new Error("no-subtlecrypto");
    const bytes = new TextEncoder().encode(s);
    const digest = await subtle.digest("SHA-1", bytes);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }

  // Mirror of kanon.kAnonPair: prefix = hash[0..5], suffix = hash[5..40].
  function kAnonSplit(hash) {
    return { hash: hash, prefix: hash.slice(0, 5), suffix: hash.slice(5) };
  }

  function kAnonPanel() {
    const panel = el("div", "kanon");

    panel.appendChild(el("div", "kanon-tag", "实时演示 · HIBP k-匿名 range 机制"));
    panel.appendChild(el("p", "kanon-intro",
      "在浏览器本地把你<b>自己</b>的一个凭证（密码或邮箱）做 SHA-1，然后看清楚：" +
      "<b>哪 5 个字符会被发出</b>、<b>哪 35 个字符永远留在本地</b>。" +
      "这复刻 Have I Been Pwned「Pwned Passwords」range API 的隐私机制，" +
      "也与后端 <code>shared/aux/kanon.js</code> 的 prefix/suffix 切分契约逐字一致。"));

    const warn = el("p", "kanon-offline");
    warn.innerHTML = "⊘ 离线模式不会查询任何泄露库 —— 本面板证明的是<b>隐私机制</b>（什么离开设备、什么留在本地），" +
      "<b>不是</b>泄露结果。绝不会显示任何伪造的泄露命中或次数。";
    panel.appendChild(warn);

    const field = el("div", "kanon-field");
    const label = el("label", "field-label", "你自己的凭证（仅在本机哈希，不会上传）");
    label.setAttribute("for", "kanonInput");
    field.appendChild(label);
    const input = el("input", "input");
    input.id = "kanonInput";
    input.type = "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("autocapitalize", "off");
    input.placeholder = "例如：你自己的一个旧密码或邮箱（本机 SHA-1，永不离开浏览器）";
    field.appendChild(input);
    const actions = el("div", "kanon-actions");
    const runBtn = el("button", "btn btn-ghost btn-tiny", "本地哈希并切分");
    runBtn.type = "button";
    const clrBtn = el("button", "btn btn-ghost btn-tiny", "清空");
    clrBtn.type = "button";
    actions.appendChild(runBtn);
    actions.appendChild(clrBtn);
    field.appendChild(actions);
    panel.appendChild(field);

    const out = el("div", "kanon-out");
    out.id = "kanonOut";
    out.setAttribute("aria-live", "polite");
    panel.appendChild(out);

    function clearOut() { out.innerHTML = ""; }

    async function run() {
      const secret = input.value;
      if (!secret) {
        out.innerHTML = '<p class="kanon-hint">输入一个字符串后再哈希。空输入不发送、不哈希。</p>';
        return;
      }
      let hash;
      try {
        hash = await sha1HexBrowser(secret);
      } catch (e) {
        out.innerHTML = '<p class="kanon-hint kanon-err">此环境不提供 Web Crypto（SubtleCrypto 仅在安全上下文，如 file:// 或 https:// 可用）。' +
          '请用 file:// 直接打开本页，或通过 https 访问。后端 <code>kanon.js</code> 用 Node crypto 做同样的 SHA-1。</p>';
        return;
      }
      const k = kAnonSplit(hash);

      out.innerHTML = "";

      // The split, shown unambiguously: prefix (sent) highlighted vs suffix (local).
      const split = el("div", "kanon-split");
      const pre = el("span", "kanon-prefix", esc(k.prefix));
      pre.title = "会被发往 range 端点的 5 个字符";
      const suf = el("span", "kanon-suffix", esc(k.suffix));
      suf.title = "永远留在本地、本地比对的 35 个字符";
      split.appendChild(pre);
      split.appendChild(suf);
      out.appendChild(split);

      const legend = el("div", "kanon-legend");
      const sent = el("div", "kanon-leg-row");
      sent.innerHTML = '<span class="kanon-chip sent">会发出 · prefix</span>' +
        '<code class="kanon-mono">GET range/<b>' + esc(k.prefix) + "</b></code>" +
        '<span class="kanon-leg-note">5 个十六进制字符 → 1,048,576 个桶之一，服务器无法分辨你查的是哪个。</span>';
      const local = el("div", "kanon-leg-row");
      local.innerHTML = '<span class="kanon-chip local">留本地 · suffix</span>' +
        '<code class="kanon-mono">' + esc(k.suffix) + "</code>" +
        '<span class="kanon-leg-note">35 个字符在你设备上与桶内候选逐一比对；明文凭证从不离开浏览器。</span>';
      legend.appendChild(sent);
      legend.appendChild(local);
      out.appendChild(legend);

      const foot = el("p", "kanon-foot");
      foot.innerHTML = "完整 SHA-1（仅展示，不发送）：<code class=\"kanon-mono\">" + esc(k.hash) + "</code><br>" +
        "下一步在真实运行中：后端只用 <code>" + esc(k.prefix) + "</code> 向 HIBP range 端点取回该桶的所有后缀+次数，" +
        "在本地匹配 <code>suffix</code>，并按 HIBP padding 指南把 count=0 的填充行当作「未命中」。" +
        "离线此处<b>到此为止</b>——不查询、不返回、不伪造任何泄露结果。";
      out.appendChild(foot);
    }

    runBtn.addEventListener("click", run);
    input.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); run(); } });
    clrBtn.addEventListener("click", () => { input.value = ""; clearOut(); input.focus(); });

    return panel;
  }

  /* =======================================================================
   * PORTABLE EVIDENCE — STIX 2.1 "Observed Data" (OpenCTI / MISP interop)
   * -----------------------------------------------------------------------
   * Mirror of shared/enrich/stix-evidence.js (toObservedData) for the
   * browser/offline (file://) build. Same field names, same observable
   * category map, same x_scope_note red line — so the JSON a user copies
   * here is byte-for-byte the shape the real actor pipeline emits.
   *
   * Why STIX Observed Data: a exposure finding ("this email is public on
   * this page, first/last observed at T, with this content hash") is exactly
   * an OASIS STIX 2.1 Observed Data object — first_observed / last_observed
   * + an objects bag of observables. That is the de-facto interchange shape
   * that OpenCTI ingests and MISP maps to attributes/objects, so a user can
   * export ONE finding and hand it to a takedown request, a SIEM, or a CTI
   * platform without reformatting.
   *
   * Ref: OASIS STIX 2.1 — Observed Data SDO + Indicator pattern; OpenCTI /
   * MISP STIX 2.1 interop (OpenCTI ingests STIX bundles; MISP <-> STIX
   * mapping of attributes to Cyber-observable Objects).
   *
   * RED LINE (unchanged from the shared module): an Observed Data object only
   * describes a PUBLIC observation of the SELF subject's footprint. No
   * inference, no third-private-party identity, no romance/intimacy slot.
   * NO FAKE DATA: in this offline template the value/url/hash fields are the
   * literal string "<TEMPLATE — filled on a real scoped run>"; nothing is
   * fabricated as if it were a real scrape.
   * =======================================================================*/

  // 1:1 with OBSERVABLE_CATEGORY in shared/enrich/stix-evidence.js
  const OBSERVABLE_CATEGORY = {
    PII_EMAIL_PUBLIC: "email-addr",
    PII_PHONE_PUBLIC: "phone-number",
    PII_POSTAL_PUBLIC: "postal-address",
    PII_HANDLE_PUBLIC: "user-account",
    PII_GEO_HINT_PUBLIC: "location-hint",
    SECRET_LEAK_PUBLIC: "credential-exposure",
    SELF_PROFILE_URL: "url",
    SELF_USERNAME: "user-account",
    TRACKER_THIRD_PARTY: "tracking-tech",
    TRACKER_FINGERPRINTING: "tracking-tech",
    TRACKER_SESSION_RECORDING: "tracking-tech",
    TRACKER_KEYLOGGING: "tracking-tech",
    COOKIE_THIRD_PARTY: "cookie",
    LEAK_REFERRER: "url",
    BREACH_RANGE_HIT: "credential-exposure",
    EXPOSURE_SUMMARY: "observed-data"
  };

  // Deterministic STIX-ish id (djb2), mirrors deterministicId() in the module.
  function stixId(type) {
    const parts = Array.prototype.slice.call(arguments, 1);
    const s = parts.map(String).join("|");
    let h = 5381;
    for (let i = 0; i < s.length; i += 1) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
    return type + "--" + h.toString(16).padStart(8, "0");
  }

  const STIX_TEMPLATE = "<TEMPLATE — filled on a real scoped run>";

  // Map an event type to the SpiderFoot-style detector module that emits it,
  // mirroring the source_module values the real pipeline sets.
  const EVENT_SOURCE_MODULE = {
    PII_EMAIL_PUBLIC: "sfp_pii", PII_PHONE_PUBLIC: "sfp_pii", PII_POSTAL_PUBLIC: "sfp_pii",
    PII_HANDLE_PUBLIC: "sfp_pii", PII_GEO_HINT_PUBLIC: "sfp_pii",
    TRACKER_THIRD_PARTY: "sfp_tracker", TRACKER_FINGERPRINTING: "sfp_tracker",
    TRACKER_SESSION_RECORDING: "sfp_tracker", TRACKER_KEYLOGGING: "sfp_tracker",
    COOKIE_THIRD_PARTY: "sfp_tracker", LEAK_REFERRER: "sfp_tracker",
    SECRET_LEAK_PUBLIC: "sfp_secret", BREACH_RANGE_HIT: "sfp_breach",
    SELF_PROFILE_URL: "sfp_accounts", SELF_USERNAME: "sfp_accounts"
  };

  // Build the STIX 2.1 Observed Data object for a template finding item.
  // Shape matches toObservedData(event) exactly; template strings stand in
  // for fields a real scoped run would populate (no fabricated values).
  function observedDataTemplate(it) {
    const category = OBSERVABLE_CATEGORY[it.event] || "observed-data";
    const id = stixId("observed-data", it.event, STIX_TEMPLATE, "template");
    return {
      type: "observed-data",
      spec_version: "2.1",
      id: id,
      created: STIX_TEMPLATE,
      modified: STIX_TEMPLATE,
      first_observed: STIX_TEMPLATE,
      last_observed: STIX_TEMPLATE,
      number_observed: 1,
      x_source_module: EVENT_SOURCE_MODULE[it.event] || "sfp_detector",
      x_event_type: it.event,
      x_scope_note: "Public observation of the SELF subject footprint. No third-party-private inference.",
      x_confidence: STIX_TEMPLATE,
      x_visibility: it.vis,
      x_risk: it.sev,
      x_source_url: STIX_TEMPLATE,
      x_integrity: {
        content_sha256: STIX_TEMPLATE,
        html_sha256: STIX_TEMPLATE,
        html_key: STIX_TEMPLATE,
        screenshot_key: STIX_TEMPLATE
      },
      objects: {
        0: { type: category, x_value: STIX_TEMPLATE, x_meta: {} }
      }
    };
  }

  // Render the per-finding "Portable evidence" detail block. Reuses existing
  // card tokens; the ONE primary (magenta) action is the copy button.
  function stixEvidenceBlock(it) {
    const od = observedDataTemplate(it);
    const cat = OBSERVABLE_CATEGORY[it.event] || "observed-data";
    const wrap = el("details", "stix-ev");

    const summary = el("summary", "stix-summary");
    summary.appendChild(el("span", "stix-summary-label",
      "可移植证据 · STIX 2.1 Observed Data（OpenCTI / MISP 互通）"));
    summary.appendChild(el("span", "stix-cat-chip", esc(cat)));
    wrap.appendChild(summary);

    const note = el("p", "stix-note");
    note.innerHTML =
      "把这条发现导出为 OASIS <b>STIX 2.1 Observed Data</b> 对象（含 " +
      "<code>first_observed</code> / <code>last_observed</code> / 内容哈希 / observable 类别），" +
      "可直接交给下架请求、SIEM 或 OpenCTI / MISP。下面是真实运行会填充的 JSON 形状——" +
      "本离线模板里所有取值字段均为占位串，<b>不是</b>抓取数据。";
    wrap.appendChild(note);

    const pre = el("pre", "stix-json");
    pre.appendChild(el("code", null, esc(JSON.stringify(od, null, 2))));
    wrap.appendChild(pre);

    const actions = el("div", "stix-actions");
    const copyBtn = el("button", "btn btn-primary btn-tiny", "复制 STIX JSON");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", function () {
      const text = JSON.stringify(od, null, 2);
      const done = function () { copyBtn.textContent = "已复制 ✓"; setTimeout(function () { copyBtn.textContent = "复制 STIX JSON"; }, 1600); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
    actions.appendChild(copyBtn);
    actions.appendChild(el("span", "stix-template-flag", "模板 · 无真实数据"));
    wrap.appendChild(actions);

    const ref = el("p", "stix-ref");
    ref.innerHTML =
      "代码：<b>shared/enrich/stix-evidence.js</b>（toObservedData / toBundle，与此处同字段）。" +
      "引用：OASIS STIX 2.1 Observed Data SDO + Indicator pattern；OpenCTI / MISP STIX 2.1 互通映射。";
    wrap.appendChild(ref);

    return wrap;
  }

  /* ---- REAL finding -> STIX Observed Data --------------------------------
   * When a produced report is loaded, build the STIX 2.1 Observed Data object
   * from the finding's ACTUAL values (event_type, source_url, risk, visibility,
   * confidence, source_module). Fields a synthetic fixture genuinely lacks
   * (timestamps, content hash) are rendered as the report's own placeholder so
   * provenance stays honest — we never invent a hash or a capture time. */
  function observedDataReal(f, report) {
    const ev = String(f.event_type || "");
    const category = OBSERVABLE_CATEGORY[ev] || "observed-data";
    const synthetic = report && /SYNTHETIC|TEMPLATE/i.test(String(report.__label || ""));
    const ph = synthetic ? "<SYNTHETIC fixture — no real capture timestamp/hash>" : null;
    const id = stixId("observed-data", ev, f.source_url || "", String(f.confidence));
    return {
      type: "observed-data",
      spec_version: "2.1",
      id: id,
      created: report && report.generated_at ? report.generated_at : ph,
      modified: report && report.generated_at ? report.generated_at : ph,
      first_observed: ph,
      last_observed: ph,
      number_observed: 1,
      x_source_module: f.source_module || EVENT_SOURCE_MODULE[ev] || "sfp_detector",
      x_event_type: ev,
      x_scope_note: "Public observation of the SELF subject footprint. No third-party-private inference.",
      x_confidence: f.confidence != null ? f.confidence : ph,
      x_visibility: f.visibility || null,
      x_risk: f.risk || null,
      x_severity_band: f.severity_band || null,
      x_source_url: f.source_url != null ? f.source_url : ph,
      x_integrity: { content_sha256: ph, html_sha256: ph, html_key: ph, screenshot_key: ph },
      objects: { 0: { type: category, x_value: ph, x_meta: {} } }
    };
  }

  // Per-real-finding portable evidence block (collapsible, mirrors the template
  // one but populated from the loaded report's actual finding values).
  function stixEvidenceBlockReal(f, report) {
    const ev = String(f.event_type || "");
    const od = observedDataReal(f, report);
    const cat = OBSERVABLE_CATEGORY[ev] || "observed-data";
    const wrap = el("details", "stix-ev");
    const summary = el("summary", "stix-summary");
    summary.appendChild(el("span", "stix-summary-label",
      "可移植证据 · STIX 2.1 Observed Data（OpenCTI / MISP 互通）"));
    summary.appendChild(el("span", "stix-cat-chip", esc(cat)));
    wrap.appendChild(summary);

    const note = el("p", "stix-note");
    note.innerHTML =
      "本对象由<b>真实检测器发现</b>填充（event_type / source_url / confidence / risk / source_module 来自加载的报告）。" +
      "时间戳与内容哈希等字段在合成 fixture 上以占位串呈现——指向真实经闸门的抓取即会写入真实哈希，绝不编造。";
    wrap.appendChild(note);

    const pre = el("pre", "stix-json");
    pre.appendChild(el("code", null, esc(JSON.stringify(od, null, 2))));
    wrap.appendChild(pre);

    const actions = el("div", "stix-actions");
    const copyBtn = el("button", "btn btn-primary btn-tiny", "复制 STIX JSON");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", function () {
      const text = JSON.stringify(od, null, 2);
      const done = function () { copyBtn.textContent = "已复制 ✓"; setTimeout(function () { copyBtn.textContent = "复制 STIX JSON"; }, 1600); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
    actions.appendChild(copyBtn);
    actions.appendChild(el("span", "stix-template-flag",
      (report && /SYNTHETIC|TEMPLATE/i.test(String(report.__label || ""))) ? "合成 fixture · 真实检测器产出" : "真实流水线产出"));
    wrap.appendChild(actions);

    const ref = el("p", "stix-ref");
    ref.innerHTML =
      "代码：<b>shared/enrich/stix-evidence.js</b>（toObservedData，与此处同字段）。" +
      "引用：OASIS STIX 2.1 Observed Data SDO；OpenCTI / MISP STIX 2.1 互通映射。";
    wrap.appendChild(ref);
    return wrap;
  }

  // Clipboard fallback for older/file:// browsers without async clipboard.
  function fallbackCopy(text) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "absolute";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    } catch (e) { /* no-op: copy unavailable offline */ }
  }

  /* Audit COVERAGE summary — a Blacklight-style top-line that tells the user, at
   * a glance, what the self-audit battery checks BEFORE they read the per-category
   * detail. Sharpens the report hierarchy: coverage → categories → findings.
   *
   * NO FAKE DATA: every number here is COUNTED from the real FINDING_GROUPS check
   * catalog rendered below — it describes the audit SCHEMA ("会检查什么"), never a
   * scraped result. Labels make that explicit so it can't be read as findings. */
  /* =========================================================================
   * SELF-EXPOSURE GRADE  (A+…F)  —  plain hero letter, no gauge/dial/animation.
   *
   * This mirrors, byte-for-byte, the rubric in integrations/grade/exposure-grade.js:
   *   - same frozen GRADE_BANDS thresholds (A+=100, A=90, …, F<40)
   *   - same letterFor() band map
   * It is a Mozilla HTTP Observatory / SecurityHeaders-style grade: start from a
   * baseline 100 and SUBTRACT weighted, capped, repeat-damped per-category
   * deductions, then map the 0..100 score to an A–F letter. We INVERT the target
   * from "site security headers" to "this person's OWN public exposure".
   * Refs (same as the module): developer.mozilla.org/en-US/observatory/docs;
   * github.com/mozilla/http-observatory scoring.md.
   *
   * NO FAKE DATA: the letter is rendered ONLY from a REAL produced report JSON
   * (the Node grade-module output). With no real scan we render the module's own
   * EMPTY-IN ⇒ NO GRADE semantics ("尚未扫描 · 暂无评分"), and NEVER default an
   * unscanned subject to A. The web does not invent a score from template checks.
   * =======================================================================*/
  const GRADE_BANDS = [
    { grade: "A+", min: 100 }, { grade: "A", min: 90 }, { grade: "A-", min: 85 },
    { grade: "B+", min: 80 }, { grade: "B", min: 75 }, { grade: "B-", min: 70 },
    { grade: "C+", min: 65 }, { grade: "C", min: 60 }, { grade: "C-", min: 55 },
    { grade: "D+", min: 50 }, { grade: "D", min: 45 }, { grade: "D-", min: 40 },
    { grade: "F", min: 0 }
  ];
  function letterFor(score) {
    const s = Math.max(0, Math.min(100, Number(score) || 0));
    for (const b of GRADE_BANDS) { if (s >= b.min) return b.grade; }
    return "F";
  }
  // plain-language one-liner per band family (Observatory-style "what it means")
  const GRADE_MEANING = {
    A: "暴露面很小：第三方很难轻易拼出关于你的画像。保持现状即可。",
    B: "暴露面较小：有少量公开痕迹可清理，但整体可控。",
    C: "中等暴露：存在若干公开信息点，建议按下方清单逐条处置。",
    D: "暴露偏高：多处公开痕迹可被串联，建议尽快处理高暴露项。",
    F: "暴露很高：关键个人信息公开可得，应优先处置高暴露与密钥泄露项。"
  };
  function gradeFamily(letter) {
    if (!letter) return "none";
    const c = letter[0].toLowerCase();
    return ["a", "b", "c", "d", "f"].includes(c) ? c : "none";
  }

  // Validate a produced report into a grade view-model, or null if not gradeable.
  // Accepts either the grade-module shape ({graded,grade,score,...}) directly, or
  // a report-builder report carrying a `grade` block / an `exposure_score`.
  function gradeFromReport(report) {
    if (!report || typeof report !== "object") return null;
    const g = report.grade || report.exposure_grade || null;
    if (g && typeof g === "object") {
      if (g.graded === false || g.grade == null) {
        return { graded: false, reason: g.reason || "no_data" };
      }
      return {
        graded: true, grade: String(g.grade), score: g.score,
        total_deduction: g.total_deduction, event_count: g.event_count,
        counted_event_count: g.counted_event_count,
        severity_band: g.severity_band, source: report.__source || null
      };
    }
    // fall back to a bare numeric exposure_score if that's all the report carries
    const sc = report.exposure_score != null ? report.exposure_score
             : (report.scores && report.scores.exposure_score);
    if (typeof sc === "number" && Number.isFinite(sc)) {
      return { graded: true, grade: letterFor(sc), score: Math.round(sc), source: report.__source || null };
    }
    return null;
  }

  function renderExposureGrade(vm) {
    const wrap = document.getElementById("exposureGrade");
    if (!wrap) return;
    wrap.innerHTML = "";

    // ---- honest EMPTY-IN ⇒ NO GRADE state (mirrors module graded:false) ----
    if (!vm || vm.graded === false) {
      const letter = el("div", "grade-letter g-none", "—");
      letter.setAttribute("role", "img");
      letter.setAttribute("aria-label", "尚未扫描，暂无评分");
      const body = el("div", "grade-body");
      body.appendChild(el("p", "grade-eyebrow", "暴露评分 · EXPOSURE GRADE"));
      body.appendChild(el("p", "grade-meaning", "尚未扫描 · 暂无评分"));
      body.appendChild(el("p", "grade-detail",
        "评分只在一次真实自审运行后给出。未扫描的对象不会被默认评为 A——「没有数据」就如实显示为「无评分」，绝不编造分数。"));
      // GOV.UK Design System: an empty/zero state should tell the user what they
      // can DO next, not just state absence. Point to Step 1 (the gate) so the
      // no-grade card is an actionable starting point, not a dead end.
      const next = el("p", "grade-next");
      next.innerHTML =
        "下一步：到<a href=\"#gate\">第 1 步 · 合规闸门</a>用 <code>self</code> 范围通过，再运行一次真实自审即可得到评分。";
      body.appendChild(next);
      body.appendChild(el("p", "grade-note",
        "评分模型：Mozilla HTTP Observatory / SecurityHeaders 式 A–F（基线 100 减去加权扣分）。代码：integrations/grade/exposure-grade.js。"));
      wrap.appendChild(letter);
      wrap.appendChild(body);
      return;
    }

    // ---- real graded state ----
    const letter = String(vm.grade);
    const fam = gradeFamily(letter);
    const letterEl = el("div", "grade-letter g-" + fam, esc(letter));
    letterEl.setAttribute("role", "img");
    letterEl.setAttribute("aria-label", "暴露评分 " + letter + (vm.score != null ? "，分数 " + vm.score + " / 100" : ""));

    const body = el("div", "grade-body");
    body.appendChild(el("p", "grade-eyebrow", "暴露评分 · EXPOSURE GRADE"));
    body.appendChild(el("p", "grade-meaning", GRADE_MEANING[fam.toUpperCase()] || ("评分 " + letter)));

    const bits = [];
    if (vm.score != null) bits.push("分数 " + vm.score + " / 100");
    if (vm.total_deduction != null) bits.push("总扣分 " + vm.total_deduction);
    if (vm.counted_event_count != null) bits.push("计分发现 " + vm.counted_event_count + " 条");
    if (vm.severity_band) bits.push("最严重等级 " + vm.severity_band);
    if (bits.length) body.appendChild(el("p", "grade-detail", esc(bits.join(" · "))));

    // compact A–F scale strip, current band highlighted (Observatory legend, no dial)
    const scale = el("div", "grade-scale");
    scale.setAttribute("aria-hidden", "true");
    ["A+", "A", "B", "C", "D", "F"].forEach(g => {
      const cur = letter[0].toUpperCase() === g[0] && (g.length === 1 || g === letter);
      scale.appendChild(el("span", "gs" + (cur ? " cur" : ""), g));
    });
    body.appendChild(scale);

    const note = el("p", "grade-note", null);
    const src = vm.source ? "来源：" + esc(vm.source) + "（合成/模板 fixture 经真实检测器流水线产出，非编造抓取结果）。 " : "";
    note.innerHTML = src +
      "评分模型：Mozilla HTTP Observatory / SecurityHeaders 式 A–F（基线 100 减加权扣分）。代码：<code>integrations/grade/exposure-grade.js</code>。";
    body.appendChild(note);

    wrap.appendChild(letterEl);
    wrap.appendChild(body);
  }

  function renderCoverage() {
    const wrap = document.getElementById("coverageSummary");
    if (!wrap) return;
    wrap.innerHTML = "";

    const cats = FINDING_GROUPS.length;
    const checks = FINDING_GROUPS.reduce((n, g) => n + g.items.length, 0);
    const sev = { high: 0, medium: 0, low: 0, info: 0 };
    FINDING_GROUPS.forEach(g => g.items.forEach(it => {
      if (sev[it.sev] != null) sev[it.sev] += 1;
    }));

    // one plain top-line stat row (HIBP/Blacklight: lead with the count)
    const stats = el("div", "cov-stats");
    [
      { n: cats, label: "暴露类别" },
      { n: checks, label: "检查项" }
    ].forEach(s => {
      const cell = el("div", "cov-stat");
      cell.appendChild(el("span", "cov-num", String(s.n)));
      cell.appendChild(el("span", "cov-lbl", s.label));
      stats.appendChild(cell);
    });

    // severity-weight distribution of the checks (not findings) — a labelled bar
    const distWrap = el("div", "cov-dist");
    distWrap.appendChild(el("span", "cov-dist-label", "检查项按暴露等级分布"));
    const bar = el("div", "cov-bar", null);
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label",
      "高暴露 " + sev.high + " 项，中暴露 " + sev.medium + " 项，低暴露 " + sev.low + " 项");
    [["high", "高"], ["medium", "中"], ["low", "低"]].forEach(([k]) => {
      if (!sev[k]) return;
      const seg = el("div", "cov-seg " + k);
      seg.style.flexGrow = String(sev[k]);
      bar.appendChild(seg);
    });
    distWrap.appendChild(bar);
    const legend = el("div", "cov-legend");
    [["high", "高暴露", sev.high], ["medium", "中暴露", sev.medium], ["low", "低暴露", sev.low]]
      .forEach(([k, name, n]) => {
        if (!n) return;
        const li = el("span", "cov-leg-item");
        li.appendChild(el("span", "cov-leg-dot " + k));
        li.appendChild(el("span", null, name + " " + n + " 项"));
        legend.appendChild(li);
      });
    distWrap.appendChild(legend);

    wrap.appendChild(stats);
    wrap.appendChild(distWrap);

    // honesty line: this is coverage/schema, not findings
    wrap.appendChild(el("p", "cov-note",
      "以上是本次自审「会检查什么」的覆盖范围（审计 schema），不是抓取结果。" +
      "真实运行经闸门、scope=self 后，命中的条目才会带 URL+时间戳+哈希填入下方各类别。"));
  }

  // Pull the REAL findings array out of a produced report (the detector output).
  function reportFindings(report) {
    if (!report || typeof report !== "object") return [];
    const f = report.findings;
    return Array.isArray(f) ? f.filter(x => x && x.event_type) : [];
  }
  function isSynthetic(report) {
    return !!(report && /SYNTHETIC|TEMPLATE/i.test(String(report.__label || "")));
  }
  const RISK_RANK = { high: 3, medium: 2, low: 1, info: 0 };

  // Render the unmistakable provenance banner above the report data whenever a
  // report is loaded: shows the report's own __label/__notice so a reader can
  // see at a glance whether the data is a SYNTHETIC fixture or live output.
  function renderProvenance(report) {
    const wrap = document.getElementById("reportProvenance");
    if (!wrap) return;
    wrap.innerHTML = "";
    if (!report) { wrap.hidden = true; return; }
    wrap.hidden = false;
    wrap.className = "report-provenance " + (isSynthetic(report) ? "synthetic" : "live");
    const tag = el("span", "prov-tag", isSynthetic(report) ? "合成 fixture · 真实检测器→评分流水线" : "真实流水线产出");
    wrap.appendChild(tag);
    if (report.__label) wrap.appendChild(el("p", "prov-label", esc(report.__label)));
    if (report.__notice) wrap.appendChild(el("p", "prov-notice", esc(report.__notice)));
    const src = [];
    if (report.generated_at) src.push("生成时间 " + report.generated_at);
    if (report.provenance && report.provenance.fixture) src.push("fixture " + report.provenance.fixture);
    if (src.length) wrap.appendChild(el("p", "prov-src", esc(src.join(" · "))));
  }

  // Dispatcher: real report findings if one is loaded, else the template catalog.
  function renderFindings() {
    if (reportFindings(LOADED_REPORT).length) { renderRealFindings(LOADED_REPORT); return; }
    renderTemplateCatalog();
  }

  // Group the report's REAL findings under the SAME category structure used by
  // the template catalog, so the vocabulary is identical. Each group shows its
  // real instance count + worst risk; each finding shows its real source URL,
  // confidence, risk and visibility, plus a real-valued STIX evidence block.
  function renderRealFindings(report) {
    const wrap = document.getElementById("findingsGroups");
    if (!wrap) return;
    wrap.innerHTML = "";
    const findings = reportFindings(report);

    // bucket findings by their category (groupId via EVENT_META)
    const byGroup = {};
    findings.forEach(f => {
      const meta = EVENT_META[f.event_type];
      const gid = meta ? meta.groupId : "other";
      (byGroup[gid] = byGroup[gid] || []).push(f);
    });

    // preserve FINDING_GROUPS order; only render groups that actually have hits
    FINDING_GROUPS.forEach(g => {
      const list = byGroup[g.id];
      if (!list || !list.length) return;
      // worst risk in this group, for the count badge tone
      list.sort((a, b) => (RISK_RANK[b.risk] || 0) - (RISK_RANK[a.risk] || 0));
      const worst = list[0].risk || "low";

      const card = el("div", "finding-group");
      const head = el("div", "fg-head");
      head.appendChild(el("span", "fg-icon", esc(g.icon)));
      const titleWrap = el("div");
      titleWrap.appendChild(el("div", "fg-title", esc(g.title)));
      titleWrap.appendChild(el("div", "fg-module", esc(g.module)));
      head.appendChild(titleWrap);
      head.appendChild(el("span", "fg-count real " + worst, list.length + " 条发现"));
      card.appendChild(head);

      const body = el("div", "fg-body");
      body.appendChild(el("p", "fg-desc", esc(g.desc)));

      list.forEach(f => {
        const meta = EVENT_META[f.event_type] || {};
        const item = el("div", "finding-item real");
        const row = el("div", "fi-row");
        row.appendChild(el("span", "fi-name", esc(meta.name || f.event_type)));
        const risk = f.risk || meta.sev || "low";
        row.appendChild(el("span", "sev-badge " + risk, esc((SEV_LABEL[risk] || risk) + "暴露")));
        const vis = f.visibility || meta.vis;
        if (vis) row.appendChild(el("span", "vis-badge", esc(VIS_LABEL[vis] || vis)));
        row.appendChild(el("span", "event-chip", esc(f.event_type)));
        item.appendChild(row);

        // real evidence one-liner: source URL + confidence + source module
        const facts = el("p", "fi-facts");
        const conf = (f.confidence != null) ? "置信度 " + f.confidence : "";
        const urlTxt = f.source_url ? f.source_url : "（无公开 URL — 如 k-匿名泄露比对）";
        facts.innerHTML =
          "<b>来源：</b>" + esc(urlTxt) +
          (conf ? " · " + esc(conf) : "") +
          (f.source_module ? " · " + esc(f.source_module) : "");
        item.appendChild(facts);

        if (meta.why) {
          const why = el("p", "fi-why");
          why.innerHTML = "<b>为什么重要：</b>" + esc(meta.why);
          item.appendChild(why);
        }
        if (meta.fix) item.appendChild(el("p", "fi-fix", "建议处置：" + esc(meta.fix)));

        item.appendChild(stixEvidenceBlockReal(f, report));
        body.appendChild(item);
      });

      card.appendChild(body);
      wrap.appendChild(card);
    });

    // any findings whose event_type isn't in the catalog (defensive, no fabrication)
    const known = new Set(Object.keys(EVENT_META));
    const orphans = findings.filter(f => !known.has(f.event_type));
    if (orphans.length) {
      const card = el("div", "finding-group");
      const head = el("div", "fg-head");
      head.appendChild(el("span", "fg-icon", "◌"));
      const tw = el("div");
      tw.appendChild(el("div", "fg-title", "其他检测器发现"));
      tw.appendChild(el("div", "fg-module", "未在前端目录中的 event_type"));
      head.appendChild(tw);
      head.appendChild(el("span", "fg-count real low", orphans.length + " 条发现"));
      card.appendChild(head);
      const body = el("div", "fg-body");
      orphans.forEach(f => {
        const item = el("div", "finding-item real");
        const row = el("div", "fi-row");
        row.appendChild(el("span", "fi-name", esc(f.event_type)));
        const risk = f.risk || "low";
        row.appendChild(el("span", "sev-badge " + risk, esc((SEV_LABEL[risk] || risk) + "暴露")));
        item.appendChild(row);
        if (f.source_url) item.appendChild(el("p", "fi-facts", "来源：" + esc(f.source_url)));
        item.appendChild(stixEvidenceBlockReal(f, report));
        body.appendChild(item);
      });
      card.appendChild(body);
      wrap.appendChild(card);
    }
  }

  // The honest TEMPLATE catalog (no report loaded): "what we look for".
  function renderTemplateCatalog() {
    const wrap = document.getElementById("findingsGroups");
    if (!wrap) return;
    wrap.innerHTML = "";
    FINDING_GROUPS.forEach(g => {
      const card = el("div", "finding-group");

      const head = el("div", "fg-head");
      head.appendChild(el("span", "fg-icon", esc(g.icon)));
      const titleWrap = el("div");
      titleWrap.appendChild(el("div", "fg-title", esc(g.title)));
      titleWrap.appendChild(el("div", "fg-module", esc(g.module)));
      head.appendChild(titleWrap);
      head.appendChild(el("span", "fg-count", g.items.length + " 项检查"));
      card.appendChild(head);

      const body = el("div", "fg-body");
      body.appendChild(el("p", "fg-desc", esc(g.desc)));

      // The breach group gets a LIVE, HONEST k-anonymity demonstrator so a user
      // can see EXACTLY what the breach-range check would send for their OWN
      // credential vs. what stays local — without ever querying a breach corpus
      // offline. (See kAnonPanel below.)
      if (g.id === "breach") body.appendChild(kAnonPanel());

      g.items.forEach(it => {
        const item = el("div", "finding-item");
        const row = el("div", "fi-row");
        row.appendChild(el("span", "fi-name", esc(it.name)));
        row.appendChild(el("span", "sev-badge " + it.sev, esc((SEV_LABEL[it.sev] || it.sev) + "暴露")));
        row.appendChild(el("span", "vis-badge", esc(VIS_LABEL[it.vis] || it.vis)));
        row.appendChild(el("span", "event-chip", esc(it.event)));
        item.appendChild(row);

        const why = el("p", "fi-why");
        why.innerHTML = "<b>为什么重要：</b>" + esc(it.why);
        item.appendChild(why);

        item.appendChild(el("p", "fi-fix", "建议处置：" + esc(it.fix)));

        const q = el("div", "fi-quality");
        q.appendChild(el("span", "q-dot"));
        q.appendChild(el("span", null, "evidence_quality：待真实运行（来源权威性 + 时间戳 + 完整性）"));
        q.appendChild(el("span", "fi-template-flag", "模板检查项 · 无真实数据"));
        item.appendChild(q);

        // Portable evidence detail — the existing module's STIX 2.1 Observed
        // Data shape, surfaced per finding so a user can export/hand off.
        item.appendChild(stixEvidenceBlock(it));

        body.appendChild(item);
      });

      card.appendChild(body);
      wrap.appendChild(card);
    });
  }

  function renderClusterCard() {
    const body = document.getElementById("clusterBody");
    const keys = document.getElementById("clusterKeys");
    if (!body || !keys) return;
    body.textContent =
      "关联引擎（同 SpiderFoot 关联引擎，对应 shared/enrich/cluster-keys.js）会把共享同一关联键的事件聚合成一个「自我暴露簇」。" +
      "例如多个 PII / 账号事件共享同一 handle 或同一 email-hash 时，会被聚合并给出置信度。真实运行时簇会附带可引用的 evidence index。";
    keys.innerHTML = "";
    ["normalizeHandle(用户名)", "email-hash 前缀", "hostOf(同一站点)"].forEach(k => {
      keys.appendChild(el("li", null, esc(k)));
    });
  }

  // Adjust the report banner + cluster note depending on the latest gate verdict.
  function updateReportForScope(res) {
    const banner = document.getElementById("reportGateBanner");
    if (!banner) return;
    const scope = res && res.accepted ? res.scope : null;
    const applies = scope === "self" || scope === "public_figure";
    if (applies) {
      banner.className = "report-banner applies";
      banner.innerHTML = "✓ 闸门已放行 <code>" + esc(scope) + "</code>。" + esc(scope === "public_figure" ? PUBLIC_FIGURE_NOTE : SELF_NOTE);
    } else if (res && res.accepted) {
      banner.className = "report-banner";
      banner.innerHTML = "闸门放行了 <code>" + esc(res.scope) + "</code>，但「第三方能发现你什么」的自审框架只适用于 <code>self</code> / <code>public_figure</code>。下面显示的是完整检查项目录。";
    } else {
      banner.className = "report-banner";
      banner.innerHTML = '先在<a href="#gate">第 1 步</a>用 <code>self</code> 或 <code>public_figure</code> 范围通过闸门，下面的检查项就会按你的范围呈现。当前显示的是完整检查项目录。';
    }
  }

  /* =========================================================================
   * LIVE k-ANONYMITY BREACH MECHANIC (HIBP Pwned Passwords range API)
   *
   * Ref: Troy Hunt, "Pwned Passwords" k-anonymity range query. To check a secret
   * we SHA-1 it locally, send ONLY the 5-char hex prefix, and match the 35-char
   * suffix locally — the secret never leaves the device. This mirrors the EXACT
   * prefix/suffix split contract in shared/aux/kanon.js (uppercase hex, prefix=5,
   * suffix=35) so the UI and the actor module agree byte-for-byte.
   *
   * NO FAKE DATA: this offline demo NEVER queries a real breach corpus and NEVER
   * shows a breach hit or count. It proves the privacy split mechanic only.
   *
   * Implementation note: crypto.subtle requires a secure context and is absent on
   * file://, so we ship a tiny pure-JS SHA-1 so the demo works fully offline.
   * =======================================================================*/

  // Minimal, dependency-free SHA-1 -> UPPERCASE hex (matches kanon.js sha1Hex).
  function sha1HexUpper(str) {
    function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
    // UTF-8 encode
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c < 0x80) bytes.push(c);
      else if (c < 0x800) { bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
      else if (c < 0xd800 || c >= 0xe000) {
        bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      } else {
        // surrogate pair
        i++;
        c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
        bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f),
          0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      }
    }
    const ml = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    // 64-bit big-endian length (high 32 bits assumed 0 for these short inputs)
    for (let i = 7; i >= 0; i--) bytes.push((i < 4) ? (ml >>> (i * 8)) & 0xff : 0);

    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    const w = new Array(80);
    for (let i = 0; i < bytes.length; i += 64) {
      for (let j = 0; j < 16; j++) {
        w[j] = (bytes[i + j * 4] << 24) | (bytes[i + j * 4 + 1] << 16)
          | (bytes[i + j * 4 + 2] << 8) | (bytes[i + j * 4 + 3]);
      }
      for (let j = 16; j < 80; j++) w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
      let a = h0, b = h1, cc = h2, d = h3, e = h4;
      for (let j = 0; j < 80; j++) {
        let f, k;
        if (j < 20) { f = (b & cc) | (~b & d); k = 0x5A827999; }
        else if (j < 40) { f = b ^ cc ^ d; k = 0x6ED9EBA1; }
        else if (j < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else { f = b ^ cc ^ d; k = 0xCA62C1D6; }
        const t = (rotl(a, 5) + f + e + k + w[j]) | 0;
        e = d; d = cc; cc = rotl(b, 30); b = a; a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + cc) | 0;
      h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }
    function hx(n) { return ("00000000" + (n >>> 0).toString(16)).slice(-8); }
    return (hx(h0) + hx(h1) + hx(h2) + hx(h3) + hx(h4)).toUpperCase();
  }

  // Same contract as shared/aux/kanon.js kAnonPair: {hash, prefix(5), suffix(35)}.
  function kAnonPair(secret) {
    const hash = sha1HexUpper(String(secret == null ? "" : secret));
    return { hash: hash, prefix: hash.slice(0, 5), suffix: hash.slice(5) };
  }

  function renderKanonResult(secret) {
    const out = document.getElementById("kanonOut");
    if (!out) return;
    out.innerHTML = "";
    const trimmed = (secret || "").trim();
    if (!trimmed) {
      const h = el("p", "kanon-hint kanon-err", "请输入任意字符串（你自己的口令或邮箱）再计算。");
      out.appendChild(h);
      return;
    }
    const pair = kAnonPair(trimmed);

    const split = el("div", "kanon-split");
    split.innerHTML = '<span class="kanon-prefix">' + esc(pair.prefix) + '</span>'
      + '<span class="kanon-suffix">' + esc(pair.suffix) + '</span>';
    out.appendChild(split);

    const legend = el("div", "kanon-legend");

    const rowSent = el("div", "kanon-leg-row");
    rowSent.appendChild(el("span", "kanon-chip sent", "会发送"));
    rowSent.appendChild(el("code", "kanon-mono", esc(pair.prefix)));
    rowSent.appendChild(el("span", "kanon-leg-note",
      "5 位十六进制前缀 = 1 个 range 桶（16^5 ≈ 104 万桶），成千上万哈希共享，服务器无法分辨你查的是哪一个。"));
    legend.appendChild(rowSent);

    const rowLocal = el("div", "kanon-leg-row");
    rowLocal.appendChild(el("span", "kanon-chip local", "留在本地"));
    rowLocal.appendChild(el("code", "kanon-mono", esc(pair.suffix)));
    rowLocal.appendChild(el("span", "kanon-leg-note",
      "35 位后缀永不离开你的设备；真实查询时只在本地把它和返回桶里的候选比对。"));
    legend.appendChild(rowLocal);

    out.appendChild(legend);

    const note = el("p", "kanon-hint");
    note.innerHTML = "离线演示：<b>没有查询任何真实泄露库</b>，因此这里不显示任何泄露命中或次数——"
      + "这证明的是隐私拆分机制，不是泄露结果。真实判定由 actors/breach-check 经 HIBP range API 完成。";
    out.appendChild(note);
  }

  function wireKanon() {
    const runBtn = document.getElementById("kanonRun");
    const clearBtn = document.getElementById("kanonClear");
    const input = document.getElementById("kanonInput");
    if (!runBtn || !input) return;
    runBtn.addEventListener("click", () => renderKanonResult(input.value));
    input.addEventListener("keydown", e => { if (e.key === "Enter") renderKanonResult(input.value); });
    if (clearBtn) clearBtn.addEventListener("click", () => {
      input.value = "";
      const out = document.getElementById("kanonOut");
      if (out) out.innerHTML = '<p class="kanon-hint">输入任意字符串后点击，演示「会发送的 5 位前缀」与「留在本地的 35 位后缀」。</p>';
    });
  }

  /* =========================================================================
   * PIPELINE / MIDDLEWARE ORDER PANEL (Scrapy + Crawlee)
   * Mirrors shared/middleware/stages.js canonical ordering. Static, plain list —
   * no animation, no flashy section; reuses existing card + pipe-list styles.
   * =======================================================================*/

  const PIPE_REQUEST = [
    { ord: "100", name: "scopeGate",
      desc: "重新运行 shared/scope.js 校验：非 self/consented/public_figure/brand/safety_evidence，或带追踪私人个体意图，立即 IgnoreRequest 丢弃（fail-closed，在 fetch 前）。" },
    { ord: "200", name: "robotsTos",
      desc: "尊重 robots.txt / ToS，丢弃登录墙 / 私域社交主机；绝不绕过登录、验证码或封禁。" },
    { ord: "300", name: "rateLimit",
      desc: "按主机最小间隔礼貌限速，超额则重新排队延后，不冲击服务器、不规避限速或封禁。" },
    { ord: "900", name: "fetchTerminal",
      desc: "真实 actor 在此抓取；纯流水线返回明确标注的 TEMPLATE 占位（template:true），绝不伪造抓取数据。" }
  ];
  const PIPE_ITEM = [
    { ord: "100", name: "scopeReassertItem",
      desc: "防御性复核：产出条目必须带合法 scope_type，否则 DropItem，不入库。" },
    { ord: "500", name: "evidenceHash",
      desc: "用 shared/hashing.js 计算 content/html SHA-256，使每条保全证据可被引用、防篡改。" }
  ];

  function renderPipelinePanel() {
    const renderList = (id, rows) => {
      const ol = document.getElementById(id);
      if (!ol) return;
      ol.innerHTML = "";
      rows.forEach(r => {
        const li = el("li");
        li.appendChild(el("span", "pstep", r.ord));
        const body = el("div");
        body.appendChild(el("b", null, esc(r.name)));
        body.appendChild(el("div", null, esc(r.desc)));
        li.appendChild(body);
        ol.appendChild(li);
      });
    };
    renderList("pipeReqList", PIPE_REQUEST);
    renderList("pipeItemList", PIPE_ITEM);
  }

  // Evidence index. With a loaded report: one row per REAL finding (Blacklight's
  // plain evidence table — event, source URL, confidence, visibility, module).
  // With no report: the evidence-index SCHEMA (which fields a real capture fills).
  function renderEvidenceTable() {
    const tbody = document.querySelector("#evTable tbody");
    const headRow = document.getElementById("evHeadRow");
    const head = document.getElementById("evHead");
    const intro = document.getElementById("evIntro");
    if (!tbody) return;
    tbody.innerHTML = "";

    const findings = reportFindings(LOADED_REPORT);
    if (findings.length) {
      if (head) head.textContent = "证据索引 · 真实检测器发现（每行一条）";
      if (intro) intro.innerHTML = isSynthetic(LOADED_REPORT)
        ? "下表每行是<b>真实检测器</b>在合成 fixture 上产出的一条发现（非编造）。展开上方各条的「可移植证据」可得 STIX JSON。"
        : "下表每行是真实流水线产出的一条发现。";
      if (headRow) headRow.innerHTML =
        "<tr><th>event_type</th><th>来源 URL</th><th>置信度</th><th>可见性</th><th>风险</th><th>来源模块</th></tr>";
      findings
        .slice()
        .sort((a, b) => (RISK_RANK[b.risk] || 0) - (RISK_RANK[a.risk] || 0))
        .forEach(f => {
          const tr = el("tr");
          tr.appendChild(el("td", "ev-event", esc(f.event_type)));
          const url = f.source_url ? f.source_url : "—";
          const urlTd = el("td", "ev-url");
          if (f.source_url) {
            const a = el("a", "optout-link", esc(f.source_url));
            a.href = f.source_url; a.target = "_blank"; a.rel = "noopener noreferrer";
            urlTd.appendChild(a);
          } else { urlTd.textContent = url; }
          tr.appendChild(urlTd);
          tr.appendChild(el("td", null, f.confidence != null ? esc(String(f.confidence)) : "—"));
          const vis = f.visibility;
          tr.appendChild(el("td", null, esc(vis ? (VIS_LABEL[vis] || vis) : "—")));
          const risk = f.risk || "low";
          const riskTd = el("td", null, null);
          riskTd.appendChild(el("span", "sev-badge " + risk, esc(SEV_LABEL[risk] || risk)));
          tr.appendChild(riskTd);
          tr.appendChild(el("td", "ev-mod", esc(f.source_module || "—")));
          tbody.appendChild(tr);
        });
      return;
    }

    // no report: honest evidence-index SCHEMA
    if (head) head.textContent = "每条证据的字段 · evidence index";
    if (intro) intro.textContent = "真实运行时，每个发现都会保全为可引用的一行：";
    if (headRow) headRow.innerHTML = "<tr><th>字段</th><th>说明</th></tr>";
    (PLAN.report.evidenceIndexFields || []).forEach(f => {
      const tr = el("tr");
      tr.appendChild(el("td", null, esc(f.field)));
      tr.appendChild(el("td", null, esc(f.desc)));
      tbody.appendChild(tr);
    });
  }

  /* SUGGESTED ACTIONS — the report's "now what do I do" checklist, derived from
   * the loaded report's REAL findings. We collapse findings to ONE action per
   * distinct exposure type, order by worst risk then instance count (Blacklight
   * closes with "what you can do"; GOV.UK ordered task list). With no report we
   * show an honest empty state — we never invent tasks for an unscanned subject. */
  function renderSuggestedActions() {
    const list = document.getElementById("actionList");
    const intro = document.getElementById("actionsIntro");
    const foot = document.getElementById("actionsFoot");
    if (!list) return;
    list.innerHTML = "";

    const findings = reportFindings(LOADED_REPORT);
    if (!findings.length) {
      if (intro) intro.textContent =
        "尚未加载报告 · 暂无处置清单。运行一次真实自审后，这里会按「最高暴露优先」列出每类可执行的下一步。";
      if (foot) foot.innerHTML =
        "处置文案与上方各发现的「建议处置」同源（FINDING_GROUPS.fix）。绝不为未扫描对象编造任务。";
      const li = el("li", "action-empty", "（无发现 → 无建议动作。这是诚实的空状态，不编造任务。）");
      list.appendChild(li);
      return;
    }

    // collapse to one action per event_type, tracking instance count + worst risk
    const byEvent = {};
    findings.forEach(f => {
      const k = f.event_type;
      const rec = byEvent[k] || (byEvent[k] = { event: k, count: 0, worst: "low", sample: f.source_url || null });
      rec.count += 1;
      if ((RISK_RANK[f.risk] || 0) > (RISK_RANK[rec.worst] || 0)) rec.worst = f.risk || rec.worst;
      if (!rec.sample && f.source_url) rec.sample = f.source_url;
    });
    const actions = Object.keys(byEvent).map(k => byEvent[k]);
    actions.sort((a, b) =>
      (RISK_RANK[b.worst] || 0) - (RISK_RANK[a.worst] || 0) || b.count - a.count);

    if (intro) intro.innerHTML = isSynthetic(LOADED_REPORT)
      ? "按<b>最高暴露优先</b>排序，逐条处置（来自真实检测器在合成 fixture 上的发现）："
      : "按<b>最高暴露优先</b>排序，逐条处置：";

    actions.forEach(a => {
      const meta = EVENT_META[a.event] || {};
      const li = el("li", "action-item");
      const head = el("div", "action-head");
      head.appendChild(el("span", "sev-badge " + a.worst, esc((SEV_LABEL[a.worst] || a.worst) + "暴露")));
      head.appendChild(el("span", "action-title", esc(meta.name || a.event)));
      head.appendChild(el("span", "action-count", a.count + " 处"));
      li.appendChild(head);
      li.appendChild(el("p", "action-do", esc(meta.fix || "审查该公开痕迹并评估是否下线/收敛。")));
      if (a.sample) {
        const ref = el("p", "action-ref");
        ref.innerHTML = "示例来源：" + esc(a.sample);
        li.appendChild(ref);
      }
      list.appendChild(li);
    });

    if (foot) foot.innerHTML =
      "处置文案与上方各发现的「建议处置」同源。下方<a href=\"#optoutCard\">数据中介下架</a>是其中最常见的一类具体动作。";
  }

  /* =========================================================================
   * DATA-BROKER OPT-OUT — the concrete self-protection action surfaced in the
   * report. Mirrors the backend opt-out input-builder (shared/optout/): every
   * target is routed through the real scope gate FIRST and self-removal is ONLY
   * ever for the user's OWN listing. The broker registry below is a clearly
   * labelled TEMPLATE carrying each broker's PUBLIC opt-out URL + method — NO
   * fabricated listing data (no "you were found on X"). A confirmed-self listing
   * emits a STIX 2.1 Observed Data object (reuses shared/enrich/stix-evidence.js)
   * + a ready-to-send erasure request (reuses shared/aux/takedown-letter.js) and
   * proposes an Apify Schedule/Webhook re-check so a REAPPEARING listing is
   * re-flagged (Closure-Mode-friendly; integrations/schedules + integrations/webhooks).
   *
   * Ref: OASIS STIX 2.1 Observed Data (OpenCTI/MISP interop) for the per-listing
   * evidence object; Apify Website Content Crawler + RAG Web Browser ingestion
   * for the re-check sweep (the existing WCC/RAG ingest path re-reads the broker
   * page to detect reappearance).
   * =======================================================================*/

  // TEMPLATE registry: PUBLIC opt-out entry points only. Each broker's opt-out
  // URL/method is itself public policy info — NOT a claim that the user is listed.
  const BROKER_REGISTRY = [
    { name: "Spokeo", method: "网页表单 + 邮箱确认", url: "https://www.spokeo.com/optout" },
    { name: "Whitepages", method: "条目移除表单", url: "https://www.whitepages.com/suppression-requests" },
    { name: "BeenVerified", method: "网页表单 + 邮箱确认", url: "https://www.beenverified.com/app/optout/search" },
    { name: "Intelius", method: "网页表单", url: "https://www.intelius.com/opt-out" },
    { name: "Radaris", method: "管理资料后移除", url: "https://radaris.com/page/how-to-remove" },
    { name: "Acxiom", method: "GDPR/CCPA 数据主体请求", url: "https://www.acxiom.com/optout/" }
  ];

  function renderOptout() {
    const tbody = document.querySelector("#optoutTable tbody");
    if (tbody) {
      BROKER_REGISTRY.forEach(b => {
        const tr = el("tr");
        tr.appendChild(el("td", "optout-broker", esc(b.name)));
        tr.appendChild(el("td", "optout-method", esc(b.method)));
        const td = el("td");
        const a = el("a", "optout-link", esc(b.url));
        a.href = b.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        td.appendChild(a);
        tr.appendChild(td);
        tbody.appendChild(tr);
      });
    }

    const flow = document.getElementById("optoutFlow");
    if (flow) {
      const steps = [
        { tag: "闸门", text: "先过合规闸门：scope=self（或 consented）才放行。针对他人的下架请求当场拒绝——这是 self-only 流程。" },
        { tag: "STIX", text: "为该挂牌生成一条 STIX 2.1 Observed Data 证据对象（复用 shared/enrich/stix-evidence.js，与上面报告里的形状一致），记录 URL + 首次/最后观测 + 内容哈希。" },
        { tag: "请求信", text: "套用一封可直接发送的删除/退订请求（复用 shared/aux/takedown-letter.js，GDPR Art.17 / CCPA 口径），按该中介的公开退订方式投递。" },
        { tag: "复检", text: "排一个 Apify Schedule + Webhook 周期复检：若已下架的挂牌重新出现，自动重新标记。复检沿用现有 WCC / RAG 抓取路径重新读取该中介页面。" }
      ];
      steps.forEach(s => {
        const li = el("li", "optout-flow-item");
        li.appendChild(el("span", "optout-flow-tag", esc(s.tag)));
        li.appendChild(el("span", null, esc(s.text)));
        flow.appendChild(li);
      });
    }

    const foot = document.getElementById("optoutFoot");
    if (foot) {
      foot.innerHTML =
        "代码：<b>shared/optout/</b>（input-builder，先过 <b>shared/scope.js</b> 闸门、self-only 拒绝他人）" +
        " · 复用 <b>shared/enrich/stix-evidence.js</b> + <b>shared/aux/takedown-letter.js</b>" +
        " · 复检 <b>integrations/schedules</b> + <b>integrations/webhooks</b>。" +
        "引用：OASIS STIX 2.1 Observed Data（OpenCTI / MISP 互通）；Apify Website Content Crawler + RAG Web Browser 复检抓取。";
    }
  }

  /* =========================================================================
   * CLOSURE MODE
   * =======================================================================*/

  function renderClosure() {
    const c = PLAN.closureMode;
    document.getElementById("closureHead").textContent = c.headline;
    document.getElementById("closureIntro").textContent = c.intro;
    const grid = document.getElementById("closureGrid");
    c.features.forEach(f => {
      const item = el("div", "closure-item");
      item.appendChild(el("h3", null, esc(f.title)));
      item.appendChild(el("p", null, esc(f.desc)));
      grid.appendChild(item);
    });

    const status = document.getElementById("closureStatus");
    const collapsed = document.getElementById("closureCollapsed");
    const revealBtn = document.getElementById("revealBtn");
    let revealed = false;
    revealBtn.addEventListener("click", () => {
      if (!revealed) {
        const ok = window.confirm("这条内容被标记为高困扰风险。你确定现在适合查看吗？");
        if (!ok) { status.textContent = "已为你保持折叠。你可以稍后再决定。"; return; }
        collapsed.textContent = "（此处为占位说明：真实运行时会展示已保全的公开证据条目，本 demo 不含真实数据。）";
        collapsed.className = "closure-revealed";
        revealBtn.textContent = "重新折叠";
        revealed = true;
        status.textContent = "已展开。如果感到不适，随时折叠。";
      } else {
        collapsed.textContent = "内容已折叠以保护你。展开前请确认你现在适合查看。";
        collapsed.className = "closure-collapsed";
        revealBtn.textContent = "需要二次确认才展开";
        revealed = false;
        status.textContent = "已重新折叠。";
      }
    });

    let cooldownTimer = null;
    document.getElementById("cooldownBtn").addEventListener("click", () => {
      if (cooldownTimer) return;
      let left = 30;
      status.className = "closure-status cooldown-lock";
      const tick = () => {
        if (left <= 0) {
          clearInterval(cooldownTimer); cooldownTimer = null;
          status.className = "closure-status";
          status.textContent = "冷却结束。希望你已经平静一些。";
          return;
        }
        status.textContent = `冷却中：还有 ${left}s。强迫性查看的冲动通常几分钟内就会过去。`;
        left -= 1;
      };
      tick();
      cooldownTimer = setInterval(tick, 1000);
    });

    document.getElementById("todayBtn").addEventListener("click", () => {
      status.className = "closure-status today-lock";
      status.textContent = "已锁定到明天。今天就到这里——你已经做得很好了。";
    });

    document.getElementById("handoffBtn").addEventListener("click", () => {
      const name = window.prompt("把查看 / 决策权移交给谁？（输入你信任的联系人名字）");
      status.className = "closure-status";
      if (name && name.trim()) status.textContent = `已（在此 demo 中）将把关权移交给「${name.trim()}」。真实版本会通知该联系人代为决定是否展开。`;
      else status.textContent = "未设置可信联系人。";
    });
  }

  /* =========================================================================
   * HOW IT WORKS — architecture flow
   * =======================================================================*/

  function renderArch() {
    const a = PLAN.architecture;
    const flow = document.getElementById("archFlow");
    const detail = document.getElementById("archDetail");
    const byId = {};
    a.nodes.forEach(n => (byId[n.id] = n));
    a.webhooks.forEach(n => (byId[n.id] = n));

    function show(id, sourceEl) {
      const n = byId[id];
      detail.innerHTML = "";
      detail.appendChild(el("h3", null, esc(n.title)));
      detail.appendChild(el("p", null, esc(n.role)));
      document.querySelectorAll(".arch-node.active").forEach(x => x.classList.remove("active"));
      if (sourceEl) sourceEl.classList.add("active");
    }

    a.flow.forEach((id, i) => {
      const n = byId[id];
      const node = el("div", "arch-node");
      node.setAttribute("role", "listitem");
      node.tabIndex = 0;
      node.appendChild(el("div", "node-id", esc(n.id)));
      node.appendChild(el("div", "node-name", esc(n.title.split("·")[1] ? n.title.split("·")[1].trim() : n.title)));
      node.addEventListener("click", () => show(id, node));
      node.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(id, node); } });
      flow.appendChild(node);
      if (i < a.flow.length - 1) flow.appendChild(el("div", "arch-arrow", "→"));
    });
  }

  function wireApify() {
    const state = document.getElementById("apifyState");
    document.getElementById("apifyCheck").addEventListener("click", () => {
      const token = document.getElementById("apifyToken").value.trim();
      const actors = document.getElementById("apifyActors").value.trim();
      if (token && actors) {
        state.className = "apify-state connected";
        state.textContent = "已检测到 token 与 actor 配置。真实运行需由后端用此凭证调用已部署 actor —— 本前端不会伪造抓取结果。";
      } else {
        state.className = "apify-state";
        state.textContent = "未连接真实 Apify（需 token + 已部署 actor）。" + (token ? "缺少 actor IDs。" : actors ? "缺少 APIFY_TOKEN。" : "");
      }
    });
  }

  function wireNavAndGate() {
    document.getElementById("runGate").addEventListener("click", doRun);
    document.getElementById("clearGate").addEventListener("click", () => {
      document.getElementById("requestInput").value = "";
      document.getElementById("scopeSelect").value = "";
      const out = document.getElementById("gateResult");
      out.innerHTML = '<div class="gate-empty"><span class="gate-empty-icon" aria-hidden="true">◎</span><p>选择一个范围或描述你的请求，然后运行闸门。<br/>逻辑在浏览器本地真实执行，没有假数据。</p></div>';
      updateReportForScope(null);
    });
    document.getElementById("requestInput").addEventListener("keydown", e => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") doRun();
    });
    const toggle = document.getElementById("navToggle");
    const links = document.querySelector(".nav-links");
    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    links.addEventListener("click", e => { if (e.target.tagName === "A") links.classList.remove("open"); });
  }

  /* Load a REAL produced report JSON (the e2e self-audit output) and surface its
   * grade. Tries data/example-report.json; on file:// (fetch blocked) falls back
   * to an injected window.__EX_REPORT__ from data/example-report.js. If neither
   * exists yet, we stay in the honest "no grade" state — we never invent one. */
  function applyReport(report) {
    if (!report || typeof report !== "object") return;
    LOADED_REPORT = report;
    const vm = gradeFromReport(report);
    if (vm) renderExposureGrade(vm);
    // re-drive the whole report view from the REAL produced report
    renderProvenance(report);
    renderFindings();
    renderEvidenceTable();
    renderSuggestedActions();
  }
  function loadExampleReport() {
    if (window.__EX_REPORT__) { applyReport(window.__EX_REPORT__); return; }
    let done = false;
    fetch("data/example-report.json")
      .then(r => { if (!r.ok) throw new Error("no report"); return r.json(); })
      .then(rep => { done = true; applyReport(rep); })
      .catch(() => {
        if (done || window.__EX_REPORT__) { if (window.__EX_REPORT__) applyReport(window.__EX_REPORT__); return; }
        // file:// fallback: try the JS-wrapped copy, mirroring the plan loader.
        const s = document.createElement("script");
        s.src = "data/example-report.js";
        s.onload = function () { if (window.__EX_REPORT__) applyReport(window.__EX_REPORT__); };
        s.onerror = function () { /* no produced report yet — stay in honest no-grade state */ };
        document.head.appendChild(s);
      });
  }

  function boot(plan) {
    PLAN = plan;
    renderHero();
    renderScopeSelect();
    renderPresets();
    renderExposureGrade(null);   // honest "no grade yet" until a real report loads
    renderProvenance(null);      // hidden until a report loads
    renderCoverage();
    renderFindings();            // template catalog until a real report loads
    renderClusterCard();
    renderEvidenceTable();       // evidence-index schema until a real report loads
    renderSuggestedActions();    // honest empty until a real report loads
    loadExampleReport();         // async; re-drives grade+findings+evidence+actions if a report exists
    renderOptout();
    renderClosure();
    renderArch();
    renderPipelinePanel();
    wireApify();
    wireKanon();
    wireNavAndGate();
    updateReportForScope(null);
  }

  fetch("data/plan.json")
    .then(r => { if (!r.ok) throw new Error("bad status"); return r.json(); })
    .then(boot)
    .catch(() => {
      if (FALLBACK_PLAN) { boot(FALLBACK_PLAN); return; }
      console.warn("plan.json 加载失败（可能是 file:// 限制）。注入内置数据。");
      var s = document.createElement("script");
      s.src = "data/plan.js";
      s.onload = function () { if (window.__MIRRORTRACE_PLAN__) boot(window.__MIRRORTRACE_PLAN__); };
      s.onerror = function () {
        var ho = document.getElementById("heroOne");
        if (ho) ho.textContent = "（plan.json 未能加载；请用本地服务器打开，或确认 data/plan.json 存在。合规闸门仍可独立使用。）";
      };
      document.head.appendChild(s);
    });

  // Expose gate for quick console testing / verification
  window.MirrorTrace = { runPolicyGate: runPolicyGate, LEGAL_SCOPES: LEGAL_SCOPES };
})();
