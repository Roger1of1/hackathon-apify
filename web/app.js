/* Ex-Ditector 合规版 — app.js
 * All client-side logic. The Policy Gate is REAL logic, not a simulation.
 */
(function () {
  "use strict";

  // ---- fallback plan (used if fetch fails, e.g. opened via file:// with CSP) ----
  const FALLBACK_PLAN = window.__EX_PLAN__ || null;

  /* =========================================================================
   * POLICY GATE — the genuine compliance logic (mirrors A0 / input_schema)
   * =======================================================================*/

  const LEGAL_SCOPES = ["self", "consented", "public_figure", "brand", "safety_evidence"];

  // Prohibited categories the gate must reject. Each has matcher patterns.
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
        /(swipe|likes|matches|followers|comments).{0,18}(tinder|bumble|instagram|ig|facebook|fb)/i
      ]
    },
    {
      id: "private_person_tracking",
      label: "追踪具名私人个体",
      reason: "请求指向追踪 / 监控某个私人个体（前任 / 暗恋对象 / 同事 / 陌生人等）。本工具只服务于你自己及合法授权 / 公开实体。",
      patterns: [
        /(前任|前男友|前女友|前夫|前妻|分手|复合)/i,
        /\b(ex[-\s]?(boyfriend|girlfriend|husband|wife|partner)?)\b/i,
        /(暗恋|心仪|喜欢的(那个)?(人|男生|女生)|那个(女生|男生|妹子|小哥))/i,
        /(跟踪|蹲点|监控|偷偷查|查一下(他|她)|扒一下(他|她)|人肉|起底)(?!.*(我自己|本人|品牌|公司|公众人物))/i,
        /(同事|邻居|室友|陌生人|那个(人|男的|女的)|某(人|个人)).{0,10}(住(在)?哪|在哪|电话|地址|行踪|每天)/i,
        /(stalk|track|monitor|spy on|dig up|locate)\s+(my|that|the|a|his|her)?\s*(coworker|colleague|neighbor|roommate|stranger|crush|guy|girl|person|him|her)/i,
        /(home address|where .* lives?|phone number|daily routine|whereabouts) of (my|a|that|the|his|her)/i
      ]
    }
  ];

  // Signals that a request is plausibly about SELF / public entities (compliance-positive).
  const SELF_SIGNALS = /(我自己|我本人|本人|我的(姓名|名字|名誉|足迹|信息)|关于我的|针对我(本人|的))/i;
  const PUBLIC_SIGNALS = /(公众人物|政治人物|官员|名人|品牌|公司|机构|企业|官网|新闻报道|公开(报道|声明|新闻|页面|资料)|召回|声誉)/i;
  const SAFETY_SIGNALS = /(诽谤|骚扰|诈骗|名誉(权)?|证据|保全|侵权|网暴|谣言)/i;
  const CONSENT_SIGNALS = /(授权|书面同意|委托|同意书|代为(审计|监控))/i;

  /**
   * runPolicyGate — the real gate.
   * @param {string} freeText  user free-text request (may be "")
   * @param {string} scope     chosen scope_type (may be "")
   * @returns {{accepted:boolean, ...}}
   */
  function runPolicyGate(freeText, scope) {
    const text = (freeText || "").trim();
    scope = (scope || "").trim();

    // 1) scope enum validation (compliance-as-code: only enum values allowed)
    if (scope && !LEGAL_SCOPES.includes(scope)) {
      return {
        accepted: false,
        category: "schema_violation",
        reason: `scope_type "${scope}" 不在合法枚举内（self / consented / public_figure / brand / safety_evidence），input_schema 校验拒绝。`,
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    // 2) prohibited pattern matching on free text (always runs, even with a legal scope —
    //    a legal scope label cannot launder a prohibited request).
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

    // 3) Must have SOMETHING to act on
    if (!scope && !text) {
      return {
        accepted: false,
        category: "empty",
        reason: "未提供 scope_type，也未输入请求内容。请至少选择一个合法 scope 或描述你的请求。",
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    // 4) Determine effective scope. If free text has no explicit scope, infer/require it.
    let effectiveScope = scope;
    if (!effectiveScope && text) {
      if (SELF_SIGNALS.test(text)) effectiveScope = "self";
      else if (SAFETY_SIGNALS.test(text) && SELF_SIGNALS.test(text)) effectiveScope = "safety_evidence";
      else if (SAFETY_SIGNALS.test(text)) effectiveScope = "safety_evidence";
      else if (CONSENT_SIGNALS.test(text)) effectiveScope = "consented";
      else if (PUBLIC_SIGNALS.test(text)) effectiveScope = "public_figure";
    }

    // 5) Free text with no legal scope and no public/self signal => cannot confirm legality => reject (fail closed)
    if (!effectiveScope) {
      return {
        accepted: false,
        category: "unscoped",
        reason: "无法确认该请求落入任一合法 scope（self / consented / public_figure / brand / safety_evidence）。闸门采用 fail-closed：无法证明合法即拒绝。请明确这是关于你自己、已授权对象、公众人物、品牌，还是涉及你本人的安全证据。",
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    // ACCEPTED
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
   * RENDERING
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
    document.getElementById("heroSub").textContent = p.subtitle;
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
      { t: "查我的前任在干嘛", txt: "帮我查一下我前任最近在干嘛，是不是有新对象了", kind: "reject" },
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
      });
      row.appendChild(b);
    });
  }

  function renderResult(res) {
    const out = document.getElementById("gateResult");
    out.innerHTML = "";
    const v = el("div", "verdict " + (res.accepted ? "accept" : "reject"));

    const head = el("div", "verdict-head");
    head.appendChild(el("span", null, res.accepted ? "✓ ACCEPTED · 通过" : "⊘ REJECTED · 拒绝"));
    head.appendChild(el("span", "verdict-badge", res.accepted ? "compliant" : "blocked"));
    v.appendChild(head);

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
  }

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
      document.querySelectorAll(".arch-node.active,.wh-node.active").forEach(x => x.classList.remove("active"));
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

    const wh = document.getElementById("archWebhooks");
    a.webhooks.forEach(w => {
      const n = el("div", "wh-node");
      n.tabIndex = 0;
      n.appendChild(el("div", "wh-title", esc(w.title)));
      n.appendChild(el("div", "muted", "点击查看回调职责"));
      n.addEventListener("click", () => show(w.id, n));
      n.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(w.id, n); } });
      wh.appendChild(n);
    });
  }

  function renderCards() {
    const grid = document.getElementById("cardsGrid");
    PLAN.cards.forEach(c => {
      const card = el("div", "tech-card");
      card.appendChild(el("h3", null, esc(c.title)));
      card.appendChild(el("p", "what", esc(c.what)));
      card.appendChild(el("div", "bonus", "<b>合规加分：</b>" + esc(c.bonus.replace(/^合规加分：?/, ""))));
      grid.appendChild(card);
    });
  }

  function renderReport() {
    const r = PLAN.report;
    document.getElementById("reportLabel").textContent = r.label;
    const scores = document.getElementById("reportScores");
    r.scores.forEach(s => {
      const c = el("div", "score-card");
      const top = el("div", "score-top");
      const left = el("div");
      left.appendChild(el("span", "score-label", esc(s.label) + " "));
      left.appendChild(el("span", "score-key", esc(s.key)));
      top.appendChild(left);
      top.appendChild(el("span", "score-sample", esc(s.sample)));
      c.appendChild(top);
      c.appendChild(el("div", "score-desc", esc(s.desc)));
      scores.appendChild(c);
    });
    const tbody = document.querySelector("#evTable tbody");
    r.evidenceIndexFields.forEach(f => {
      const tr = el("tr");
      tr.appendChild(el("td", null, esc(f.field)));
      tr.appendChild(el("td", null, esc(f.desc)));
      tbody.appendChild(tr);
    });
  }

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

    // Reverse-design demo interactions (no fake data — generic placeholder text only)
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

  function renderPlan() {
    const board = document.getElementById("planBoard");
    const statusLabel = { done: "已完成", in_progress: "进行中", todo: "待办" };
    PLAN.plan48h.forEach(p => {
      const col = el("div", "plan-col " + p.status);
      col.appendChild(el("div", "plan-phase", esc(p.phase)));
      col.appendChild(el("h3", null, esc(p.title)));
      col.appendChild(el("p", null, esc(p.desc)));
      col.appendChild(el("span", "plan-status " + p.status, statusLabel[p.status] || p.status));
      board.appendChild(col);
    });
  }

  function wireApify() {
    const state = document.getElementById("apifyState");
    document.getElementById("apifyCheck").addEventListener("click", () => {
      const token = document.getElementById("apifyToken").value.trim();
      const actors = document.getElementById("apifyActors").value.trim();
      if (token && actors) {
        // We do NOT call Apify or simulate success here. We only acknowledge config presence.
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
      out.innerHTML = '<div class="gate-empty"><span class="gate-empty-icon" aria-hidden="true">⌖</span><p>选择一个 scope 或输入请求，然后运行闸门。<br/>逻辑在浏览器本地真实执行——没有假数据。</p></div>';
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

  function boot(plan) {
    PLAN = plan;
    renderHero();
    renderScopeSelect();
    renderPresets();
    renderArch();
    renderCards();
    renderReport();
    renderClosure();
    renderPlan();
    wireApify();
    wireNavAndGate();
  }

  // Load plan.json; gracefully fall back so the app works even via file:// when fetch is blocked.
  fetch("data/plan.json")
    .then(r => { if (!r.ok) throw new Error("bad status"); return r.json(); })
    .then(boot)
    .catch(() => {
      if (FALLBACK_PLAN) { boot(FALLBACK_PLAN); return; }
      // Last resort: minimal inline notice + still run gate-only.
      console.warn("plan.json 加载失败（可能是 file:// 限制）。注入内置数据。");
      var s = document.createElement("script");
      s.src = "data/plan.js";
      s.onload = function () { if (window.__EX_PLAN__) boot(window.__EX_PLAN__); };
      s.onerror = function () {
        document.getElementById("heroOne").textContent = "（plan.json 未能加载；请用本地服务器打开，或确认 data/plan.json 存在。合规闸门仍可独立使用。）";
      };
      document.head.appendChild(s);
    });

  // Expose gate for quick console testing / verification
  window.ExDitector = { runPolicyGate: runPolicyGate, LEGAL_SCOPES: LEGAL_SCOPES };
})();
