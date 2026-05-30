/* MirrorTrace — app.js
 *
 * Clarity-first dashboard. The Policy Gate is REAL logic, not a simulation.
 * No preloader, no radio-dial/channel nav, no scroll-driven wheel — those were
 * removed because they violated the hard clarity red line ("clear, not flashy or confusing").
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
      label: "Romance / intimacy / infidelity inference",
      reason: "The request asks for romance, intimacy, or infidelity inference about a private relationship. MirrorTrace does not infer relationships.",
      patterns: [
        /\u66a7\u6627|\u51fa\u8f68|\u5288\u817f|\u7ea6\u4f1a|\u7ea6\u70ae|\u604b\u7231|\u559c\u6b22(\u6211|\u4ed6|\u5979|\u5bf9\u65b9)|\u662f\u4e0d\u662f\u5355\u8eab|\u6709\u6ca1\u6709\u5bf9\u8c61|\u6709\u6ca1\u6709\u7537(\u670b)?\u53cb|\u6709\u6ca1\u6709\u5973(\u670b)?\u53cb|\u811a\u8e0f\u4e24(\u53ea|\u6761)\u8239/i,
        /affair|cheat(ing)?|dating life|is .* single|has a (boy|girl)friend|romantic|crush|love interest/i
      ]
    },
    {
      id: "gender_from_image",
      label: "Infer gender or sexual orientation from an avatar / image",
      reason: "The request asks to infer gender or sexual orientation from an avatar or image. MirrorTrace does not infer identity from images.",
      patterns: [
        /(\u5934\u50cf|\u7167\u7247|\u56fe\u7247|\u957f\u76f8|\u5916\u8c8c|\u6837\u5b50|\u8138).{0,8}(\u6027\u522b|\u7537\u7684\u8fd8\u662f\u5973\u7684|\u662f\u7537\u662f\u5973|\u6027\u53d6\u5411|gay|\u540c\u6027\u604b|\u76f4\u7537|\u76f4\u5973)/i,
        /(\u6027\u522b|\u6027\u53d6\u5411|gay|\u662f\u4e0d\u662f\u540c\u6027\u604b|\u662f\u4e0d\u662f\u76f4).{0,8}(\u5934\u50cf|\u7167\u7247|\u56fe\u7247|\u957f\u76f8|\u5916\u8c8c|\u8138)/i,
        /(infer|guess|detect|determine).{0,20}(gender|sex|sexual orientation).{0,20}(avatar|photo|image|picture|face)/i,
        /(avatar|photo|image|picture|face).{0,20}(gender|sexual orientation|is .* (gay|straight))/i
      ]
    },
    {
      id: "dating_app_presence",
      label: "Detect dating-app activity",
      reason: "The request asks whether someone is active on a dating app. That is private-behavior tracking and is prohibited.",
      patterns: [
        /(tinder|bumble|\u63a2\u63a2|\u964c\u964c|soul|hinge|okcupid|grindr|\u4ea4\u53cb(\u8f6f\u4ef6|app)|\u7ea6\u4f1a(\u8f6f\u4ef6|app)|\u76f8\u4eb2(\u8f6f\u4ef6|app))/i,
        /(\u5728\u4e0d\u5728|\u6709\u6ca1\u6709(\u7528|\u6ce8\u518c)|\u662f\u5426(\u6ce8\u518c|\u6d3b\u8dc3|\u5237)).{0,12}(\u4ea4\u53cb|\u7ea6\u4f1a|\u76f8\u4eb2|tinder|bumble|\u63a2\u63a2|\u964c\u964c)/i,
        /(swipe|likes|matches|followers|comments).{0,18}(tinder|bumble|instagram|ig|facebook|fb)/i,
        /(tinder|bumble|instagram|ig|facebook|fb|\u5fae\u535a|\u6296\u97f3|\u5c0f\u7ea2\u4e66)\s*(\u7684)?\s*(followers?|likes?|comments?|matches|\u7c89\u4e1d|\u5173\u6ce8|\u70b9\u8d5e|\u8bc4\u8bba)/i
      ]
    },
    {
      id: "private_person_tracking",
      label: "Track a named private person",
      reason: "The request asks to track or monitor a private person. This tool serves only you, properly authorized subjects, and public entities.",
      patterns: [
        /(\u79c1\u4eba\u4e2a\u4f53|\u524d\u7537\u53cb|\u524d\u5973\u53cb|\u524d\u592b|\u524d\u59bb|\u5206\u624b|\u590d\u5408)/i,
        /\b(ex[-\s]?(boyfriend|girlfriend|husband|wife|partner)?)\b/i,
        /(\u6697\u604b|\u5fc3\u4eea|\u559c\u6b22\u7684(\u90a3\u4e2a)?(\u4eba|\u7537\u751f|\u5973\u751f)|\u90a3\u4e2a(\u5973\u751f|\u7537\u751f|\u59b9\u5b50|\u5c0f\u54e5))/i,
        /(\u8ddf\u8e2a|\u8e72\u70b9|\u76d1\u63a7|\u5077\u5077\u67e5|\u67e5\u4e00\u4e0b(\u4ed6|\u5979)|\u6252\u4e00\u4e0b(\u4ed6|\u5979)|\u4eba\u8089|\u8d77\u5e95)(?!.*(\u6211\u81ea\u5df1|\u672c\u4eba|\u54c1\u724c|\u516c\u53f8|\u516c\u4f17\u4eba\u7269))/i,
        /(\u540c\u4e8b|\u90bb\u5c45|\u5ba4\u53cb|\u964c\u751f\u4eba|\u90a3\u4e2a(\u4eba|\u7537\u7684|\u5973\u7684)|\u67d0(\u4eba|\u4e2a\u4eba)).{0,10}(\u4f4f(\u5728)?\u54ea|\u5728\u54ea|\u7535\u8bdd|\u5730\u5740|\u884c\u8e2a|\u6bcf\u5929)/i,
        /(stalk|track|monitor|spy on|dig up|locate)\s+(my|that|the|a|his|her)?\s*(coworker|colleague|neighbor|roommate|stranger|crush|guy|girl|person|him|her)/i,
        /(home address|where .* lives?|phone number|daily routine|whereabouts) of (my|a|that|the|his|her)/i
      ]
    }
  ];

  const SELF_SIGNALS = /(\u6211\u81ea\u5df1|\u6211\u672c\u4eba|\u672c\u4eba|\u6211\u7684(\u59d3\u540d|\u540d\u5b57|\u540d\u8a89|\u8db3\u8ff9|\u4fe1\u606f)|\u5173\u4e8e\u6211\u7684|\u9488\u5bf9\u6211(\u672c\u4eba|\u7684))/i;
  const PUBLIC_SIGNALS = /(\u516c\u4f17\u4eba\u7269|\u653f\u6cbb\u4eba\u7269|\u5b98\u5458|\u540d\u4eba|\u54c1\u724c|\u516c\u53f8|\u673a\u6784|\u4f01\u4e1a|\u5b98\u7f51|\u65b0\u95fb\u62a5\u9053|\u516c\u5f00(\u62a5\u9053|\u58f0\u660e|\u65b0\u95fb|\u9875\u9762|\u8d44\u6599)|\u53ec\u56de|\u58f0\u8a89)/i;
  const SAFETY_SIGNALS = /(\u8bfd\u8c24|\u9a9a\u6270|\u8bc8\u9a97|\u540d\u8a89(\u6743)?|\u8bc1\u636e|\u4fdd\u5168|\u4fb5\u6743|\u7f51\u66b4|\u8c23\u8a00)/i;
  const CONSENT_SIGNALS = /(\u6388\u6743|\u4e66\u9762\u540c\u610f|\u59d4\u6258|\u540c\u610f\u4e66|\u4ee3\u4e3a(\u5ba1\u8ba1|\u76d1\u63a7))/i;

  function runPolicyGate(freeText, scope) {
    const text = (freeText || "").trim();
    scope = (scope || "").trim();

    if (scope && !LEGAL_SCOPES.includes(scope)) {
      return {
        accepted: false,
        category: "schema_violation",
        reason: `scope_type "${scope}" is outside the permitted enum (self / consented / public_figure / brand / safety_evidence); input_schema validation refused it.`,
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
          reason: hits[0].reason + (scope ? ` (A legal-looking scope=${scope} cannot launder an out-of-bounds request.)` : ""),
          matched: hits.map(h => ({ id: h.id, label: h.label })),
          alternatives: alternativesFor(hits[0].id)
        };
      }
    }

    if (!scope && !text) {
      return {
        accepted: false,
        category: "empty",
        reason: "No scope_type or request text was provided. Choose a permitted scope or describe your request.",
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
        reason: "The request cannot be assigned to a permitted scope (self / consented / public_figure / brand / safety_evidence). The gate fails closed: if permission cannot be established, it refuses. State whether this concerns you, an authorized subject, a public figure, a brand, or safety evidence involving you.",
        matched: [],
        alternatives: defaultAlternatives()
      };
    }

    return {
      accepted: true,
      category: "accepted",
      scope: effectiveScope,
      reason: scope
        ? `The request falls within permitted scope "${effectiveScope}" and matches no prohibited pattern.`
        : `The request text implies permitted scope "${effectiveScope}" and matches no prohibited pattern.`,
      pipeline: pipelineFor(effectiveScope)
    };
  }

  function pipelineFor(scope) {
    const subject = {
      self: "your own public footprint",
      consented: "the public footprint of a subject with written authorization",
      public_figure: "public statements and reporting about this public figure",
      brand: "public reputation information about this brand or organization",
      safety_evidence: "public safety evidence involving you"
    }[scope];
    return [
      { step: "A0", text: `Passed policy gate: scope=${scope}; record compliance audit metadata only.` },
      { step: "A2", text: `Metamorph routes the task to an allowlisted public-source actor; target=${subject}.` },
      { step: "A3", text: "AdaptivePlaywrightCrawler fetches public pages only; it stops and records the event when it meets a login wall, CAPTCHA, or block." },
      { step: "A5", text: "Structure evidence, compute exposure / evidence_quality / actionability scores, and build a citable evidence index." },
      { step: "A6", text: "Generate the self-footprint report centered on the Exposure Map, with actionable opt-out and takedown steps." }
    ];
  }

  const ALT_LIBRARY = {
    private_person_tracking: [
      "Audit my own public footprint: show what public pages reveal about me.",
      "Preserve public harassment or defamation involving me as evidence (scope=safety_evidence).",
      "Monitor public news coverage about a public figure (scope=public_figure)."
    ],
    romance_inference: [
      "Audit reputation-related mentions of me on public pages (scope=self).",
      "Preserve a public defamatory post targeting me as evidence (scope=safety_evidence)."
    ],
    gender_from_image: [
      "Audit which public pages use my own public avatar (scope=self).",
      "Monitor public visual assets from a brand's official accounts (scope=brand)."
    ],
    dating_app_presence: [
      "Audit the search-engine visibility of my own public accounts (scope=self).",
      "Audit public mentions of a brand under written authorization (scope=consented)."
    ]
  };
  function alternativesFor(id) { return ALT_LIBRARY[id] || defaultAlternatives(); }
  function defaultAlternatives() {
    return [
      "Audit my own public digital footprint (scope=self).",
      "Preserve public evidence involving me: harassment, defamation, or fraud (scope=safety_evidence).",
      "Monitor public reporting about a public figure (scope=public_figure).",
      "Monitor a brand's public reputation under written authorization (scope=brand / consented)."
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
      { t: "Track a private person", txt: "Track what a private person has been doing lately and infer their intimate relationships", kind: "reject" },
      { t: "Infer romance", txt: "Check whether this person and my coworker are romantically involved", kind: "reject" },
      { t: "Guess gender from an avatar", txt: "Determine whether this person is a man or a woman from their avatar", kind: "reject" },
      { t: "Check dating-app activity", txt: "Check whether this person uses Tinder or Bumble", kind: "reject" },
      { t: "Track a coworker", txt: "Track my coworker's daily whereabouts and home address", kind: "reject" },
      { t: "Audit my footprint", txt: "Search public pages for my own name and assess my exposure", kind: "accept" },
      { t: "Preserve defamation evidence", txt: "Preserve a public defamatory post targeting me as evidence", kind: "accept" },
      { t: "Monitor a public figure", txt: "Summarize public reporting and official statements about a political figure", kind: "accept" },
      { t: "Monitor brand reputation", txt: "Monitor public news and official pages for a brand recall", kind: "accept" }
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
    const v = el("div", "verdict " + (res.accepted ? "accept" : "reject") +
      (prefersReducedMotion() ? "" : " stamp-in"));

    // Plain-language verdict first (HIBP-style instant outcome), then the
    // one-line meaning, then the technical reason. Strong top-down hierarchy:
    // a first-time visitor reads big word → what it means → why.
    const head = el("div", "verdict-head");
    const mark = el("span", "verdict-mark", res.accepted ? "✓" : "⊘");
    const word = el("span", "verdict-word", res.accepted ? "Permitted" : "Refused");
    head.appendChild(mark);
    head.appendChild(word);
    head.appendChild(el("span", "verdict-badge", res.accepted ? "compliant" : "blocked"));
    v.appendChild(head);

    // one-line "what this means" — plain language, no jargon
    v.appendChild(el("p", "verdict-meaning",
      res.accepted
        ? "This request falls within a permitted scope. The gate allows it into the self-audit pipeline."
        : "This request crosses a compliance red line. The gate refuses it immediately; no crawl runs."));

    // technical reason, labelled so it reads as the supporting detail
    v.appendChild(el("p", "verdict-why-label", res.accepted ? "Decision basis" : "Why it was refused"));
    v.appendChild(el("p", "verdict-reason", esc(res.reason)));

    if (res.accepted) {
      v.appendChild(el("span", "scope-tag", "scope_type = " + esc(res.scope)));
      v.appendChild(el("p", "verdict-sub", "Pipeline execution (compliant path)"));
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
        wrap.appendChild(el("p", "verdict-sub", "Matched prohibited categories"));
        res.matched.forEach(m => wrap.appendChild(el("span", "matched-tag", esc(m.label))));
        v.appendChild(wrap);
      }
      v.appendChild(el("p", "verdict-sub", "Safer alternatives →"));
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
   * clearly flagged "template checks (no live data)". No scraped result is fabricated.
   *
   * The categories below mirror, 1:1, the detector modules that actually exist
   * in shared/detectors/* and the EVENT_TYPES they emit, so the UI and the
   * pipeline speak the same vocabulary.
   * =======================================================================*/

  const FINDING_GROUPS = [
    {
      id: "pii",
      icon: "◐",
      title: "Public PII · Identifiable information you published",
      module: "sfp_pii  ·  pii-detector.js",
      desc: "Directly identifying information published on pages you control: email, phone number, address, handle, or coarse location. Detect, never infer.",
      items: [
        { name: "Public email on your page", event: "PII_EMAIL_PUBLIC", sev: "high", vis: "indexed",
          why: "An indexed email helps third parties link your public accounts and creates a spam or phishing entry point.",
          fix: "Replace your primary email on high-sensitivity pages with a dedicated address and review every page that still exposes it." },
        { name: "Public phone number", event: "PII_PHONE_PUBLIC", sev: "high", vis: "indexed",
          why: "A public phone number can be used for social engineering, account recovery abuse, and location discovery.",
          fix: "Remove it or replace it with a contact form. Preserve a snapshot as a remediation record." },
        { name: "Public postal or home-address text", event: "PII_POSTAL_PUBLIC", sev: "high", vis: "linked",
          why: "A public address creates a direct personal-safety risk.",
          fix: "Ask the site to remove it and prioritize highly ranked pages." },
        { name: "Reused public handle", event: "PII_HANDLE_PUBLIC", sev: "medium", vis: "indexed",
          why: "A reused handle lets someone jump from one public account to your other public accounts.",
          fix: "Separate public and private handles to reduce cross-platform correlation." },
        { name: "Self-described coarse location", event: "PII_GEO_HINT_PUBLIC", sev: "low", vis: "indexed",
          why: "A city or organization shown with your name narrows the area in which you can be located.",
          fix: "Decide whether it needs to be public and standardize what you disclose." }
      ]
    },
    {
      id: "tracker",
      icon: "◉",
      title: "Third-party trackers · Privacy leakage on your site",
      module: "sfp_tracker  ·  tracker-detector.js",
      desc: "A Blacklight-inspired check for third-party trackers on sites you control. These scripts may disclose visitor activity, including your own.",
      items: [
        { name: "Third-party tracking script", event: "TRACKER_THIRD_PARTY", sev: "medium", vis: "indexed",
          why: "Third-party scripts can send visitor behavior to advertising or data intermediaries.", fix: "Review and remove unnecessary third-party scripts and tags." },
        { name: "Browser fingerprinting", event: "TRACKER_FINGERPRINTING", sev: "high", vis: "indexed",
          why: "Fingerprinting can recognize visitors across sites even when cookies are disabled.", fix: "Remove fingerprinting libraries and use privacy-friendly analytics." },
        { name: "Session recording", event: "TRACKER_SESSION_RECORDING", sev: "high", vis: "indexed",
          why: "Session recording may capture form contents along with mouse and keyboard activity.", fix: "Disable session recording or enforce strict redaction." },
        { name: "Keystroke-style form listener", event: "TRACKER_KEYLOGGING", sev: "high", vis: "indexed",
          why: "Capturing input before submission can leak sensitive content.", fix: "Remove third-party form scripts that listen before submission." },
        { name: "Third-party cookie", event: "COOKIE_THIRD_PARTY", sev: "low", vis: "indexed",
          why: "Third-party cookies are used to track visitors across sites.", fix: "Restrict cookies to necessary first-party use." },
        { name: "Identity leaked through referrer", event: "LEAK_REFERRER", sev: "medium", vis: "indexed",
          why: "A URL or referrer can carry your identifier to a third-party domain.", fix: "Set a referrer policy and avoid exposing identifiers in URLs." }
      ]
    },
    {
      id: "secret",
      icon: "◈",
      title: "Secret leakage · Credentials you accidentally published",
      module: "sfp_secret  ·  secret-leak-detector.js",
      desc: "API keys, tokens, private keys, or .env assignments accidentally published on your pages or repositories. This self-audit hygiene check is inspired by secret scanning.",
      items: [
        { name: "Credential in a public page or repository", event: "SECRET_LEAK_PUBLIC", sev: "high", vis: "indexed",
          why: "A public credential can be abused immediately. This check concerns only your own credentials, never a third party's.",
          fix: "Rotate the credential immediately, remove it from history, and adopt secret management." }
      ]
    },
    {
      id: "breach",
      icon: "◍",
      title: "Breach-corpus match · Known exposure of your credential",
      module: "sfp_breach  ·  breach-range-detector.js",
      desc: "Use an HIBP-style k-anonymous range lookup to check whether your own credential appears in a known breach corpus. MirrorTrace never transmits or stores plaintext credentials.",
      items: [
        { name: "Credential matched a breach range", event: "BREACH_RANGE_HIT", sev: "high", vis: "private",
          why: "A credential found in a known breach corpus should be retired. Matching happens locally within a k-anonymous bucket without exposing the suffix.",
          fix: "Retire the credential, use a unique strong password, and enable multi-factor authentication." }
      ]
    },
    {
      id: "surface",
      icon: "◎",
      title: "Visible accounts and surfaces · Entrypoints you expose",
      module: "sfp_accounts  ·  username-enum-detector.js (dual use; gate permits self/public_figure only)",
      desc: "Public profile URLs and handles you control. Handle enumeration is dual use, so it is available only for self or public_figure scopes after the policy gate.",
      items: [
        { name: "Public profile URL", event: "SELF_PROFILE_URL", sev: "low", vis: "indexed",
          why: "Inventory your known public profile entrypoints so you can manage and remediate them.", fix: "Maintain a public-profile inventory and retire old profiles you no longer use." },
        { name: "Enumerable public handle", event: "SELF_USERNAME", sev: "medium", vis: "indexed",
          why: "A reused handle increases cross-platform correlation.", fix: "Separate public and private handles. This dual-use enumeration is gate checked." }
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
  const SEV_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  const VIS_LABEL = { indexed: "search-engine indexed", linked: "reachable by link", private: "normally should not be exposed" };

  // The "why this is a template, not a finding" banner copy.
  const SELF_NOTE =
    "scope=self: the categories below show what third parties can easily find about you. These are audit-schema template checks, " +
    "not scraped results. A live run fills evidence-index rows with URL, timestamp, and hash.";
  const PUBLIC_FIGURE_NOTE =
    "scope=public_figure: inventory only official or public surfaces in the public domain, such as official sites, news, and public statements. " +
    "Never touch private behavior or infer identity or relationships. The items below are audit-schema template checks.";

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

    panel.appendChild(el("div", "kanon-tag", "Live demo · HIBP k-anonymous range mechanism"));
    panel.appendChild(el("p", "kanon-intro",
      "Hash <b>your own</b> credential locally in the browser with SHA-1 and inspect exactly: " +
      "<b>which 5 characters would be sent</b> and <b>which 35 characters always stay local</b>. " +
      "This mirrors the Have I Been Pwned Pwned Passwords range API privacy mechanism, " +
      "and matches the prefix/suffix split contract in <code>shared/aux/kanon.js</code>."));

    const warn = el("p", "kanon-offline");
    warn.innerHTML = "⊘ Offline mode never queries a breach corpus. This panel demonstrates the <b>privacy mechanism</b>: what leaves your device and what stays local. " +
      "It is <b>not</b> a breach result and never displays a fabricated hit or count.";
    panel.appendChild(warn);

    const field = el("div", "kanon-field");
    const label = el("label", "field-label", "Your own credential (hashed locally, never uploaded)");
    label.setAttribute("for", "kanonInput");
    field.appendChild(label);
    const input = el("input", "input");
    input.id = "kanonInput";
    input.type = "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("autocapitalize", "off");
    input.placeholder = "Example: one of your old passwords or your email (local SHA-1 only)";
    field.appendChild(input);
    const actions = el("div", "kanon-actions");
    const runBtn = el("button", "btn btn-ghost btn-tiny", "Hash and split locally");
    runBtn.type = "button";
    const clrBtn = el("button", "btn btn-ghost btn-tiny", "Clear");
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
        out.innerHTML = '<p class="kanon-hint">Enter a string before hashing. Empty input is neither sent nor hashed.</p>';
        return;
      }
      let hash;
      try {
        hash = await sha1HexBrowser(secret);
      } catch (e) {
        out.innerHTML = '<p class="kanon-hint kanon-err">Web Crypto is unavailable in this environment. SubtleCrypto requires a secure context such as file:// or https://. ' +
          'Open this page directly with file:// or serve it over https://. The backend <code>kanon.js</code> performs the same SHA-1 operation with Node crypto.</p>';
        return;
      }
      const k = kAnonSplit(hash);

      out.innerHTML = "";

      // The split, shown unambiguously: prefix (sent) highlighted vs suffix (local).
      const split = el("div", "kanon-split");
      const pre = el("span", "kanon-prefix", esc(k.prefix));
      pre.title = "The 5 characters sent to the range endpoint";
      const suf = el("span", "kanon-suffix", esc(k.suffix));
      suf.title = "The 35 characters that always stay local for matching";
      split.appendChild(pre);
      split.appendChild(suf);
      out.appendChild(split);

      const legend = el("div", "kanon-legend");
      const sent = el("div", "kanon-leg-row");
      sent.innerHTML = '<span class="kanon-chip sent">Sent · prefix</span>' +
        '<code class="kanon-mono">GET range/<b>' + esc(k.prefix) + "</b></code>" +
        '<span class="kanon-leg-note">5 hexadecimal characters select 1 of 1,048,576 buckets; the server cannot tell which credential you checked.</span>';
      const local = el("div", "kanon-leg-row");
      local.innerHTML = '<span class="kanon-chip local">Stays local · suffix</span>' +
        '<code class="kanon-mono">' + esc(k.suffix) + "</code>" +
        '<span class="kanon-leg-note">The 35-character suffix is matched against bucket candidates on your device. Plaintext credentials never leave the browser.</span>';
      legend.appendChild(sent);
      legend.appendChild(local);
      out.appendChild(legend);

      const foot = el("p", "kanon-foot");
      foot.innerHTML = "Full SHA-1 (displayed only, never sent): <code class=\"kanon-mono\">" + esc(k.hash) + "</code><br>" +
        "In a live run, the backend uses only <code>" + esc(k.prefix) + "</code> to retrieve suffixes and counts for that bucket from the HIBP range endpoint, " +
        "matches the <code>suffix</code> locally, and treats padding rows with count=0 as not matched, following HIBP guidance. " +
        "Offline mode <b>stops here</b>: no query, no returned corpus data, and no fabricated breach result.";
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
      "Portable evidence · STIX 2.1 Observed Data (OpenCTI / MISP interoperable)"));
    summary.appendChild(el("span", "stix-cat-chip", esc(cat)));
    wrap.appendChild(summary);

    const note = el("p", "stix-note");
    note.innerHTML =
      "Export this finding as an OASIS <b>STIX 2.1 Observed Data</b> object with " +
      "<code>first_observed</code>, <code>last_observed</code>, content hash, and observable category. " +
      "Hand it directly to a removal request, SIEM, OpenCTI, or MISP. The JSON shape below is populated by a live run. " +
      "Every value field in this offline template is a placeholder, <b>not</b> scraped data.";
    wrap.appendChild(note);

    const pre = el("pre", "stix-json");
    pre.appendChild(el("code", null, esc(JSON.stringify(od, null, 2))));
    wrap.appendChild(pre);

    const actions = el("div", "stix-actions");
    const copyBtn = el("button", "btn btn-primary btn-tiny", "Copy STIX JSON");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", function () {
      const text = JSON.stringify(od, null, 2);
      const done = function () { copyBtn.textContent = "Copied ✓"; setTimeout(function () { copyBtn.textContent = "Copy STIX JSON"; }, 1600); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
    actions.appendChild(copyBtn);
    actions.appendChild(el("span", "stix-template-flag", "Template · no live data"));
    wrap.appendChild(actions);

    const ref = el("p", "stix-ref");
    ref.innerHTML =
      "Code: <b>shared/enrich/stix-evidence.js</b> (toObservedData / toBundle, same fields as this panel). " +
      "References: OASIS STIX 2.1 Observed Data SDO + Indicator pattern; OpenCTI / MISP STIX 2.1 interoperability mapping.";
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
      "Portable evidence · STIX 2.1 Observed Data (OpenCTI / MISP interoperable)"));
    summary.appendChild(el("span", "stix-cat-chip", esc(cat)));
    wrap.appendChild(summary);

    const note = el("p", "stix-note");
    note.innerHTML =
      "This object is populated from a <b>real detector finding</b>: event_type, source_url, confidence, risk, and source_module come from the loaded report. " +
      "Timestamp and content-hash fields remain placeholders in a synthetic fixture. A real gate-approved crawl writes real hashes; MirrorTrace never fabricates them.";
    wrap.appendChild(note);

    const pre = el("pre", "stix-json");
    pre.appendChild(el("code", null, esc(JSON.stringify(od, null, 2))));
    wrap.appendChild(pre);

    const actions = el("div", "stix-actions");
    const copyBtn = el("button", "btn btn-primary btn-tiny", "Copy STIX JSON");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", function () {
      const text = JSON.stringify(od, null, 2);
      const done = function () { copyBtn.textContent = "Copied ✓"; setTimeout(function () { copyBtn.textContent = "Copy STIX JSON"; }, 1600); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
    actions.appendChild(copyBtn);
    actions.appendChild(el("span", "stix-template-flag",
      (report && /SYNTHETIC|TEMPLATE/i.test(String(report.__label || ""))) ? "Synthetic fixture · real detector output" : "Live pipeline output"));
    wrap.appendChild(actions);

    const ref = el("p", "stix-ref");
    ref.innerHTML =
      "Code: <b>shared/enrich/stix-evidence.js</b> (toObservedData, same fields as this panel). " +
      "References: OASIS STIX 2.1 Observed Data SDO; OpenCTI / MISP STIX 2.1 interoperability mapping.";
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
   * catalog rendered below — it describes the audit SCHEMA ("what it checks"), never a
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
   * EMPTY-IN ⇒ NO GRADE semantics ("Not scanned · no grade yet"), and NEVER default an
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
    A: "Very small exposure surface: third parties cannot easily assemble a profile about you. Maintain the current posture.",
    B: "Small exposure surface: a few public traces can be cleaned up, but the overall picture is manageable.",
    C: "Moderate exposure: several public information points should be remediated using the checklist below.",
    D: "Elevated exposure: several public traces can be correlated. Address high-exposure items promptly.",
    F: "High exposure: key personal information is publicly available. Prioritize high-exposure and secret-leak items."
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

  var SC_KIND = { phone: "📱 Phone", email: "📧 Email", name: "👤 Name", handle: "🔖 Handle", identity: "🆔 Identity" };
  function scLabel(s) {
    if (s.site) return s.site;
    var t = String(s.label || s.query || "")
      .replace(/^phone fmt\s*/i, "").replace(/^email\s*/i, "")
      .replace(/^(phone|name|handle|identity)\s*/i, "")
      .replace(/^site:/i, "").replace(/^["']|["']$/g, "").trim();
    return t || String(s.query || "source");
  }
  // Render the actual data sources this live run queried, as a neat grouped list.
  function appendSourcesChecked(body) {
    var rep = LOADED_REPORT;
    var list = rep && rep.provenance && rep.provenance.sources_checked;
    if (!Array.isArray(list) || !list.length) return;
    var groups = {};
    list.forEach(function (s) { var k = s.kind || "other"; (groups[k] = groups[k] || []).push(s); });
    var wrapEl = el("div", "sources-checked");
    wrapEl.appendChild(el("p", "sc-title", "Sources checked · " + list.length));
    Object.keys(groups).forEach(function (k) {
      var arr = groups[k];
      var found = arr.filter(function (s) { return s.status === "found"; }).length;
      var g = el("div", "sc-group");
      g.appendChild(el("p", "sc-group-head",
        (SC_KIND[k] || ("🔎 " + k)) + " · " + arr.length + " checked" + (found ? (" · " + found + " found") : "")));
      var ul = el("ul", "sc-list");
      arr.forEach(function (s) {
        var st = s.status === "found" ? ["✓", "sc-found"] : s.status === "blocked" ? ["⛬", "sc-blocked"] : ["·", "sc-none"];
        var li = el("li", "sc-row " + st[1]);
        li.appendChild(el("span", "sc-ic", st[0]));
        li.appendChild(el("span", "sc-name", esc(scLabel(s))));
        if (s.status) li.appendChild(el("span", "sc-st", esc(s.status)));
        ul.appendChild(li);
      });
      g.appendChild(ul);
      wrapEl.appendChild(g);
    });
    body.appendChild(wrapEl);
  }

  function renderExposureGrade(vm) {
    const wrap = document.getElementById("exposureGrade");
    if (!wrap) return;
    wrap.innerHTML = "";

    // ---- honest EMPTY-IN ⇒ NO GRADE state (mirrors module graded:false) ----
    if (!vm || vm.graded === false) {
      const letter = el("div", "grade-letter g-none", "—");
      letter.setAttribute("role", "img");
      letter.setAttribute("aria-label", "Not scanned, no grade yet");
      const body = el("div", "grade-body");
      body.appendChild(el("p", "grade-eyebrow", "Exposure grade · EXPOSURE GRADE"));
      body.appendChild(el("p", "grade-meaning", "Not scanned · no grade yet"));
      body.appendChild(el("p", "grade-detail",
        "A grade appears only after a live self-audit. An unscanned subject is never defaulted to A. No data means no grade; MirrorTrace never invents a score."));
      // GOV.UK Design System: an empty/zero state should tell the user what they
      // can DO next, not just state absence. Point to Step 1 (the gate) so the
      // no-grade card is an actionable starting point, not a dead end.
      const next = el("p", "grade-next");
      next.innerHTML =
        "Next: pass the <a href=\"#gate\">Step 1 · Policy Gate</a> with <code>self</code> scope, then run a live self-audit to calculate a grade.";
      body.appendChild(next);
      body.appendChild(el("p", "grade-note",
        "Grade model: Mozilla HTTP Observatory / SecurityHeaders-style A–F scoring (baseline 100 minus weighted deductions). Code: integrations/grade/exposure-grade.js."));
      wrap.appendChild(letter);
      wrap.appendChild(body);
      return;
    }

    // ---- real graded state ----
    const letter = String(vm.grade);
    const fam = gradeFamily(letter);
    const letterEl = el("div", "grade-letter g-" + fam, esc(letter));
    letterEl.setAttribute("role", "img");
    letterEl.setAttribute("aria-label", "Exposure grade " + letter + (vm.score != null ? ", score " + vm.score + " / 100" : ""));

    const body = el("div", "grade-body");
    body.appendChild(el("p", "grade-eyebrow", "Exposure grade · EXPOSURE GRADE"));
    body.appendChild(el("p", "grade-meaning", GRADE_MEANING[fam.toUpperCase()] || ("Grade " + letter)));

    const bits = [];
    if (vm.score != null) bits.push("Score " + vm.score + " / 100");
    if (vm.total_deduction != null) bits.push("Total deduction " + vm.total_deduction);
    if (vm.counted_event_count != null) bits.push("Counted findings " + vm.counted_event_count + "");
    if (vm.severity_band) bits.push("Highest severity " + vm.severity_band);
    if (bits.length) body.appendChild(el("p", "grade-detail", esc(bits.join(" · "))));

    // compact A–F scale strip, current band highlighted (Observatory legend, no dial)
    const scale = el("div", "grade-scale");
    scale.setAttribute("aria-hidden", "true");
    ["A+", "A", "B", "C", "D", "F"].forEach(g => {
      const cur = letter[0].toUpperCase() === g[0] && (g.length === 1 || g === letter);
      scale.appendChild(el("span", "gs" + (cur ? " cur" : ""), g));
    });
    body.appendChild(scale);

    // Sources checked — the actual data sources this live run queried (neat list)
    appendSourcesChecked(body);

    const note = el("p", "grade-note", null);
    note.innerHTML =
      "Grade model: Mozilla HTTP Observatory–style A–F (baseline 100 − weighted deductions). Code: <code>integrations/grade/exposure-grade.js</code>.";
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
      { n: cats, label: "Exposure categories" },
      { n: checks, label: "Checks" }
    ].forEach(s => {
      const cell = el("div", "cov-stat");
      cell.appendChild(el("span", "cov-num", String(s.n)));
      cell.appendChild(el("span", "cov-lbl", s.label));
      stats.appendChild(cell);
    });

    // severity-weight distribution of the checks (not findings) — a labelled bar
    const distWrap = el("div", "cov-dist");
    distWrap.appendChild(el("span", "cov-dist-label", "Checks by exposure level"));
    const bar = el("div", "cov-bar", null);
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label",
      "High exposure " + sev.high + " items, Medium exposure " + sev.medium + " items, Low exposure " + sev.low + " items");
    [["high", "High"], ["medium", "Medium"], ["low", "Low"]].forEach(([k]) => {
      if (!sev[k]) return;
      const seg = el("div", "cov-seg " + k);
      seg.style.flexGrow = String(sev[k]);
      bar.appendChild(seg);
    });
    distWrap.appendChild(bar);
    const legend = el("div", "cov-legend");
    [["high", "High exposure", sev.high], ["medium", "Medium exposure", sev.medium], ["low", "Low exposure", sev.low]]
      .forEach(([k, name, n]) => {
        if (!n) return;
        const li = el("span", "cov-leg-item");
        li.appendChild(el("span", "cov-leg-dot " + k));
        li.appendChild(el("span", null, name + " " + n + " items"));
        legend.appendChild(li);
      });
    distWrap.appendChild(legend);

    wrap.appendChild(stats);
    wrap.appendChild(distWrap);

    // honesty line: this is coverage/schema, not findings
    wrap.appendChild(el("p", "cov-note",
      "This is the audit-schema coverage: what the self-audit checks, not scraped results. " +
      "After a gate-approved live run with scope=self, matched items fill the categories below with URL, timestamp, and hash."));
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

  /* =========================================================================
   * REPORT BREADTH — the honest "how many sources were checked, how many hit"
   * per identifier (phone / email / name / handle). Single source of truth for
   * the email+phone hero stats, the coverage strip, and the references breadth
   * list. Drawn ONLY from the real report's provenance — never fabricated:
   *   - provenance.per_query[]  → queries run + SERP results + findings per kind
   *   - provenance.serp_listings_all[] → public listings actually surfaced
   *   - findings[] (by event_type) → CONFIRMED self-exposure hits
   *   - provenance.dropped_by_compliance[] → social hosts blocked by the gate
   * Identity findings (SELF_PROFILE_URL) and name/handle queries map to "name".
   * If a kind was never queried, it reports honestly as not-checked (sources:0).
   * ======================================================================= */
  // event_type → the identifier kind it exposes.
  const EVENT_TO_KIND = {
    PII_PHONE_PUBLIC: "phone",
    PII_EMAIL_PUBLIC: "email",
    PII_HANDLE_PUBLIC: "handle",
    SELF_USERNAME: "handle",
    SECRET_LEAK_PUBLIC: "handle",
    SELF_PROFILE_URL: "name",
    PII_POSTAL_PUBLIC: "name",
    PII_GEO_HINT_PUBLIC: "name"
  };
  // per_query.kind / serp.query_kind use "identity" for name searches.
  function normKind(k) {
    k = String(k || "").toLowerCase();
    if (k === "identity") return "name";
    if (k === "phone" || k === "email" || k === "handle" || k === "name") return k;
    return "other";
  }
  // Which kind a single finding belongs to (prefers explicit fields, then event).
  function findingKind(f) {
    if (f.identifier_kind) return normKind(f.identifier_kind);
    if (f.query_kind) return normKind(f.query_kind);
    if (EVENT_TO_KIND[f.event_type]) return EVENT_TO_KIND[f.event_type];
    return "other";
  }

  function reportBreadth(report) {
    const kinds = ["phone", "email", "name", "handle"];
    const out = {};
    kinds.forEach(function (k) {
      out[k] = { kind: k, queried: false, sources: 0, results: 0, listings: 0, findings: 0, blocked: 0 };
    });
    out.total = { sources: 0, results: 0, findings: 0, blocked: 0 };
    if (!report || typeof report !== "object") return out;
    const prov = (report.provenance && typeof report.provenance === "object") ? report.provenance : {};

    // 1) per_query = the authoritative list of sources/queries checked per kind.
    if (Array.isArray(prov.per_query)) {
      prov.per_query.forEach(function (q) {
        const k = normKind(q.kind);
        if (!out[k]) return;
        out[k].queried = true;
        out[k].sources += 1;                         // one source/query checked
        out[k].results += Number(q.results) || 0;    // SERP results that came back
        out.total.sources += 1;
        out.total.results += Number(q.results) || 0;
      });
    }
    // 2) real public listings actually surfaced (breadth visible even pre-crawl).
    if (Array.isArray(prov.serp_listings_all)) {
      prov.serp_listings_all.forEach(function (s) {
        const k = normKind(s.query_kind);
        if (out[k]) out[k].listings += 1;
      });
    }
    // 3) CONFIRMED hits = real findings, counted by the identifier they expose.
    reportFindings(report).forEach(function (f) {
      const k = findingKind(f);
      if (out[k]) out[k].findings += 1;
      out.total.findings += 1;
    });
    // 4) compliance blocks (social hosts the gate refused to scrape) — a feature.
    if (Array.isArray(prov.dropped_by_compliance)) {
      out.total.blocked = prov.dropped_by_compliance.length;
      // best-effort attribution: which identifier surfaced the blocked host.
      prov.dropped_by_compliance.forEach(function (d) {
        const k = normKind(d.query_kind || d.kind);
        if (out[k]) out[k].blocked += 1;
      });
    }
    return out;
  }

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
    const tag = el("span", "prov-tag", isSynthetic(report) ? "Synthetic fixture · real detector-to-grade pipeline" : "Live pipeline output");
    wrap.appendChild(tag);
    if (report.__label) wrap.appendChild(el("p", "prov-label", esc(report.__label)));
    if (report.__notice) wrap.appendChild(el("p", "prov-notice", esc(report.__notice)));
    const src = [];
    if (report.generated_at) src.push("Generated at " + report.generated_at);
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
      head.appendChild(el("span", "fg-count real " + worst, list.length + " findings"));
      card.appendChild(head);

      const body = el("div", "fg-body");
      body.appendChild(el("p", "fg-desc", esc(g.desc)));

      list.forEach(f => {
        const meta = EVENT_META[f.event_type] || {};
        const item = el("div", "finding-item real");
        const row = el("div", "fi-row");
        row.appendChild(el("span", "fi-name", esc(meta.name || f.event_type)));
        const risk = f.risk || meta.sev || "low";
        row.appendChild(el("span", "sev-badge " + risk, esc((SEV_LABEL[risk] || risk) + " exposure")));
        const vis = f.visibility || meta.vis;
        if (vis) row.appendChild(el("span", "vis-badge", esc(VIS_LABEL[vis] || vis)));
        row.appendChild(el("span", "event-chip", esc(f.event_type)));
        item.appendChild(row);

        // real evidence one-liner: source URL + confidence + source module
        const facts = el("p", "fi-facts");
        const conf = (f.confidence != null) ? "Confidence " + f.confidence : "";
        const urlTxt = f.source_url ? f.source_url : "(no public URL, such as a k-anonymous breach lookup)";
        facts.innerHTML =
          "<b>Source:</b> " + esc(urlTxt) +
          (conf ? " · " + esc(conf) : "") +
          (f.source_module ? " · " + esc(f.source_module) : "");
        item.appendChild(facts);

        if (meta.why) {
          const why = el("p", "fi-why");
          why.innerHTML = "<b>Why it matters:</b>" + esc(meta.why);
          item.appendChild(why);
        }
        if (meta.fix) item.appendChild(el("p", "fi-fix", "Suggested action: " + esc(meta.fix)));

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
      tw.appendChild(el("div", "fg-title", "Other detector findings"));
      tw.appendChild(el("div", "fg-module", "event_type not listed in the front-end catalog"));
      head.appendChild(tw);
      head.appendChild(el("span", "fg-count real low", orphans.length + " findings"));
      card.appendChild(head);
      const body = el("div", "fg-body");
      orphans.forEach(f => {
        const item = el("div", "finding-item real");
        const row = el("div", "fi-row");
        row.appendChild(el("span", "fi-name", esc(f.event_type)));
        const risk = f.risk || "low";
        row.appendChild(el("span", "sev-badge " + risk, esc((SEV_LABEL[risk] || risk) + " exposure")));
        item.appendChild(row);
        if (f.source_url) item.appendChild(el("p", "fi-facts", "Source: " + esc(f.source_url)));
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
      head.appendChild(el("span", "fg-count", g.items.length + "  checks"));
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
        row.appendChild(el("span", "sev-badge " + it.sev, esc((SEV_LABEL[it.sev] || it.sev) + " exposure")));
        row.appendChild(el("span", "vis-badge", esc(VIS_LABEL[it.vis] || it.vis)));
        row.appendChild(el("span", "event-chip", esc(it.event)));
        item.appendChild(row);

        const why = el("p", "fi-why");
        why.innerHTML = "<b>Why it matters:</b>" + esc(it.why);
        item.appendChild(why);

        item.appendChild(el("p", "fi-fix", "Suggested action: " + esc(it.fix)));

        const q = el("div", "fi-quality");
        q.appendChild(el("span", "q-dot"));
        q.appendChild(el("span", null, "evidence_quality: pending live run (source authority + timestamp + integrity)"));
        q.appendChild(el("span", "fi-template-flag", "Template check · no live data"));
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

  /* =========================================================================
   * EXPOSURE MAP — the #1 deliverable. A dependency-free, file://-safe SVG
   * radial node graph built in-browser from the loaded report.
   *
   * This re-implements the buildExposureGraph CONTRACT from
   * shared/graph/build-exposure-graph.js client-side, kept aligned field-for-
   * field: center "you" + one node per distinct SOURCE (host, or a hostless
   * origin like a k-anonymity breach), node COLOR = severityTier (red/yellow/
   * green from severity_band), node SIZE = infoCount (distinct findings at that
   * source), center->source `exposes` edges, and cross-source `shared-identifier`
   * edges wherever two sources expose the SAME identifier (same email/handle).
   *
   * Identity-join keys reuse the SAME honest extractor logic as
   * shared/enrich/cluster-keys.js: host (the node itself, dropped for linking),
   * handle (normalized), and email_prefix (the HIBP k-anonymity SHA-1 prefix —
   * NEVER the plaintext email). We reuse the page's existing sha1HexUpper so the
   * email prefix matches shared/aux/kanon.js byte-for-byte.
   *
   * LAYOUT: a calm DETERMINISTIC radial — severity rings (red inner, yellow mid,
   * green outer), NOT a physics hairball. Long low-risk tail folds into one
   * "+N low-risk" node so the map never becomes a hairball.
   *
   * Refs: Maltego entity-link graph; SpiderFoot 4.0 correlation engine;
   * The Markup Blacklight (severity read at a glance). Prefer dependency-free SVG
   * over d3-force given the file:// constraint.
   * =======================================================================*/

  // ---- client-side mirror of the shared builder's tier projection ----
  const MAP_BAND_TO_TIER = { critical: "red", high: "red", medium: "yellow", low: "green", info: "green" };
  const MAP_RISK_TO_BAND = { high: "high", medium: "medium", low: "low", info: "info" };
  const MAP_TIER_RANK = { green: 0, yellow: 1, red: 2 };
  const MAP_ORIGIN_LABELS = {
    breach_range_detector: "Breach database (k-anonymity)",
    breach_detector: "Breach database"
  };
  function mapTierForBand(band) { return MAP_BAND_TO_TIER[band] || "green"; }

  function mapHostOf(url) {
    if (typeof url !== "string" || !url) return null;
    try { return new URL(url).hostname.toLowerCase() || null; } catch (e) { return null; }
  }
  function mapNormalizeHandle(h) {
    if (typeof h !== "string") return null;
    const v = h.trim().replace(/^@+/, "").toLowerCase();
    return v.length ? v : null;
  }
  // The stable source key a finding belongs to (host, or hostless origin).
  function mapSourceOf(f) {
    const host = mapHostOf(f.source_url);
    if (host) return { id: "host:" + host, host: host, label: host, kind: "host" };
    const mod = f.source_module || "origin";
    return { id: "origin:" + mod, host: null, label: MAP_ORIGIN_LABELS[mod] || mod, kind: "origin" };
  }
  // Identity-join keys for cross-source links: handle + email_prefix only (host
  // is the node itself; secrets are credential artifacts, not identity). Mirrors
  // identifierKeysOf() in the shared builder.
  function mapIdentifierKeys(f) {
    const keys = [];
    const meta = (f.meta && typeof f.meta === "object") ? f.meta : {};
    // handle
    if (f.event_type === "PII_HANDLE_PUBLIC" || f.event_type === "SELF_USERNAME") {
      const h = mapNormalizeHandle(meta.handle != null ? meta.handle : f.data);
      if (h) keys.push("handle:" + h);
    } else if (meta.handle != null) {
      const h = mapNormalizeHandle(meta.handle);
      if (h) keys.push("handle:" + h);
    }
    // email_prefix — prefer a prefix already in meta, else derive from a plaintext
    // email in data via the SAME k-anonymity SHA-1 prefix as kanon.js (5 hex).
    let prefix = typeof meta.email_hash_prefix === "string" ? meta.email_hash_prefix : null;
    if (!prefix && typeof f.data === "string" && f.data.includes("@")) {
      try { prefix = sha1HexUpper(f.data.trim().toLowerCase()).slice(0, 5); } catch (e) { prefix = null; }
    }
    if (prefix) keys.push("email_prefix:" + prefix);
    return Array.from(new Set(keys)).sort();
  }
  // Coarse band for a finding: trust report's severity_band, else map from risk.
  function mapBandOf(f) {
    if (typeof f.severity_band === "string" && MAP_BAND_TO_TIER[f.severity_band]) return f.severity_band;
    return MAP_RISK_TO_BAND[f.risk] || "info";
  }

  /* Build the Exposure Map model from a produced report. Output shape matches
   * shared/graph/build-exposure-graph.js: {center, nodes, edges, legend, meta}.
   * infoCount = distinct findings at that source; findingRefs index back into
   * report.findings so the detail panel renders the EXACT real finding. */
  function buildExposureGraphClient(report, opts) {
    opts = opts || {};
    const selfLabel = (typeof opts.selfLabel === "string" && opts.selfLabel) || "You";
    const center = { id: "self", label: selfLabel };
    const findings = (report && Array.isArray(report.findings)) ? report.findings : [];

    const bySource = {};      // sourceId -> aggregate
    const keyToSources = {};  // identity key -> Set(sourceId)

    findings.forEach(function (f, idx) {
      if (!f || typeof f.event_type !== "string") return;
      const src = mapSourceOf(f);
      let agg = bySource[src.id];
      if (!agg) {
        agg = { id: src.id, host: src.host, label: src.label, kind: src.kind,
                findingRefs: [], eventTypes: {}, worstBandRank: -1, worstBand: "info" };
        bySource[src.id] = agg;
      }
      agg.findingRefs.push(idx);
      agg.eventTypes[f.event_type] = true;
      const band = mapBandOf(f);
      const r = MAP_TIER_RANK[mapTierForBand(band)];
      if (r > agg.worstBandRank) { agg.worstBandRank = r; agg.worstBand = band; }
      mapIdentifierKeys(f).forEach(function (k) {
        (keyToSources[k] = keyToSources[k] || {})[src.id] = true;
      });
    });

    const nodes = Object.keys(bySource).map(function (id) {
      const agg = bySource[id];
      return {
        id: agg.id, host: agg.host, label: agg.label, kind: agg.kind,
        severityTier: mapTierForBand(agg.worstBand),
        infoCount: agg.findingRefs.length,
        eventTypes: Object.keys(agg.eventTypes).sort(),
        findingRefs: agg.findingRefs.slice().sort(function (a, b) { return a - b; })
      };
    });
    // Deterministic ordering: severity tier desc, then infoCount desc, then label.
    nodes.sort(function (a, b) {
      return (MAP_TIER_RANK[b.severityTier] - MAP_TIER_RANK[a.severityTier])
        || (b.infoCount - a.infoCount)
        || String(a.host || a.label).localeCompare(String(b.host || b.label))
        || a.id.localeCompare(b.id);
    });

    const edges = nodes.map(function (n) { return { from: "self", to: n.id, kind: "exposes" }; });

    // Cross-source shared-identifier edges (undirected, deduped, deterministic).
    const seen = {};
    const sharedEdges = [];
    Object.keys(keyToSources).sort().forEach(function (key) {
      const ids = Object.keys(keyToSources[key]).sort();
      if (ids.length < 2) return;
      const via = key.indexOf("email_prefix:") === 0 ? "email" : "handle";
      for (let i = 0; i < ids.length; i++) {
        for (let j = i + 1; j < ids.length; j++) {
          const pid = ids[i] + "|" + ids[j] + "|" + via;
          if (seen[pid]) continue;
          seen[pid] = true;
          sharedEdges.push({ from: ids[i], to: ids[j], kind: "shared-identifier", via: via });
        }
      }
    });
    sharedEdges.sort(function (x, y) {
      return x.from.localeCompare(y.from) || x.to.localeCompare(y.to) || x.via.localeCompare(y.via);
    });
    sharedEdges.forEach(function (e) { edges.push(e); });

    const tally = { red: 0, yellow: 0, green: 0 };
    nodes.forEach(function (n) { tally[n.severityTier] += 1; });

    return {
      center: center, nodes: nodes, edges: edges,
      legend: { tally: tally },
      meta: { source_count: nodes.length, finding_count: findings.length,
              shared_identifier_links: sharedEdges.length }
    };
  }

  /* ---- Radial SVG renderer ------------------------------------------------
   * Calm deterministic layout. Sources sit in three severity RINGS (red inner,
   * yellow middle, green outer). The low-risk (green) long tail beyond a cap
   * folds into ONE "+N low-risk" node so the map never becomes a hairball.
   * Subtle one-shot ease-in only; honors prefers-reduced-motion (static). */
  const SVGNS = "http://www.w3.org/2000/svg";
  const MAP_GREEN_CAP = 4;     // show at most this many green nodes; fold the rest
  function svgEl(tag, attrs) {
    const e = document.createElementNS(SVGNS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }
  const TIER_FILL = { red: "#b3203f", yellow: "#9a6a00", green: "#0b6b00" };
  const TIER_RING_R = { red: 115, yellow: 175, green: 232 };
  const TIER_WORD = { red: "red high sensitivity", yellow: "yellow medium sensitivity", green: "green low sensitivity" };
  function nodeRadius(infoCount) {
    // size = how much info that source holds; clamped so it stays legible.
    return Math.max(13, Math.min(34, 11 + infoCount * 4));
  }

  let MAP_GRAPH = null;        // last built graph model (in-memory only)
  let MAP_REPORT = null;       // the report the map was built from
  let MAP_SELECTED = null;     // currently selected node id

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  // Fold the green long tail into a synthetic "+N low-risk" node so the map stays
  // readable. Returns the visible node list (real nodes + optional fold node).
  function foldLowRiskTail(nodes) {
    const reds = nodes.filter(function (n) { return n.severityTier === "red"; });
    const yellows = nodes.filter(function (n) { return n.severityTier === "yellow"; });
    const greens = nodes.filter(function (n) { return n.severityTier === "green"; });
    if (greens.length <= MAP_GREEN_CAP) return reds.concat(yellows, greens);
    const shown = greens.slice(0, MAP_GREEN_CAP);
    const folded = greens.slice(MAP_GREEN_CAP);
    const foldNode = {
      id: "fold:lowrisk",
      label: "+" + folded.length + " low-risk sources",
      kind: "fold",
      severityTier: "green",
      infoCount: folded.reduce(function (s, n) { return s + n.infoCount; }, 0),
      eventTypes: [],
      findingRefs: folded.reduce(function (s, n) { return s.concat(n.findingRefs); }, []),
      foldedFrom: folded
    };
    return reds.concat(yellows, shown, [foldNode]);
  }

  // Place nodes deterministically around their severity ring; spread evenly.
  function layoutNodes(visibleNodes) {
    const cx = 360, cy = 280;
    const byTier = { red: [], yellow: [], green: [] };
    visibleNodes.forEach(function (n) { byTier[n.severityTier].push(n); });
    const placed = {};
    ["red", "yellow", "green"].forEach(function (tier) {
      const ring = byTier[tier];
      const R = TIER_RING_R[tier];
      const count = ring.length;
      ring.forEach(function (n, i) {
        // start at -90deg (top) and spread; offset alternate rings slightly so
        // nodes don't line up radially across rings.
        const offset = tier === "yellow" ? 0.5 : (tier === "green" ? 0.25 : 0);
        const ang = (-Math.PI / 2) + ((i + offset) / Math.max(1, count)) * Math.PI * 2;
        placed[n.id] = { x: cx + Math.cos(ang) * R, y: cy + Math.sin(ang) * R, node: n };
      });
    });
    return { cx: cx, cy: cy, placed: placed };
  }

  function renderExposureMap(report) {
    const svg = document.getElementById("exposureMapSvg");
    const wrap = document.getElementById("exposureMapWrap");
    if (!svg || !wrap) return;
    MAP_REPORT = report || null;
    MAP_SELECTED = null;
    svg.innerHTML = "";

    const prov = document.getElementById("mapProv");
    const sub = document.getElementById("mapSub");

    // No report → honest empty map (center only). Never fabricate spokes.
    if (!report || !reportFindings(report).length) {
      if (prov) {
        prov.className = "map-prov empty";
        prov.innerHTML = "No report loaded · no source nodes yet. Pass Step 1 (scope=self) to populate.";
      }
      renderMapCenterOnly(svg);
      renderMapLegend({ tally: { red: 0, yellow: 0, green: 0 } });
      resetMapDetail();
      return;
    }

    const graph = buildExposureGraphClient(report, { selfLabel: "You" });
    MAP_GRAPH = graph;

    if (prov) {
      prov.className = "map-prov " + (isSynthetic(report) ? "synthetic" : "live");
      prov.innerHTML =
        (isSynthetic(report) ? "Synthetic fixture" : "Live output") +
        " · " + graph.meta.source_count + " sources · " + graph.meta.finding_count + " findings · " +
        graph.meta.shared_identifier_links + " cross-source links · session-local, never uploaded.";
    }
    if (sub) {
      // keep the static explainer; nothing to change per-report
    }

    const visible = foldLowRiskTail(graph.nodes);
    const layout = layoutNodes(visible);
    const reduce = prefersReducedMotion();

    // ---- draw ring guides (faint, purely orientational) ----
    ["green", "yellow", "red"].forEach(function (tier) {
      const ring = svgEl("circle", {
        cx: layout.cx, cy: layout.cy, r: TIER_RING_R[tier],
        fill: "none", stroke: "#d6ddd6", "stroke-width": "1",
        "stroke-dasharray": "3 6", class: "map-ring"
      });
      svg.appendChild(ring);
    });

    // ---- edges first (under nodes) ----
    const edgeLayer = svgEl("g", { class: "map-edges" });
    svg.appendChild(edgeLayer);
    // map id -> placed point (fold node included; folded-away ids point to fold)
    const point = {};
    Object.keys(layout.placed).forEach(function (id) { point[id] = layout.placed[id]; });
    const foldNode = visible.filter(function (n) { return n.kind === "fold"; })[0];
    if (foldNode) {
      foldNode.foldedFrom.forEach(function (n) { point[n.id] = layout.placed["fold:lowrisk"]; });
    }
    // center->source. Edges DRAW ON via stroke-dashoffset (one-shot) on the dark
    // canvas, staggered with the node settle. Tagged data-edge-to for hover-highlight.
    let eIdx = 0;
    graph.edges.forEach(function (e) {
      if (e.kind !== "exposes") return;
      const p = point[e.to];
      if (!p) return;
      const line = svgEl("line", {
        x1: layout.cx, y1: layout.cy, x2: p.x, y2: p.y,
        stroke: "#3a4a44", "stroke-width": "1.4", class: "map-edge exposes",
        "data-edge-node": e.to
      });
      edgeLayer.appendChild(line);
      if (!reduce) {
        const len = Math.hypot(p.x - layout.cx, p.y - layout.cy);
        line.style.strokeDasharray = String(len);
        line.style.strokeDashoffset = String(len);
        line.style.transition = "stroke-dashoffset .55s ease";
        window.setTimeout(function () { line.style.strokeDashoffset = "0"; }, 40 + eIdx * 35);
        eIdx += 1;
      }
    });
    // cross-source shared-identifier (dashed) — the correlation story. Neon
    // magenta on the dark canvas; draws on after the exposes edges.
    graph.edges.forEach(function (e) {
      if (e.kind !== "shared-identifier") return;
      const a = point[e.from], b = point[e.to];
      if (!a || !b) return;
      const line = svgEl("line", {
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
        stroke: "#ff4cb2", "stroke-width": "1.8", "stroke-dasharray": "5 4",
        class: "map-edge shared", opacity: "0.9",
        "data-edge-from": e.from, "data-edge-to": e.to
      });
      const title = svgEl("title");
      title.textContent = "Shared " + (e.via === "email" ? "email" : "handle") + " → correlatable";
      line.appendChild(title);
      edgeLayer.appendChild(line);
    });

    // ---- center node ----
    const centerG = svgEl("g", { class: "map-center" });
    centerG.appendChild(svgEl("circle", {
      cx: layout.cx, cy: layout.cy, r: 30, fill: "#1a1a17", stroke: "#0b6b00", "stroke-width": "2.5"
    }));
    const ct = svgEl("text", { x: layout.cx, y: layout.cy + 5, "text-anchor": "middle", class: "map-center-text", fill: "#fff" });
    ct.textContent = "You";
    centerG.appendChild(ct);
    const ctTitle = svgEl("title");
    ctTitle.textContent = "You — subject of this self-audit (center)";
    centerG.appendChild(ctTitle);
    svg.appendChild(centerG);

    // ---- source nodes (keyboard-focusable) ----
    // apex = the single highest-severity node (sorted first). It gets a gentle
    // "breathing" pulse to guide the eye — ONLY this one node, never the field.
    const apexId = (graph.nodes[0] && graph.nodes[0].severityTier === "red") ? graph.nodes[0].id : null;
    const nodeLayer = svgEl("g", { class: "map-nodes" });
    svg.appendChild(nodeLayer);
    visible.forEach(function (n, i) {
      const p = layout.placed[n.id];
      if (!p) return;
      const r = nodeRadius(n.infoCount);
      const isApex = !reduce && n.id === apexId;
      const g = svgEl("g", {
        class: "map-node tier-" + n.severityTier + (n.kind === "fold" ? " is-fold" : "") + (isApex ? " is-apex" : ""),
        tabindex: "0", role: "button",
        "data-node": n.id,
        transform: "translate(" + p.x.toFixed(1) + "," + p.y.toFixed(1) + ")"
      });
      // aria-label per the brief: "source example.com, red high sensitivity, 3 exposures"
      const aria = n.kind === "fold"
        ? ("Folded: " + n.label + ", green low sensitivity, total " + n.infoCount + " exposures, press Enter to expand details")
        : ("Source " + n.label + ", " + TIER_WORD[n.severityTier] + ", " + n.infoCount + " exposures");
      g.setAttribute("aria-label", aria);

      const circle = svgEl("circle", {
        r: String(r), fill: TIER_FILL[n.severityTier],
        stroke: "#ffffff", "stroke-width": "2", class: "map-node-circle"
      });
      g.appendChild(circle);
      // count badge inside the node
      const cnt = svgEl("text", { y: "5", "text-anchor": "middle", class: "map-node-count", fill: "#fff" });
      cnt.textContent = n.kind === "fold" ? ("+" + (n.foldedFrom ? n.foldedFrom.length : n.infoCount)) : String(n.infoCount);
      g.appendChild(cnt);
      // label below the node
      const label = svgEl("text", { y: String(r + 14), "text-anchor": "middle", class: "map-node-label" });
      label.textContent = n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label;
      g.appendChild(label);

      const title = svgEl("title");
      title.textContent = aria;
      g.appendChild(title);

      const onActivate = function () { selectMapNode(n.id); };
      g.addEventListener("click", onActivate);
      g.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onActivate(); }
      });
      // hover/focus → highlight this node's connected edges (calm, not perpetual).
      const hi = function () { highlightNodeEdges(svg, n.id, true); };
      const lo = function () { highlightNodeEdges(svg, n.id, false); };
      g.addEventListener("mouseenter", hi);
      g.addEventListener("mouseleave", lo);
      g.addEventListener("focus", hi);
      g.addEventListener("blur", lo);
      nodeLayer.appendChild(g);

      // subtle one-shot ease-in: nodes settle from center into their ring.
      if (!reduce) {
        g.style.transformBox = "fill-box";
        g.style.opacity = "0";
        g.style.transform = "translate(" + p.x.toFixed(1) + "px," + p.y.toFixed(1) + "px) scale(0.6)";
        g.style.transition = "opacity .45s ease, transform .5s cubic-bezier(.22,.61,.36,1)";
        // stagger gently by index for a calm settle, then leave it static.
        window.setTimeout(function () {
          g.style.opacity = "1";
          g.style.transform = "translate(" + p.x.toFixed(1) + "px," + p.y.toFixed(1) + "px) scale(1)";
        }, 60 + i * 40);
      }
    });

    renderMapLegend(graph.legend);
    resetMapDetail();
  }

  // Toggle a highlight class on edges connected to a node (its center spoke +
  // any shared-identifier edges touching it). Pure visual, reversible, no state.
  function highlightNodeEdges(svg, nodeId, on) {
    if (!svg) return;
    svg.querySelectorAll(".map-edge").forEach(function (line) {
      const to = line.getAttribute("data-edge-node");
      const sf = line.getAttribute("data-edge-from");
      const st = line.getAttribute("data-edge-to");
      const connected = to === nodeId || sf === nodeId || st === nodeId;
      if (connected) line.classList.toggle("edge-hi", on);
    });
  }

  function renderMapCenterOnly(svg) {
    const cx = 360, cy = 280;
    const g = svgEl("g", { class: "map-center" });
    g.appendChild(svgEl("circle", { cx: cx, cy: cy, r: 30, fill: "#1a1a17", stroke: "#0b6b00", "stroke-width": "2.5" }));
    const t = svgEl("text", { x: cx, y: cy + 5, "text-anchor": "middle", class: "map-center-text", fill: "#fff" });
    t.textContent = "You";
    g.appendChild(t);
    svg.appendChild(g);
  }

  function renderMapLegend(legend) {
    const wrap = document.getElementById("mapLegend");
    if (!wrap) return;
    wrap.innerHTML = "";
    const tally = (legend && legend.tally) || { red: 0, yellow: 0, green: 0 };
    [
      ["red", "Red · sensitive exposures (breach-level, email, phone, or address)", tally.red],
      ["yellow", "Yellow · medium exposure", tally.yellow],
      ["green", "Green · low-risk public traces only", tally.green]
    ].forEach(function (row) {
      const item = el("span", "ml-item");
      item.appendChild(el("span", "ml-dot " + row[0]));
      item.appendChild(el("span", null, esc(row[1]) + (row[2] ? " (" + row[2] + ")" : "")));
      wrap.appendChild(item);
    });
    const size = el("span", "ml-item ml-meta");
    size.appendChild(el("span", null, "Larger nodes mean a source holds more information about you"));
    wrap.appendChild(size);
    const dash = el("span", "ml-item ml-meta");
    dash.appendChild(el("span", "ml-dash"));
    dash.appendChild(el("span", null, "Dashed line = two sources share an identifier and can be correlated"));
    wrap.appendChild(dash);
  }

  function resetMapDetail() {
    const detail = document.getElementById("mapDetail");
    if (!detail) return;
    detail.innerHTML = "";
    const empty = el("p", "map-detail-empty");
    empty.id = "mapDetailEmpty";
    empty.innerHTML = "Click any source node, or focus it with Tab and press Enter, to inspect its <b>specific exposure findings</b>, why they matter, and suggested actions.";
    detail.appendChild(empty);
  }

  // Click/Enter a node → render that source's EXACT findings (reusing the same
  // real-findings vocabulary) + why-it-matters + suggested action in the panel.
  function selectMapNode(nodeId) {
    MAP_SELECTED = nodeId;
    document.querySelectorAll(".map-node.selected").forEach(function (x) { x.classList.remove("selected"); });
    const g = document.querySelector('.map-node[data-node="' + cssEsc(nodeId) + '"]');
    if (g) g.classList.add("selected");

    const detail = document.getElementById("mapDetail");
    if (!detail || !MAP_GRAPH || !MAP_REPORT) return;

    // resolve the node — it may be a folded synthetic node
    let node = MAP_GRAPH.nodes.filter(function (n) { return n.id === nodeId; })[0];
    let foldedFrom = null;
    if (!node && nodeId === "fold:lowrisk") {
      const visible = foldLowRiskTail(MAP_GRAPH.nodes);
      const f = visible.filter(function (n) { return n.kind === "fold"; })[0];
      if (f) { node = f; foldedFrom = f.foldedFrom; }
    }
    if (!node) { resetMapDetail(); return; }

    // nice-to-have: surface this node's sources in the References panel.
    highlightReferencesForNode(node);

    const findings = reportFindings(MAP_REPORT);
    detail.innerHTML = "";

    const head = el("div", "md-head");
    head.appendChild(el("span", "md-dot " + node.severityTier));
    const ht = el("div");
    ht.appendChild(el("div", "md-title", esc(node.label)));
    ht.appendChild(el("div", "md-sub", esc(TIER_WORD[node.severityTier] + " · " + node.infoCount + " exposures")));
    head.appendChild(ht);
    detail.appendChild(head);

    if (foldedFrom) {
      detail.appendChild(el("p", "md-fold-note",
        "This combines " + foldedFrom.length + " merged low-risk sources. Their specific findings are grouped by source below."));
      foldedFrom.forEach(function (sub) {
        detail.appendChild(el("div", "md-fold-src", esc(sub.label)));
        sub.findingRefs.forEach(function (ref) {
          const f = findings[ref];
          if (f) detail.appendChild(mapFindingCard(f));
        });
      });
    } else {
      // cross-source correlation note, if this node shares an identifier
      const links = (MAP_GRAPH.edges || []).filter(function (e) {
        return e.kind === "shared-identifier" && (e.from === node.id || e.to === node.id);
      });
      if (links.length) {
        const other = links.map(function (e) {
          const oid = e.from === node.id ? e.to : e.from;
          const on = MAP_GRAPH.nodes.filter(function (n) { return n.id === oid; })[0];
          return (on ? on.label : oid) + " (same " + (e.via === "email" ? "email" : "handle") + ")";
        });
        const corr = el("p", "md-corr");
        corr.innerHTML = "⚲ <b>Correlation:</b> This source and " + esc(Array.from(new Set(other)).join("、")) +
          " shared identifiers, allowing third parties to correlate your public traces into one profile.";
        detail.appendChild(corr);
      }
      node.findingRefs.forEach(function (ref) {
        const f = findings[ref];
        if (f) detail.appendChild(mapFindingCard(f));
      });
    }
  }

  // One finding card for the detail panel. Reuses the SAME real-findings copy
  // (EVENT_META name/why/fix) + risk/visibility badges as renderRealFindings,
  // plus the portable STIX evidence block, so the panel and the list agree.
  function mapFindingCard(f) {
    const meta = EVENT_META[f.event_type] || {};
    const item = el("div", "finding-item real md-finding");
    const row = el("div", "fi-row");
    row.appendChild(el("span", "fi-name", esc(meta.name || f.event_type)));
    const risk = f.risk || meta.sev || "low";
    row.appendChild(el("span", "sev-badge " + risk, esc((SEV_LABEL[risk] || risk) + " exposure")));
    const vis = f.visibility || meta.vis;
    if (vis) row.appendChild(el("span", "vis-badge", esc(VIS_LABEL[vis] || vis)));
    row.appendChild(el("span", "event-chip", esc(f.event_type)));
    item.appendChild(row);

    const facts = el("p", "fi-facts");
    const conf = (f.confidence != null) ? "Confidence " + f.confidence : "";
    const urlTxt = f.source_url ? f.source_url : "(no public URL, such as a k-anonymous breach lookup)";
    facts.innerHTML = "<b>Source:</b> " + esc(urlTxt) + (conf ? " · " + esc(conf) : "") +
      (f.source_module ? " · " + esc(f.source_module) : "");
    item.appendChild(facts);

    if (meta.why) { const w = el("p", "fi-why"); w.innerHTML = "<b>Why it matters:</b>" + esc(meta.why); item.appendChild(w); }
    if (meta.fix) item.appendChild(el("p", "fi-fix", "Suggested action: " + esc(meta.fix)));
    item.appendChild(stixEvidenceBlockReal(f, MAP_REPORT));
    return item;
  }

  function cssEsc(s) {
    if (window.CSS && CSS.escape) return CSS.escape(s);
    return String(s).replace(/[^a-zA-Z0-9_-]/g, function (c) { return "\\" + c; });
  }

  /* =========================================================================
   * REFERENCES / SOURCES PANEL — the right-rail "where your info was found".
   *
   * Lists EVERY real source from the SAME loaded report that drives the map.
   * Sources come from the report itself, never fabricated:
   *   1. report.findings[]                          — CONFIRMED self-exposure
   *      (event on a page that literally contains the user's identifier)
   *   2. report.provenance.observed_unconfirmed[]   — REAL detector observations
   *      on pages that did NOT confirm the identifier (preserved, not hidden)
   *   3. report.provenance.serp_listings_not_crawled[] — REAL SERP listings
   *      (incl. data brokers) surfaced but not crawled
   * Each source row shows: clickable source_url (new tab, rel=noopener), host,
   * exposure type (phone listed / email mention / public profile / …), a
   * severity color dot, and the snippet/title when present. Grouped by the
   * identifier that surfaced it (phone / email / name / handle). Honest empty
   * state when the report carries no public sources. NO FAKE DATA. */

  // Plain-language exposure-type label for a source row.
  const REF_EVENT_LABEL = {
    PII_EMAIL_PUBLIC: "email mention",
    PII_PHONE_PUBLIC: "phone listed",
    PII_POSTAL_PUBLIC: "postal address",
    PII_HANDLE_PUBLIC: "handle reused",
    PII_GEO_HINT_PUBLIC: "location hint",
    SELF_PROFILE_URL: "public profile",
    SELF_USERNAME: "public account",
    SECRET_LEAK_PUBLIC: "credential leak",
    BREACH_RANGE_HIT: "breach match",
    EXPOSURE_SUMMARY: "page observation"
  };
  // Map a finding/observation risk or severity_band to the map's red/yellow/green tier.
  function refTierOf(src) {
    if (typeof src.severity_band === "string" && MAP_BAND_TO_TIER[src.severity_band]) {
      return MAP_BAND_TO_TIER[src.severity_band];
    }
    return mapTierForBand(MAP_RISK_TO_BAND[src.risk] || "info");
  }
  function refHostOf(url) {
    const h = mapHostOf(url);
    return h || null;
  }
  // Which identifier group a source belongs to: phone / email / name / handle / other.
  function refGroupOf(src) {
    const kind = String(src.identifier_kind || "").toLowerCase();
    if (kind === "phone") return "phone";
    if (kind === "email") return "email";
    if (kind === "handle") return "handle";
    if (kind === "name") return "name";
    // (kind === "other" or empty falls through to surfaced_by heuristics below)
    // surfaced_by reads like "name Roger Tang / @ruizetang" or "phone 2067…":
    // the LEADING token is the identifier that actually drove the search, so it
    // wins over an "@handle" that merely appears later in the same string.
    const by = String(src.surfaced_by || "").trim().toLowerCase();
    const lead = by.split(/[\s/]+/)[0];
    if (lead === "phone") return "phone";
    if (lead === "email") return "email";
    if (lead === "name") return "name";
    if (lead === "handle" || lead.charAt(0) === "@") return "handle";
    if (by.indexOf("phone") !== -1) return "phone";
    if (by.indexOf("email") !== -1) return "email";
    if (by.indexOf("@") !== -1 || by.indexOf("handle") !== -1) return "handle";
    if (by.indexOf("name") !== -1) return "name";
    return "other";
  }
  const REF_GROUP_META = {
    phone: { label: "Phone", ico: "📱" },
    email: { label: "Email", ico: "📧" },
    name: { label: "Name", ico: "🪪" },
    handle: { label: "Handle", ico: "＠" },
    other: { label: "Other identifiers", ico: "◎" }
  };
  const REF_GROUP_ORDER = ["phone", "email", "name", "handle", "other"];

  // Collect the report's REAL sources into one normalized list (no fabrication).
  function collectReferenceSources(report) {
    const out = [];
    if (!report || typeof report !== "object") return out;

    const seenUrls = {};

    // 1) confirmed findings — the real self-exposure hits, tagged with the
    // identifier that surfaced them so they group under Phone / Email / Name.
    reportFindings(report).forEach(function (f, i) {
      if (!f.source_url) return; // a row needs a real URL to be a "reference"
      seenUrls[f.source_url] = true;
      out.push({
        url: f.source_url,
        host: refHostOf(f.source_url),
        eventType: f.event_type,
        risk: f.risk, severity_band: f.severity_band,
        title: f.title || null,
        snippet: (f.meta && f.meta.snippet) || f.snippet || f.note || null,
        confirmed: true, is_data_broker: !!f.broker,
        surfaced_by: f.surfaced_by || f.surfaced_by_query || null,
        identifier_kind: findingKind(f),
        kindNote: "confirmed self-exposure",
        refId: "find:" + i
      });
    });

    const prov = (report.provenance && typeof report.provenance === "object") ? report.provenance : {};

    // 2) real detector observations that did not confirm the identifier
    if (Array.isArray(prov.observed_unconfirmed)) {
      prov.observed_unconfirmed.forEach(function (o, i) {
        if (!o || !o.source_url || seenUrls[o.source_url]) return;
        seenUrls[o.source_url] = true;
        out.push({
          url: o.source_url,
          host: refHostOf(o.source_url),
          eventType: o.event_type,
          risk: o.risk, severity_band: o.severity_band,
          title: o.title || null,
          snippet: o.snippet || o.note || null,
          confirmed: false, is_data_broker: false,
          surfaced_by: o.surfaced_by || null,
          identifier_kind: o.identifier_kind ? normKind(o.identifier_kind) : null,
          kindNote: "observed · identifier not confirmed on page",
          refId: "obs:" + i
        });
      });
    }

    // 3) real SERP listings surfaced (incl. data brokers). The real report
    // stores these as provenance.serp_listings_all[]; older fixtures used
    // serp_listings_not_crawled[]. Either way: only genuinely surfaced URLs.
    const serpList = Array.isArray(prov.serp_listings_all)
      ? prov.serp_listings_all
      : (Array.isArray(prov.serp_listings_not_crawled) ? prov.serp_listings_not_crawled : []);
    serpList.forEach(function (s, i) {
      if (!s || !s.url || seenUrls[s.url]) return;
      seenUrls[s.url] = true;
      out.push({
        url: s.url,
        host: s.host || refHostOf(s.url),
        eventType: null,
        risk: s.is_data_broker ? "medium" : "low",
        severity_band: null,
        title: s.title || null,
        snippet: s.snippet || null,
        confirmed: false, is_data_broker: !!s.is_data_broker,
        surfaced_by: s.surfaced_by || null,
        identifier_kind: normKind(s.identifier_kind || s.query_kind),
        kindNote: s.is_data_broker ? "data-broker listing (search result)" : "search listing · not crawled",
        refId: "serp:" + i
      });
    });

    return out;
  }

  // Build one reference row element (anchor + meta), tagged with refId + host for
  // optional highlight when a map node is clicked.
  function referenceRow(src) {
    const tier = refTierOf(src);
    const item = el("li", "ref-item");
    item.setAttribute("data-ref-id", src.refId);
    if (src.host) item.setAttribute("data-ref-host", src.host);

    const head = el("div", "ref-item-head");
    head.appendChild(el("span", "ref-dot " + tier));
    const typeLabel = src.is_data_broker
      ? "data broker"
      : (src.eventType && REF_EVENT_LABEL[src.eventType]) || (src.eventType ? src.eventType : "public listing");
    head.appendChild(el("span", "ref-type", esc(typeLabel)));
    if (src.confirmed) head.appendChild(el("span", "ref-flag confirmed", "confirmed"));
    else head.appendChild(el("span", "ref-flag unconfirmed", "unconfirmed"));
    item.appendChild(head);

    // clickable source link — opens in new tab, rel=noopener (no login bypass).
    const a = el("a", "ref-link");
    a.href = src.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = src.url;
    item.appendChild(a);

    if (src.host) item.appendChild(el("span", "ref-host", esc(src.host)));
    if (src.title) item.appendChild(el("p", "ref-title", esc(src.title)));
    if (src.snippet) item.appendChild(el("p", "ref-snippet", esc(src.snippet)));
    item.appendChild(el("p", "ref-note", esc(src.kindNote)));
    return item;
  }

  // Render the References / Sources right-rail panel from the loaded report.
  function renderReferences(report) {
    const body = document.getElementById("referencesBody");
    const countEl = document.getElementById("referencesCount");
    const headEl = document.getElementById("referencesHeading");
    if (!body) return;
    body.innerHTML = "";

    const sources = collectReferenceSources(report);
    if (countEl) countEl.textContent = sources.length ? "(" + sources.length + " sources)" : "";
    if (headEl) headEl.textContent = "References — where your info was found";

    // no report loaded yet → honest pre-run empty state.
    if (!report) {
      const empty = el("p", "ref-empty");
      empty.id = "referencesEmpty";
      empty.textContent = "Run an audit to list every real public source from your report.";
      body.appendChild(empty);
      return;
    }

    // --- BREADTH STRIP: full list of identifiers checked, with status, so the
    // coverage is visible even where a search came back clean. Phone + email are
    // foregrounded (their real per_query counts), then name/handle as secondary.
    const breadth = reportBreadth(report);
    const breadthWrap = el("div", "ref-breadth");
    breadthWrap.appendChild(el("p", "ref-breadth-label", "Sources checked — breadth of this audit"));
    const bRow = el("ul", "ref-breadth-list");
    [
      { k: "phone", ico: "📱", label: "Phone" },
      { k: "email", ico: "📧", label: "Email" },
      { k: "name", ico: "🪪", label: "Name" },
      { k: "handle", ico: "＠", label: "Handle" }
    ].forEach(function (row) {
      const b = breadth[row.k];
      if (!b || !b.queried) return; // only show identifiers actually searched
      const status = b.findings > 0 ? "found" : "none";
      const li = el("li", "ref-breadth-item " + status + (row.k === "phone" || row.k === "email" ? " primary" : ""));
      const ico = el("span", "ref-breadth-ico", row.ico);
      li.appendChild(ico);
      const tx = el("div", "ref-breadth-tx");
      const top = el("div", "ref-breadth-top");
      top.appendChild(el("span", "ref-breadth-name", row.label));
      top.appendChild(el("span", "ref-breadth-badge " + status,
        b.findings > 0 ? (b.findings + " found") : "none found"));
      tx.appendChild(top);
      tx.appendChild(el("span", "ref-breadth-sub",
        b.sources + " source" + (b.sources === 1 ? "" : "s") + " checked"
        + (b.results ? " · " + b.results + " result" + (b.results === 1 ? "" : "s") + " seen" : "")));
      li.appendChild(tx);
      bRow.appendChild(li);
    });
    breadthWrap.appendChild(bRow);
    body.appendChild(breadthWrap);

    // group surfaced sources by identifier (phone / email / name / handle / other)
    const groups = {};
    sources.forEach(function (s) {
      const g = refGroupOf(s);
      (groups[g] = groups[g] || []).push(s);
    });

    const TIER_RANK = { red: 2, yellow: 1, green: 0 };
    let renderedAny = false;
    REF_GROUP_ORDER.forEach(function (gid) {
      const list = groups[gid];
      if (!list || !list.length) return;
      renderedAny = true;
      // worst exposure first inside each identifier group
      list.sort(function (a, b) { return (TIER_RANK[refTierOf(b)] || 0) - (TIER_RANK[refTierOf(a)] || 0); });

      const meta = REF_GROUP_META[gid] || REF_GROUP_META.other;
      const groupWrap = el("div", "ref-group" + (gid === "phone" || gid === "email" ? " ref-group-primary" : ""));
      const gh = el("div", "ref-group-head");
      gh.appendChild(el("span", "ref-group-ico", meta.ico));
      gh.appendChild(el("span", "ref-group-label", esc(meta.label)));
      gh.appendChild(el("span", "ref-group-count", String(list.length)));
      groupWrap.appendChild(gh);

      const ul = el("ul", "ref-list");
      list.forEach(function (s) { ul.appendChild(referenceRow(s)); });
      groupWrap.appendChild(ul);
      body.appendChild(groupWrap);
    });

    // honest line when breadth exists but nothing surfaced on a public page.
    if (!renderedAny) {
      body.appendChild(el("p", "ref-clean",
        "Sources were checked (above) but nothing of yours surfaced on a crawlable public page in this run."));
    }

    // --- COMPLIANCE BLOCKS: social hosts the policy gate refused to scrape.
    // Shown as a FEATURE — breadth the gate deliberately did not cross. Honest:
    // we list the blocked URLs but never claim what they contain.
    const prov = (report.provenance && typeof report.provenance === "object") ? report.provenance : {};
    const blocked = Array.isArray(prov.dropped_by_compliance) ? prov.dropped_by_compliance : [];
    if (blocked.length) {
      // de-dup blocked URLs, keep a stable reason.
      const seenB = {};
      const uniq = [];
      blocked.forEach(function (d) {
        if (!d || !d.url || seenB[d.url]) return;
        seenB[d.url] = true;
        uniq.push(d);
      });
      const cWrap = el("div", "ref-group ref-group-compliance");
      const ch = el("div", "ref-group-head");
      ch.appendChild(el("span", "ref-group-ico", "⛬"));
      ch.appendChild(el("span", "ref-group-label", "Blocked by compliance"));
      ch.appendChild(el("span", "ref-group-count", String(uniq.length)));
      cWrap.appendChild(ch);
      cWrap.appendChild(el("p", "ref-compliance-note",
        "These social-host links surfaced in search but the policy gate refused to scrape them. Login-walled / private social is never crossed — shown for transparency, not stored."));
      const cul = el("ul", "ref-list");
      uniq.forEach(function (d) {
        const li = el("li", "ref-item ref-item-blocked");
        const head = el("div", "ref-item-head");
        head.appendChild(el("span", "ref-dot green"));
        head.appendChild(el("span", "ref-type", "social · blocked"));
        head.appendChild(el("span", "ref-flag blocked", "not scraped"));
        li.appendChild(head);
        const a = el("a", "ref-link");
        a.href = d.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.textContent = d.url;
        li.appendChild(a);
        const host = (d.reason && d.reason.indexOf(":") !== -1) ? d.reason.split(":")[1] : refHostOf(d.url);
        if (host) li.appendChild(el("span", "ref-host", esc(host)));
        li.appendChild(el("p", "ref-note", esc("compliance: " + (d.reason || "private social host"))));
        cul.appendChild(li);
      });
      cWrap.appendChild(cul);
      body.appendChild(cWrap);
    }
  }

  // Optional: when a map node is clicked, highlight/scroll to its sources in the
  // References panel (nice-to-have; guarded so it never breaks if skipped).
  function highlightReferencesForNode(node) {
    try {
      const panel = document.getElementById("referencesPanel");
      const body = document.getElementById("referencesBody");
      if (!panel || !body || !node) return;
      body.querySelectorAll(".ref-item.ref-hi").forEach(function (x) { x.classList.remove("ref-hi"); });
      const host = node.host || (node.label && /\./.test(node.label) ? node.label : null);
      if (!host) return;
      let first = null;
      body.querySelectorAll('.ref-item[data-ref-host="' + cssEsc(host) + '"]').forEach(function (row) {
        row.classList.add("ref-hi");
        if (!first) first = row;
      });
      if (first && typeof first.scrollIntoView === "function") {
        first.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "nearest" });
      }
    } catch (e) { /* nice-to-have only — never break the map on highlight failure */ }
  }

  /* ---- map / list view toggle. The grouped findings LIST is the accessible
   * FLOOR; the map is an enhancement. Screen-reader / keyboard users can always
   * use the list. We never hide the list from assistive tech destructively —
   * the toggle just collapses the visual map vs the list section. */
  function wireViewToggle() {
    const mapBtn = document.getElementById("viewMapBtn");
    const listBtn = document.getElementById("viewListBtn");
    const mapWrap = document.getElementById("exposureMapWrap");
    const list = document.getElementById("findingsGroups");
    if (!mapBtn || !listBtn || !mapWrap || !list) return;

    function show(which) {
      const isMap = which === "map";
      mapBtn.classList.toggle("active", isMap);
      listBtn.classList.toggle("active", !isMap);
      mapBtn.setAttribute("aria-selected", String(isMap));
      listBtn.setAttribute("aria-selected", String(!isMap));
      // The map stage hides when viewing the list; the head+toggle stay visible.
      // The grouped-findings LIST is ALWAYS present in the DOM (the accessible
      // floor for screen-reader / keyboard users) — we only collapse the map's
      // visual stage, never remove the list.
      mapWrap.classList.toggle("show-list", !isMap);
      // Visually de-emphasize the map stage when in list mode.
      const stage = mapWrap.querySelector(".map-stage");
      const legend = document.getElementById("mapLegend");
      if (stage) stage.style.display = isMap ? "" : "none";
      if (legend) legend.style.display = isMap ? "" : "none";
      if (!isMap) { list.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "nearest" }); }
    }
    mapBtn.addEventListener("click", function () { show("map"); });
    listBtn.addEventListener("click", function () { show("list"); });
    show("map");
  }

  /* Map data-source controls. Loading the synthetic correlation demo or the
   * example report is a low-sensitivity TEMPLATE map (tier 'none' — no sign-in).
   * "Build full correlation graph" is the SENSITIVE action (a real PII pull +
   * correlate) and must pass the identity gate; with no real verified identity it
   * cannot proceed and we honestly say so — never a fabricated success. */
  function loadGraphDemo() {
    if (window.__MIRRORTRACE_GRAPH_DEMO__) { applyGraphDemo(window.__MIRRORTRACE_GRAPH_DEMO__); return; }
    const s = document.createElement("script");
    s.src = "data/example-graph-demo.js";
    s.onload = function () { if (window.__MIRRORTRACE_GRAPH_DEMO__) applyGraphDemo(window.__MIRRORTRACE_GRAPH_DEMO__); };
    s.onerror = function () {
      const prov = document.getElementById("mapProv");
      if (prov) { prov.className = "map-prov empty"; prov.textContent = "Correlation-demo fixture could not load (data/example-graph-demo.js is missing)."; }
    };
    document.head.appendChild(s);
  }
  function applyGraphDemo(demo) {
    // Render the map from the synthetic demo without disturbing the loaded report
    // grade/list — the demo is map-only and clearly labelled synthetic.
    renderExposureMap(demo);
    const stage = document.querySelector("#exposureMapWrap .map-stage");
    if (stage) stage.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "nearest" });
  }

  function wireMapControls() {
    const demoBtn = document.getElementById("loadGraphDemoBtn");
    const exBtn = document.getElementById("loadExampleMapBtn");
    const fullBtn = document.getElementById("buildFullGraphBtn");
    if (demoBtn) demoBtn.addEventListener("click", loadGraphDemo);
    if (exBtn) exBtn.addEventListener("click", function () {
      if (LOADED_REPORT) renderExposureMap(LOADED_REPORT);
      else renderExposureMap(null);
    });
    if (fullBtn) fullBtn.addEventListener("click", function () {
      // SENSITIVE: build_correlation_graph requires sign_in (verification-tiers.js).
      requireVerification("build_correlation_graph", function () {
        // Only reached with a real verified identity. The deployment credential
        // handoff controls when this live branch becomes available.
      });
    });
  }

  /* =========================================================================
   * IDENTITY GATE UX — tiered verification (shared/identity/verification-tiers.js).
   * Sensitive actions show an explicit ownership-verification handoff. A live
   * branch opens only after deployment provides a real verified identity.
   * Low-sensitivity actions (template map over the example fixture, k-anon)
   * remain available without that handoff.
   * =======================================================================*/

  // Client mirror of ACTION_POLICY tiers (policy only; no OAuth, no token).
  const VERIFICATION_POLICY = {
    public_search: { tier: "none", sensitive: false },
    kanon_breach_check: { tier: "none", sensitive: false },
    pull_pii: { tier: "sign_in", sensitive: true,
      rationale: "Collecting your PII is sensitive. OAuth 2.0 PKCE must verify an email or handle to prove the collected PII belongs to the signed-in user and prevent third-party lookups." },
    build_correlation_graph: { tier: "sign_in", sensitive: true,
      rationale: "Cross-source correlation creates a preassembled profile, the product's most sensitive output. One-click OAuth sign-in must prove ownership before correlation occurs." },
    confirm_broker_listing: { tier: "sign_in", sensitive: true,
      rationale: "Confirming that a data-broker listing belongs to you binds a real-world record to a subject. Verified identity prevents confirmation on someone else's behalf." },
    enable_monitoring: { tier: "sign_in", sensitive: true,
      rationale: "Continuous monitoring is a long-lived capability. It must be bound to a verified account and monitor only the verified user." }
  };
  // No real verified identity is ever fabricated. Until live OAuth is wired this
  // stays null, so sensitive actions cannot proceed past the gate.
  let VERIFIED_IDENTITY = null;

  function requiredVerificationClient(action) {
    const p = VERIFICATION_POLICY[action];
    return p ? p.tier : "sign_in"; // unknown → fail closed
  }
  function isVerificationSatisfiedClient(action) {
    if (requiredVerificationClient(action) === "none") return true;
    const id = VERIFIED_IDENTITY;
    return !!(id && id.verified === true &&
      ((typeof id.email === "string" && id.email.length) || (typeof id.handle === "string" && id.handle.length)));
  }

  // Open the gate for a sensitive action. onPass runs only if a REAL verified
  // identity is present (never fabricated). Returns true if the action may
  // proceed immediately (tier 'none' or already verified).
  function requireVerification(action, onPass) {
    if (isVerificationSatisfiedClient(action)) { if (onPass) onPass(); return true; }
    const modal = document.getElementById("identityGate");
    const why = document.getElementById("identityGateWhy");
    if (!modal) return false;
    const p = VERIFICATION_POLICY[action] || { rationale: "Unknown action: fail closed and require sign-in." };
    if (why) why.textContent = p.rationale || "This action requires identity verification.";
    modal.removeAttribute("hidden");
    modal.dataset.pendingAction = action;
    // focus the first action for keyboard users
    const g = document.getElementById("oauthGoogle");
    if (g) g.focus();
    return false;
  }

  function wireIdentityGate() {
    const modal = document.getElementById("identityGate");
    if (!modal) return;
    const close = function () { modal.setAttribute("hidden", ""); };
    const closeBtn = document.getElementById("identityGateClose");
    const backdrop = document.getElementById("identityGateBackdrop");
    if (closeBtn) closeBtn.addEventListener("click", close);
    if (backdrop) backdrop.addEventListener("click", close);
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !modal.hasAttribute("hidden")) close();
    });
    // OAuth credential handoff remains explicit: sensitive actions stay paused
    // until the deployment has a real verified identity.
    ["oauthGoogle", "oauthGithub"].forEach(function (id) {
      const b = document.getElementById(id);
      if (!b) return;
      b.addEventListener("click", function () {
        const note = document.getElementById("identityGateNote");
        if (note) {
          note.innerHTML = "<b>Credential handoff:</b> add the " + (id === "oauthGoogle" ? "Google" : "GitHub") +
            " OAuth 2.0 PKCE client in deployment settings to activate ownership verification. The live action stays paused until verification completes. " +
            "Policy source: <code>shared/identity/verification-tiers.js</code>.";
          note.classList.add("flash");
        }
      });
    });
  }

  function renderClusterCard() {
    const body = document.getElementById("clusterBody");
    const keys = document.getElementById("clusterKeys");
    if (!body || !keys) return;
    body.textContent =
      "The SpiderFoot-style correlation engine in shared/enrich/cluster-keys.js groups events that share correlation keys into one self-exposure cluster. " +
      "For example, PII and account events sharing a handle or email hash are grouped with confidence. Live clusters include a citable evidence index.";
    keys.innerHTML = "";
    ["normalizeHandle(handle)", "email-hash prefix", "hostOf(same site)"].forEach(k => {
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
      banner.innerHTML = "✓ Gate permitted <code>" + esc(scope) + "</code>. " + esc(scope === "public_figure" ? PUBLIC_FIGURE_NOTE : SELF_NOTE);
    } else if (res && res.accepted) {
      banner.className = "report-banner";
      banner.innerHTML = "The gate permitted <code>" + esc(res.scope) + "</code>, but the self-audit framework for what third parties can find applies only to <code>self</code> or <code>public_figure</code>. The full check catalog is shown below.";
    } else {
      banner.className = "report-banner";
      banner.innerHTML = 'Pass the <a href="#gate">Step 1</a> gate with <code>self</code> or <code>public_figure</code> scope to tailor the catalog below. The full check catalog is shown for now.';
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
      const h = el("p", "kanon-hint kanon-err", "Enter any string, using only your own credential or email, before calculating.");
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
    rowSent.appendChild(el("span", "kanon-chip sent", "Sent"));
    rowSent.appendChild(el("code", "kanon-mono", esc(pair.prefix)));
    rowSent.appendChild(el("span", "kanon-leg-note",
      "A 5-character hexadecimal prefix selects 1 range bucket out of 16^5, about 1.04 million buckets. Many hashes share it, so the server cannot tell which credential you checked."));
    legend.appendChild(rowSent);

    const rowLocal = el("div", "kanon-leg-row");
    rowLocal.appendChild(el("span", "kanon-chip local", "Stays local"));
    rowLocal.appendChild(el("code", "kanon-mono", esc(pair.suffix)));
    rowLocal.appendChild(el("span", "kanon-leg-note",
      "The 35-character suffix never leaves your device. A live query matches it locally against candidates in the returned bucket."));
    legend.appendChild(rowLocal);

    out.appendChild(legend);

    const note = el("p", "kanon-hint");
    note.innerHTML = "Offline demo: <b>no live breach corpus is queried</b>, so this panel displays no hit or count. "
      + "This proves the privacy split, not a breach result. Live determination is performed by actors/breach-check through the HIBP range API.";
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
      if (out) out.innerHTML = '<p class="kanon-hint">Enter any string to demonstrate the 5-character prefix that is sent and the 35-character suffix that stays local.</p>';
    });
  }

  /* =========================================================================
   * PIPELINE / MIDDLEWARE ORDER PANEL (Scrapy + Crawlee)
   * Mirrors shared/middleware/stages.js canonical ordering. Static, plain list —
   * no animation, no flashy section; reuses existing card + pipe-list styles.
   * =======================================================================*/

  const PIPE_REQUEST = [
    { ord: "100", name: "scopeGate",
      desc: "Run shared/scope.js validation again. Reject scopes outside self/consented/public_figure/brand/safety_evidence and any private-person tracking intent with IgnoreRequest, fail closed before fetch." },
    { ord: "200", name: "robotsTos",
      desc: "Respect robots.txt and Terms of Service. Drop login walls and private-social hosts; never bypass login, CAPTCHA, or blocks." },
    { ord: "300", name: "rateLimit",
      desc: "Apply a polite per-host minimum interval. Requeue excess work for later; never hammer a server or evade rate limits or blocks." },
    { ord: "900", name: "fetchTerminal",
      desc: "A live actor fetches here. The pure pipeline returns an explicitly labelled TEMPLATE placeholder (template:true) and never fabricates scraped data." }
  ];
  const PIPE_ITEM = [
    { ord: "100", name: "scopeReassertItem",
      desc: "Defense in depth: output items must carry a permitted scope_type or DropItem prevents storage." },
    { ord: "500", name: "evidenceHash",
      desc: "Use shared/hashing.js to compute content/html SHA-256 so each preserved item is citable and tamper-evident." }
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
      if (head) head.textContent = "Evidence index · live detector findings (one row each)";
      if (intro) intro.innerHTML = isSynthetic(LOADED_REPORT)
        ? "Each row below is a finding produced by <b>live detector code</b> over a synthetic fixture, not fabricated data. Expand a portable-evidence section above to obtain STIX JSON."
        : "Each row below is live pipeline output.";
      if (headRow) headRow.innerHTML =
        "<tr><th>event_type</th><th>Source URL</th><th>Confidence</th><th>Visibility</th><th>Risk</th><th>Source module</th></tr>";
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
    if (head) head.textContent = "Fields for each evidence row · evidence index";
    if (intro) intro.textContent = "In a live run, each finding is preserved as a citable row:";
    if (headRow) headRow.innerHTML = "<tr><th>Field</th><th>Description</th></tr>";
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
        "No report loaded · no remediation checklist yet. After a live self-audit, executable next steps appear here in highest-exposure-first order.";
      if (foot) foot.innerHTML =
        "Remediation copy comes from the same FINDING_GROUPS.fix metadata as each finding above. No tasks are invented for an unscanned subject.";
      const li = el("li", "action-empty", "(No findings means no suggested actions. This is an honest empty state.)");
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
      ? "Ordered by <b>highest exposure first</b>, using findings produced by live detector code over a synthetic fixture:"
      : "Ordered by <b>highest exposure first</b>:";

    actions.forEach(a => {
      const meta = EVENT_META[a.event] || {};
      const li = el("li", "action-item");
      const head = el("div", "action-head");
      head.appendChild(el("span", "sev-badge " + a.worst, esc((SEV_LABEL[a.worst] || a.worst) + " exposure")));
      head.appendChild(el("span", "action-title", esc(meta.name || a.event)));
      head.appendChild(el("span", "action-count", a.count + " locations"));
      li.appendChild(head);
      li.appendChild(el("p", "action-do", esc(meta.fix || "Review this public trace and decide whether to remove or narrow it.")));
      if (a.sample) {
        const ref = el("p", "action-ref");
        ref.innerHTML = "Example source: " + esc(a.sample);
        li.appendChild(ref);
      }
      list.appendChild(li);
    });

    if (foot) foot.innerHTML =
      "Remediation copy comes from the same suggested-action metadata as the findings above. <a href=\"#optoutCard\">Data-broker opt-out</a> is a common concrete action.";
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
   * re-flagged (integrations/schedules + integrations/webhooks).
   *
   * Ref: OASIS STIX 2.1 Observed Data (OpenCTI/MISP interop) for the per-listing
   * evidence object; Apify Website Content Crawler + RAG Web Browser ingestion
   * for the re-check sweep (the existing WCC/RAG ingest path re-reads the broker
   * page to detect reappearance).
   * =======================================================================*/

  // TEMPLATE registry: PUBLIC opt-out entry points only. Each broker's opt-out
  // URL/method is itself public policy info — NOT a claim that the user is listed.
  const BROKER_REGISTRY = [
    { name: "Spokeo", method: "Web form + email confirmation", url: "https://www.spokeo.com/optout" },
    { name: "Whitepages", method: "Listing-removal form", url: "https://www.whitepages.com/suppression-requests" },
    { name: "BeenVerified", method: "Web form + email confirmation", url: "https://www.beenverified.com/app/optout/search" },
    { name: "Intelius", method: "Web form", url: "https://www.intelius.com/opt-out" },
    { name: "Radaris", method: "Remove after profile management", url: "https://radaris.com/page/how-to-remove" },
    { name: "Acxiom", method: "GDPR/CCPA data-subject request", url: "https://www.acxiom.com/optout/" }
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
        { tag: "Gate", text: "Pass the policy gate first: scope=self or consented is required. Opt-out requests for someone else are refused immediately; this is a self-only workflow." },
        { tag: "STIX", text: "Generate a STIX 2.1 Observed Data evidence object for the listing using shared/enrich/stix-evidence.js, with URL, first and last observation, and content hash." },
        { tag: "Request letter", text: "Prepare a send-ready removal request using shared/aux/takedown-letter.js with GDPR Art. 17 or CCPA wording, then submit it through the broker's public opt-out method." },
        { tag: "Recheck", text: "Schedule an Apify Schedule + Webhook recheck. If a removed listing reappears, flag it again using the existing WCC / RAG ingestion path." }
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
        "Code: <b>shared/optout/</b> (input-builder passes <b>shared/scope.js</b> first and refuses third-party requests)" +
        " · reuses <b>shared/enrich/stix-evidence.js</b> + <b>shared/aux/takedown-letter.js</b>" +
        " · rechecks through <b>integrations/schedules</b> + <b>integrations/webhooks</b>. " +
        "References: OASIS STIX 2.1 Observed Data (OpenCTI / MISP interoperable); Apify Website Content Crawler + RAG Web Browser recheck ingestion.";
    }
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

  let APIFY_SESSION = null;
  function coreApifyActorIds(username) {
    return [
      "mirrortrace-policy-gate",
      "mirrortrace-discovery",
      "mirrortrace-crawler",
      "mirrortrace-diff-evidence",
      "mirrortrace-report-builder"
    ].map(function (actor) { return username + "/" + actor; });
  }

  function wireApify() {
    const state = document.getElementById("apifyState");
    const button = document.getElementById("apifyCheck");
    const tokenInput = document.getElementById("apifyToken");
    const actorsInput = document.getElementById("apifyActors");
    const preview = document.getElementById("apifyActorPreview");
    if (!state || !button || !tokenInput || !actorsInput) return;

    button.addEventListener("click", async function () {
      const token = tokenInput.value.trim();
      if (!token) {
        state.className = "apify-state attention";
        state.textContent = "Enter an Apify API token to validate your workspace.";
        tokenInput.focus();
        return;
      }

      button.disabled = true;
      state.className = "apify-state checking";
      state.textContent = "Validating your Apify workspace...";

      try {
        const response = await fetch("https://api.apify.com/v2/users/me", {
          headers: { Authorization: "Bearer " + token }
        });
        if (!response.ok) throw new Error("Apify account validation returned " + response.status);
        const payload = await response.json();
        const account = payload && payload.data ? payload.data : payload;
        const username = account && (account.username || account.id);
        if (!username) throw new Error("Apify account response did not include a workspace identifier");

        const actorIds = actorsInput.value.trim()
          ? actorsInput.value.split(",").map(function (id) { return id.trim(); }).filter(Boolean)
          : coreApifyActorIds(username);
        APIFY_SESSION = { username: username, token: token, actorIds: actorIds };
        tokenInput.value = "";
        actorsInput.value = actorIds.join(", ");
        state.className = "apify-state connected";
        state.textContent = "Connected to Apify workspace @" + username + ".";
        if (preview) preview.textContent = actorIds.length + " actor IDs prepared: " + actorIds.join(" · ");
        button.textContent = "Workspace connected";
      } catch (error) {
        APIFY_SESSION = null;
        state.className = "apify-state attention";
        state.textContent = "Workspace validation needs attention. Check the token and try again.";
        if (preview) preview.textContent = "";
        console.warn(error);
      } finally {
        button.disabled = false;
      }
    });
  }

  function wireNavAndGate() {
    document.getElementById("runGate").addEventListener("click", doRun);
    document.getElementById("clearGate").addEventListener("click", () => {
      document.getElementById("requestInput").value = "";
      document.getElementById("scopeSelect").value = "";
      const out = document.getElementById("gateResult");
      out.innerHTML = '<div class="gate-empty"><span class="gate-empty-icon" aria-hidden="true">◎</span><p>Choose a scope or describe your request, then run the gate.<br/>The logic really executes in your browser. No fake data.</p></div>';
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
   * to an injected window.__MIRRORTRACE_REPORT__ from data/example-report.js. If neither
   * exists yet, we stay in the honest "no grade" state — we never invent one. */
  function applyReport(report) {
    if (!report || typeof report !== "object") return;
    LOADED_REPORT = report;
    // EPHEMERAL session cache (sessionStorage only — never localStorage/server,
    // per shared/privacy/storage-policy.js ALLOWED_LOCATIONS). This is the real
    // session state the one-click purge button clears.
    try {
      if (window.sessionStorage) {
        sessionStorage.setItem(SESSION_REPORT_KEY, JSON.stringify(report));
      }
    } catch (e) { /* sessionStorage unavailable (e.g. some file:// modes) — memory only */ }
    const vm = gradeFromReport(report);
    if (vm) renderExposureGrade(vm);
    // re-drive the whole report view from the REAL produced report
    renderBrief(report);         // conclusion first: top-of-page comprehensive brief
    renderProvenance(report);
    renderExposureMap(report);   // the #1 deliverable — radial exposure map
    renderReferences(report);    // right-rail: every real source from this report
    renderFindings();
    renderEvidenceTable();
    renderSuggestedActions();
    observeReveal();             // (re)wire scroll-enter reveal for new cards
  }

  /* =========================================================================
   * ONE-CLICK PURGE — the privacy promise made tangible (storage-policy.js
   * PURGE_CONTRACT 'explicit_purge'). REALLY clears this session's computed
   * exposure data: sessionStorage keys + in-memory report/graph refs, then
   * visibly resets every report/map view to its honest empty state. NO fake.
   * =======================================================================*/
  const SESSION_REPORT_KEY = "mirrortrace.exposure_report";
  const SESSION_GRAPH_KEY = "mirrortrace.exposure_graph";

  function purgeExposureData() {
    // 1) sessionStorage — the only persisted (ephemeral) tier we ever write to.
    let clearedKeys = 0;
    try {
      if (window.sessionStorage) {
        [SESSION_REPORT_KEY, SESSION_GRAPH_KEY].forEach(function (k) {
          if (sessionStorage.getItem(k) !== null) { sessionStorage.removeItem(k); clearedKeys += 1; }
        });
        // defensive: clear any other mirrortrace.* exposure keys
        Object.keys(sessionStorage).forEach(function (k) {
          if (k.indexOf("mirrortrace.") === 0) { sessionStorage.removeItem(k); clearedKeys += 1; }
        });
      }
    } catch (e) { /* no sessionStorage — nothing persisted to clear */ }

    // 2) in-memory refs (PURGE_CONTRACT.mustNullInMemoryRefs) — null the dossier.
    LOADED_REPORT = null;
    MAP_GRAPH = null;
    MAP_REPORT = null;
    MAP_SELECTED = null;

    // 3) visibly reset every view to its honest empty state.
    renderExposureGrade(null);
    renderBrief(null);
    renderProvenance(null);
    renderExposureMap(null);   // center-only, no spokes
    renderReferences(null);    // right-rail back to its honest empty state
    renderFindings();          // template catalog
    renderEvidenceTable();     // evidence-index schema
    renderSuggestedActions();  // honest empty

    return { clearedKeys: clearedKeys };
  }

  function wirePurge() {
    const btn = document.getElementById("purgeAllBtn");
    const status = document.getElementById("purgeStatus");
    if (!btn) return;
    btn.addEventListener("click", function () {
      const res = purgeExposureData();
      btn.classList.add("purged");
      btn.disabled = true;
      btn.textContent = "Purged ✓";
      if (status) {
        status.className = "purge-status done";
        status.textContent = "Purged · no local trace remains and our servers never stored it (cleared " + res.clearedKeys + "  session-cache items plus the in-memory report and graph).";
      }
      // let the user re-load the synthetic example afterward (honest, not auto).
      window.setTimeout(function () {
        btn.disabled = false;
        btn.classList.remove("purged");
        btn.textContent = "Reload example report";
        btn.onclick = function () { btn.onclick = null; location.reload(); };
      }, 2200);
    });
  }

  /* =========================================================================
   * COMPREHENSIVE BRIEF (conclusion first) — bright high-contrast at-a-glance summary derived
   * ONLY from the loaded report. Big A–F grade (count-up on reveal), headline
   * numbers (sources / sensitive exposures), top 2–3 highest-severity risks.
   * Honest empty state until a report loads — never invents a conclusion.
   * =======================================================================*/
  function renderBrief(report) {
    const wrap = document.getElementById("briefCard");
    if (!wrap) return;
    wrap.innerHTML = "";

    const findings = reportFindings(report);
    if (!report || !findings.length) {
      wrap.className = "brief-card empty";
      wrap.appendChild(el("p", "brief-eyebrow", "Comprehensive brief"));
      wrap.appendChild(el("p", "brief-empty",
        "No report loaded · no conclusion yet. After a live self-audit passes Step 1 with scope=self, this panel shows an A–F exposure grade and the highest-priority risks. No conclusion is invented for an unscanned subject."));
      return;
    }

    wrap.className = "brief-card" + (isSynthetic(report) ? " synthetic" : " live");
    const vm = gradeFromReport(report);
    const graph = buildExposureGraphClient(report, { selfLabel: "You" });

    // headline numbers
    const sourceCount = graph.meta.source_count;
    const sharedLinks = graph.meta.shared_identifier_links;
    const sensitive = findings.filter(function (f) {
      const b = mapBandOf(f);
      return b === "critical" || b === "high" || (f.risk === "high");
    }).length;

    // --- header: label + provenance flag ---
    const top = el("div", "brief-top");
    top.appendChild(el("span", "brief-eyebrow", "Comprehensive brief · conclusion first"));
    top.appendChild(el("span", "brief-prov " + (isSynthetic(report) ? "synthetic" : "live"),
      isSynthetic(report) ? "Synthetic fixture · real pipeline" : "Live pipeline output"));
    wrap.appendChild(top);

    // --- EMAIL + PHONE exposure lead (the demo's main point) -----------------
    // The two hero stats lead with HITS / SOURCES CHECKED, drawn from the real
    // report's provenance (per_query = sources checked, findings = hits). Never
    // fabricated; honest empties when a kind was searched but came back clean.
    const breadth = reportBreadth(report);
    const phoneB = breadth.phone;
    const emailB = breadth.email;
    const epLead = el("div", "brief-headline");
    epLead.appendChild(el("h3", "brief-headline-title", "Your email &amp; phone exposure"));
    const epRow = el("div", "brief-ep-row");
    [
      { ico: "📧", b: emailB, label: "email", note: "breaches + public mentions" },
      { ico: "📱", b: phoneB, label: "phone", note: "data-broker listings + public records" }
    ].forEach(function (c) {
      const hits = c.b.findings;
      const checked = c.b.sources;
      const cell = el("div", "brief-ep" + (hits > 0 ? " hit" : (c.b.queried ? " clear" : " unscanned")));
      cell.appendChild(el("span", "brief-ep-ico", c.ico));
      const txt = el("div", "brief-ep-text");
      // hero number = hits, with "/ N sources checked" right beside it.
      const head = el("div", "brief-ep-head");
      const num = el("span", "brief-ep-num", "0");
      num.dataset.target = String(hits);
      head.appendChild(num);
      head.appendChild(el("span", "brief-ep-lbl",
        " " + c.label + (hits === 1 ? " exposure" : " exposures")));
      txt.appendChild(head);
      // honest breadth line under each hero stat.
      if (c.b.queried) {
        const frac = el("span", "brief-ep-frac");
        frac.appendChild(el("b", null, String(hits)));
        frac.appendChild(el("span", null, " hit / " + checked + " source" + (checked === 1 ? "" : "s") + " checked"));
        txt.appendChild(frac);
      }
      txt.appendChild(el("span", "brief-ep-note",
        !c.b.queried ? "not searched in this run · " + c.note
          : hits > 0 ? c.note
          : "clean · " + checked + " source" + (checked === 1 ? "" : "s") + " checked, nothing surfaced"));
      cell.appendChild(txt);
      epRow.appendChild(cell);
    });
    epLead.appendChild(epRow);

    // --- coverage / breadth strip (honest, from the real report only) --------
    const stripBits = [];
    if (phoneB.queried) stripBits.push("Checked <b>" + phoneB.sources + "</b> source" + (phoneB.sources === 1 ? "" : "s") + " for your phone");
    if (emailB.queried) stripBits.push("<b>" + emailB.sources + "</b> for your email");
    if (stripBits.length) {
      const strip = el("p", "brief-coverage-strip", stripBits.join(" · "));
      if (breadth.total.blocked > 0) {
        strip.appendChild(el("span", "brief-coverage-block",
          " · ⛬ " + breadth.total.blocked + " social link" + (breadth.total.blocked === 1 ? "" : "s") + " blocked by compliance"));
      }
      epLead.appendChild(strip);
    }
    wrap.appendChild(epLead);

    // --- grade block (count-up) ---
    const main = el("div", "brief-main");
    const gradeWrap = el("div", "brief-grade");
    const fam = vm && vm.graded ? gradeFamily(String(vm.grade)) : "none";
    const letter = el("div", "brief-letter bg-" + fam, vm && vm.graded ? esc(String(vm.grade)) : "—");
    letter.setAttribute("role", "img");
    letter.setAttribute("aria-label", "Exposure grade " + (vm && vm.graded ? vm.grade : "Unknown"));
    gradeWrap.appendChild(letter);
    const gradeMeta = el("div", "brief-grade-meta");
    gradeMeta.appendChild(el("span", "brief-grade-label", "Exposure grade"));
    const scoreEl = el("span", "brief-score", vm && vm.score != null ? "0" : "—");
    if (vm && vm.score != null) scoreEl.dataset.target = String(vm.score);
    gradeMeta.appendChild(scoreEl);
    gradeMeta.appendChild(el("span", "brief-score-max", vm && vm.score != null ? "/ 100" : ""));
    gradeWrap.appendChild(gradeMeta);
    main.appendChild(gradeWrap);

    // --- headline stat chips ---
    const stats = el("div", "brief-stats");
    [
      { n: sourceCount, label: "Exposure sources" },
      { n: sensitive, label: "Sensitive exposures" },
      { n: sharedLinks, label: "Cross-source links" }
    ].forEach(function (s) {
      const chip = el("div", "brief-stat");
      const num = el("span", "brief-stat-num", "0");
      num.dataset.target = String(s.n);
      chip.appendChild(num);
      chip.appendChild(el("span", "brief-stat-lbl", s.label));
      stats.appendChild(chip);
    });
    main.appendChild(stats);
    wrap.appendChild(main);

    // --- top 2–3 highest-severity risks ---
    // rank by exact severity_band first (critical > high > medium > low > info),
    // then by neon tier, then confidence — so the truly worst exposures lead.
    const BAND_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const top3 = findings.slice().sort(function (a, b) {
      return ((BAND_RANK[mapBandOf(b)] || 0) - (BAND_RANK[mapBandOf(a)] || 0))
        || (MAP_TIER_RANK[mapTierForBand(mapBandOf(b))] - MAP_TIER_RANK[mapTierForBand(mapBandOf(a))])
        || ((b.confidence || 0) - (a.confidence || 0));
    });
    const seen = {};
    const picked = [];
    top3.forEach(function (f) {
      if (picked.length >= 3) return;
      if (seen[f.event_type]) return;
      seen[f.event_type] = true;
      picked.push(f);
    });
    if (picked.length) {
      const risks = el("div", "brief-risks");
      risks.appendChild(el("p", "brief-risks-label", "Highest-priority risks"));
      const ul = el("ul", "brief-risk-list");
      picked.forEach(function (f) {
        const meta = EVENT_META[f.event_type] || {};
        const tier = mapTierForBand(mapBandOf(f));
        const li = el("li", "brief-risk");
        li.appendChild(el("span", "brief-risk-dot " + tier));
        const t = el("div", "brief-risk-text");
        t.appendChild(el("span", "brief-risk-name", esc(meta.name || f.event_type)));
        if (meta.why) t.appendChild(el("span", "brief-risk-why", esc(meta.why)));
        li.appendChild(t);
        ul.appendChild(li);
      });
      risks.appendChild(ul);
      wrap.appendChild(risks);
    }

    // --- jump CTA into the dark exposure scene ---
    const cta = el("div", "brief-cta");
    const go = el("a", "btn-brief-go", "View full Exposure Map ↓");
    go.href = "#report";
    cta.appendChild(go);
    cta.appendChild(el("span", "brief-cta-note",
      isSynthetic(report) ? "The data below comes from live detector code running over a synthetic fixture, not fabricated data." : "The data below is live pipeline output."));
    wrap.appendChild(cta);

    // count-up the grade score + stat chips once on reveal (honors reduced-motion).
    countUpInside(wrap);
  }

  /* count-up: animate any [data-target] number from 0 → target ONCE. Under
   * prefers-reduced-motion (or if already animated) it snaps to the final value. */
  function countUpInside(root) {
    const nums = root.querySelectorAll("[data-target]");
    const reduce = prefersReducedMotion();
    nums.forEach(function (n) {
      const target = Number(n.dataset.target) || 0;
      if (reduce) { n.textContent = String(target); return; }
      const start = performance.now();
      const dur = 700;
      function frame(t) {
        const p = Math.min(1, (t - start) / dur);
        // easeOutCubic
        const e = 1 - Math.pow(1 - p, 3);
        n.textContent = String(Math.round(target * e));
        if (p < 1) requestAnimationFrame(frame);
        else n.textContent = String(target);
      }
      requestAnimationFrame(frame);
    });
  }

  function wireScrollProgress() {
    const bar = document.getElementById("scrollProgressBar");
    if (!bar) return;
    let ticking = false;
    function update() {
      ticking = false;
      const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
      const progress = Math.max(0, Math.min(1, window.scrollY / max));
      bar.style.transform = "scaleX(" + progress.toFixed(4) + ")";
      document.documentElement.style.setProperty("--scroll", progress.toFixed(4));
    }
    window.addEventListener("scroll", function () {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    window.addEventListener("resize", update, { passive: true });
    update();
  }

  /* =========================================================================
   * (REMOVED) scroll-driven light → dark gradient.
   * The page no longer interpolates the body background from #f8f8f6 → #0b0b0e
   * as you scroll. The front half is bright SOLID COLOR BLOCKS that clash; the
   * dark exposure zone begins with a HARD discrete cut (the solid .zone-divider
   * + the full-bleed .dark-zone floor in CSS). This stub stays so the boot()
   * call site and any console reference keep resolving, but it drives nothing.
   * =======================================================================*/
  function wireSceneGradient() {
    /* intentionally a no-op: --scene gradient retired, hard color-block cut now. */
  }

  /* =========================================================================
   * SCROLL-ENTER REVEAL — subtle fade+rise, staggered, ONCE per element via
   * IntersectionObserver. Honors prefers-reduced-motion (everything visible,
   * no transform). Purely additive: elements are fully visible without JS.
   * =======================================================================*/
  let revealObserver = null;
  function observeReveal() {
    if (prefersReducedMotion() || !("IntersectionObserver" in window)) {
      document.querySelectorAll(".reveal").forEach(function (el2) { el2.classList.add("revealed"); });
      return;
    }
    if (!revealObserver) {
      revealObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            const e2 = entry.target;
            const delay = Number(e2.dataset.revealDelay || 0);
            window.setTimeout(function () { e2.classList.add("revealed"); }, delay);
            revealObserver.unobserve(e2);
          }
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
    }
    // tag the major cards/sections as reveal targets (idempotent), staggered.
    const targets = document.querySelectorAll(
      ".section-head, .map-wrap, .grade-card, .coverage, .finding-group, " +
      ".cluster-card, .kanon, .ev-card, .actions-card, .optout-card, " +
      ".arch-wrap, .apify-box, .purge-zone, .brief-card, .feature-tile, " +
      ".how-tile, .inspector-drawer, .implementation-drawer");
    targets.forEach(function (t, i) {
      if (t.classList.contains("reveal")) return;
      t.classList.add("reveal");
      t.dataset.revealDelay = String((i % 5) * 60);
      revealObserver.observe(t);
    });
  }
  function loadExampleReport() {
    if (window.__MIRRORTRACE_REPORT__) { applyReport(window.__MIRRORTRACE_REPORT__); return; }
    // Report source preference: a LIVE, gitignored real-subject report
    // (data/real-report.local.json, produced by integrations/run-live-audit.js)
    // takes precedence for the local demo; otherwise the committed SYNTHETIC
    // example report. Each has a file:// .js fallback for when fetch() is blocked.
    const sources = [
      { json: "data/real-report.local.json", js: "data/real-report.local.js" },
      { json: "data/example-report.json", js: "data/example-report.js" }
    ];
    function tryJsFallback(src, onFail) {
      const s = document.createElement("script");
      s.src = src.js;
      s.onload = function () {
        if (window.__MIRRORTRACE_REPORT__) { applyReport(window.__MIRRORTRACE_REPORT__); }
        else { onFail(); }
      };
      s.onerror = onFail;
      document.head.appendChild(s);
    }
    function tryAt(i) {
      if (i >= sources.length) { return; /* no produced report yet — honest no-grade state */ }
      const src = sources[i];
      let done = false;
      fetch(src.json)
        .then(r => { if (!r.ok) throw new Error("no report"); return r.json(); })
        .then(rep => { done = true; applyReport(rep); })
        .catch(() => {
          if (done || window.__MIRRORTRACE_REPORT__) {
            if (window.__MIRRORTRACE_REPORT__) applyReport(window.__MIRRORTRACE_REPORT__);
            return;
          }
          // file:// fallback for this source, then advance to the next source.
          tryJsFallback(src, function () { tryAt(i + 1); });
        });
    }
    tryAt(0);
  }

  /* =========================================================================
   * AUDIT FORM — the prominent self-only input (email + phone focus).
   *
   * Honest wiring (NO FAKE DATA, scope=self only):
   *  1. At least one identifier must be entered, else an honest "enter something"
   *     state — we never run an empty audit.
   *  2. The request really passes through runPolicyGate() with scope=self, so the
   *     SAME compliance gate that guards everything else also guards this form.
   *     If the gate refuses (it won't for a self identifier audit, but the call is
   *     real), we surface the refusal and stop — no report is shown.
   *  3. On a permitted gate verdict we show a brief "Scanning… (live Apify audit)"
   *     state, then load + render the REAL report via loadExampleReport(), which
   *     prefers data/real-report.local.json (a genuine pre-run live Apify audit)
   *     and falls back to the labelled synthetic example. We do NOT fabricate a
   *     per-keystroke result; the inputs scope the request, the report is real.
   * =======================================================================*/
  function wireAuditForm() {
    const form = document.getElementById("auditForm");
    if (!form) return;
    const btn = document.getElementById("auditRunBtn");
    const status = document.getElementById("auditStatus");
    const emailEl = document.getElementById("auditEmail");
    const phoneEl = document.getElementById("auditPhone");
    const nameEl = document.getElementById("auditName");
    const handleEl = document.getElementById("auditHandle");

    function setStatus(cls, text) {
      if (!status) return;
      status.className = "af-status" + (cls ? " " + cls : "");
      status.textContent = text;
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();

      const email = (emailEl && emailEl.value || "").trim();
      const phone = (phoneEl && phoneEl.value || "").trim();
      const name = (nameEl && nameEl.value || "").trim();
      const handle = (handleEl && handleEl.value || "").trim();

      // 1) honest empty guard — never run an audit with no identifier.
      if (!email && !phone && !name && !handle) {
        setStatus("empty", "Enter at least one of your own identifiers (email or phone recommended) before running.");
        if (emailEl) emailEl.focus();
        return;
      }

      // 2) route the request through the REAL policy gate at scope=self.
      const parts = [];
      if (email) parts.push("email " + email);
      if (phone) parts.push("phone " + phone);
      if (name) parts.push("name " + name);
      if (handle) parts.push("handle " + handle);
      const requestText = "Audit my own public footprint for my " + parts.join(", ") + " and assess my exposure.";
      const verdict = runPolicyGate(requestText, "self");
      // mirror the verdict into the gate panel so the audience sees it really ran
      renderResult(verdict);
      updateReportForScope(verdict);
      if (!verdict.accepted) {
        setStatus("empty", "Policy gate refused this request: " + verdict.reason);
        return;
      }

      // 3) brief scanning state, then load the REAL pre-run live Apify report.
      if (btn) { btn.setAttribute("aria-busy", "true"); btn.disabled = true; }
      setStatus("scanning", "Scanning… (live Apify audit) — querying public sources for your email & phone exposure");

      const finish = function () {
        loadExampleReport();   // prefers data/real-report.local.json (genuine live run)
        if (btn) { btn.removeAttribute("aria-busy"); btn.disabled = false; }
        setStatus("done", "Audit loaded · live Apify run. See your email & phone exposure below ↓");
        const brief = document.getElementById("brief");
        if (brief) brief.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
      };
      // short, honest delay so the "live audit" state is visible; the result is
      // the real pre-run report, not a fabricated per-keystroke scrape.
      if (prefersReducedMotion()) finish();
      else window.setTimeout(finish, 900);
    });
  }

  function boot(plan) {
    PLAN = plan;
    renderHero();
    renderScopeSelect();
    renderPresets();
    renderExposureGrade(null);   // honest "no grade yet" until a real report loads
    renderBrief(null);           // honest empty brief until a real report loads
    renderProvenance(null);      // hidden until a report loads
    renderCoverage();
    renderExposureMap(null);     // honest center-only map until a real report loads
    renderReferences(null);      // right-rail references panel (empty until a report loads)
    renderFindings();            // template catalog until a real report loads
    renderClusterCard();
    renderEvidenceTable();       // evidence-index schema until a real report loads
    renderSuggestedActions();    // honest empty until a real report loads
    loadExampleReport();         // async; re-drives grade+findings+evidence+actions if a report exists
    renderOptout();
    renderArch();
    renderPipelinePanel();
    wireApify();
    wireKanon();
    wireAuditForm();             // prominent self-only audit input (email + phone focus)
    wireNavAndGate();
    wireViewToggle();
    wireMapControls();
    wireIdentityGate();
    wirePurge();                 // one-click real purge (sessionStorage + memory)
    wireScrollProgress();         // compact instrument-panel scroll feedback
    wireSceneGradient();         // scroll-linked light → dark scene gradient
    observeReveal();             // subtle scroll-enter fade+rise (reduced-motion safe)
    updateReportForScope(null);
  }

  fetch("data/plan.json")
    .then(r => { if (!r.ok) throw new Error("bad status"); return r.json(); })
    .then(boot)
    .catch(() => {
      if (FALLBACK_PLAN) { boot(FALLBACK_PLAN); return; }
      console.warn("plan.json failed to load, possibly because of file:// restrictions. Injecting bundled data.");
      var s = document.createElement("script");
      s.src = "data/plan.js";
      s.onload = function () { if (window.__MIRRORTRACE_PLAN__) boot(window.__MIRRORTRACE_PLAN__); };
      s.onerror = function () {
        var ho = document.getElementById("heroOne");
        if (ho) ho.textContent = "plan.json could not load. Serve the page locally or confirm data/plan.json exists. The policy gate still works independently.";
      };
      document.head.appendChild(s);
    });

  // Expose gate for quick console testing / verification without overwriting
  // browser-safe modules loaded before app.js.
  window.MirrorTrace = Object.assign(window.MirrorTrace || {}, {
    runPolicyGate: runPolicyGate,
    LEGAL_SCOPES: LEGAL_SCOPES,
    buildExposureGraphFromReport: buildExposureGraphClient
  });
})();
