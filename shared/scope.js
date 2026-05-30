/**
 * shared/scope.js
 *
 * Canonical compliance boundary for MirrorTrace (Self Footprint Audit Pro).
 *
 * This module is the SINGLE SOURCE OF TRUTH for what this product is allowed to
 * do. Every actor imports `validateScope` and the constants below. The product
 * audits a user's OWN public footprint, preserves public evidence involving
 * themselves, and monitors consented / public-figure / brand sources.
 *
 * It MUST NOT, under any circumstance, enable tracking of private individuals,
 * romantic / dating inference, or scraping behind login walls. Those are not
 * "features we left out" — they are red lines this code actively rejects.
 */

'use strict';

/**
 * The only scope_type values this product will ever process.
 *  - self            : auditing your own public digital footprint
 *  - consented       : monitoring someone who gave written authorization
 *  - public_figure   : a genuine public figure (officials, celebrities) acting publicly
 *  - brand           : a company / brand / product you are entitled to monitor
 *  - safety_evidence : preserving public evidence of harm directed AT the user
 *                      (harassment, threats, doxxing) for reporting/legal use
 *
 * Anything not in this list is rejected. The list is frozen so it cannot be
 * mutated at runtime by a caller trying to widen the allowed surface.
 */
const ALLOWED_SCOPES = Object.freeze([
  'self',
  'consented',
  'public_figure',
  'brand',
  'safety_evidence',
]);

/**
 * Analyses that are categorically prohibited. If an input requests any of
 * these (via `prohibited_analysis`, `analysis`, or `tasks`), the run is
 * rejected outright regardless of scope_type. These map directly to the
 * product's hard red lines.
 */
const PROHIBITED_ANALYSIS = Object.freeze([
  'romance_inference',
  'gender_from_image',
  'dating_app_presence',
  'private_person_tracking',
  'platform_evasion',
  'real_time_location',
  'high_frequency_surveillance',
  // Additional near-synonyms callers might try, all rejected:
  'affair_detection',
  'sexuality_inference',
  'intimacy_inference',
  'follower_scrape',
  'likes_scrape',
  'swipe_tracking',
]);

/**
 * Scopes that require proof of authorization before we will touch any source.
 * `consented` means a real, identifiable person agreed in writing; we demand a
 * URL pointing at that evidence (e.g. a signed consent doc the user hosts).
 */
const SCOPES_REQUIRING_AUTHORIZATION = Object.freeze(['consented']);

/**
 * Sources we will never crawl, because reaching their useful data requires
 * defeating a login wall and/or scraping private social graphs. We block on
 * hostname so a caller cannot smuggle these in as "self" or "public_figure".
 * Public, logged-out, official endpoints are intentionally NOT here.
 */
const PRIVATE_SOCIAL_HOSTS = Object.freeze([
  'instagram.com',
  'www.instagram.com',
  'facebook.com',
  'www.facebook.com',
  'm.facebook.com',
  'tinder.com',
  'www.tinder.com',
  'bumble.com',
  'www.bumble.com',
  'hinge.co',
  'www.hinge.co',
  'snapchat.com',
  'www.snapchat.com',
]);

/**
 * Suggest concrete legal alternatives whenever we reject something. Rejections
 * should redirect the user toward the compliant version of their goal, not just
 * say "no". Keyed loosely by intent.
 */
const ALTERNATIVE_TASKS = Object.freeze({
  private_person_tracking: [
    'Audit YOUR OWN public footprint (scope_type="self") to see what others can find about you.',
    'If you are being harassed by this person, use scope_type="safety_evidence" to preserve public evidence of the harassment for a report.',
  ],
  romance_inference: [
    'Run a self-audit of your own public dating-adjacent footprint (scope_type="self").',
    'Use Closure Mode in the report to reduce compulsive checking instead.',
  ],
  dating_app_presence: [
    'Audit which of YOUR own public profiles expose dating-app links (scope_type="self").',
  ],
  gender_from_image: [
    'We do not analyze any attribute from photos of people. Audit your own public images (scope_type="self") for unwanted exposure instead.',
  ],
  private_social: [
    'Monitor a public, logged-out brand or public-figure page (scope_type="brand" or "public_figure").',
    'Audit your own public profile on these platforms via scope_type="self".',
  ],
  platform_evasion: [
    'Use only public, logged-out URLs, official APIs, or your own data export.',
    'If a site blocks access, stop and request data/removal through the platform instead of bypassing controls.',
  ],
  real_time_location: [
    'We never produce a person\'s live location. Audit your own footprint for location data you expose instead.',
  ],
  high_frequency_surveillance: [
    'Use low-frequency scheduled digests for public/owned sources; do not poll people in real time.',
  ],
  default: [
    'Audit your own public footprint (scope_type="self").',
    'Monitor a brand you own (scope_type="brand") or a genuine public figure (scope_type="public_figure").',
    'Preserve public evidence of harm directed at you (scope_type="safety_evidence").',
  ],
});

/**
 * Natural-language requests can try to launder prohibited intent under a legal
 * scope_type. These patterns are deliberately conservative and only trigger on
 * strong stalking / dating / image-inference / evasion / live-location signals.
 */
const PROHIBITED_TEXT_PATTERNS = Object.freeze([
  {
    code: 'private_person_tracking',
    pattern: /(track|monitor|watch|stalk|surveil|scrape|crawl|alert me|ping me|追踪|监控|盯着|抓取).{0,90}(ex\b|crush|coworker|private individual|private person|this person|their account|私人个体|暗恋|同事|陌生人|这个人|他们的账号)/iu,
    reason: 'Request appears to track a private person rather than audit the user\'s own footprint.',
  },
  {
    code: 'romance_inference',
    pattern: /(暧昧|出轨|恋爱|romance|romantic|flirt|cheat|relationship|likes?|comments?|点赞|评论).{0,90}(infer|detect|analy[sz]e|tell me|who|跟谁|判断|分析|搞)/iu,
    reason: 'Romantic / intimacy inference is categorically prohibited.',
  },
  {
    code: 'dating_app_presence',
    pattern: /((tinder|bumble|hinge|grindr|dating app|dating profile|探探|交友软件).{0,90}(find|lookup|active|presence|is my|check|搜索|查找|找)|(find|lookup|check|is my|搜索|查找|找).{0,90}(tinder|bumble|hinge|grindr|dating app|dating profile|探探|交友软件))/iu,
    reason: 'Dating-app presence lookup is outside scope.',
  },
  {
    code: 'gender_from_image',
    pattern: /((avatar|profile photo|image|photo|头像|照片).{0,70}(gender|male|female|男|女|性别|classify|判断|识别)|(gender|male|female|男|女|性别).{0,70}(avatar|profile photo|image|photo|头像|照片))/iu,
    reason: 'Inferring gender or other attributes from images is prohibited.',
  },
  {
    code: 'platform_evasion',
    pattern: /(private account|get in|login wall|bypass|evade|captcha|ignore your rules|read their posts|绕过|规避|破解|私密账号|验证码|登录墙)/iu,
    reason: 'Bypassing privacy controls, login walls, rate limits, or rules is prohibited.',
  },
  {
    code: 'real_time_location',
    pattern: /(live location|current address|whereabouts|real[- ]?time location|现在住址|实时位置|当前位置|行踪)/iu,
    reason: 'Live location or whereabouts of a person is prohibited.',
  },
  {
    code: 'high_frequency_surveillance',
    pattern: /(every minute|instant they post|real[- ]?time alert|ping me in real time|每分钟|一发就通知|实时提醒)/iu,
    reason: 'High-frequency polling of people mimics surveillance and is prohibited.',
  },
]);

/**
 * Normalize a possibly-messy host out of a URL string.
 * Returns lowercase hostname or null if unparseable.
 */
function hostOf(urlString) {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Gather every analysis-like field a caller might use, normalized lowercase.
 */
function collectRequestedAnalysis(input) {
  const buckets = [
    input.prohibited_analysis,
    input.analysis,
    input.analyses,
    input.tasks,
  ];
  const out = [];
  for (const b of buckets) {
    if (!b) continue;
    if (Array.isArray(b)) {
      for (const v of b) if (typeof v === 'string') out.push(v.trim().toLowerCase());
    } else if (typeof b === 'string') {
      out.push(b.trim().toLowerCase());
    }
  }
  return out;
}

/**
 * Gather free-text fields that might encode prohibited intent even when
 * scope_type and target_urls look legal.
 */
function collectIntentText(input) {
  const fields = [
    input.freeText,
    input.prompt,
    input.query,
    input.goal,
    input.objective,
    input.target,
    input.subject_label,
    input.description,
  ];
  return fields
    .filter((v) => typeof v === 'string')
    .map((v) => v.trim())
    .join(' \n ');
}

/**
 * validateScope(input) -> decision object
 *
 * The canonical gate. Pure function (no I/O) so it can be unit-tested and reused
 * by any actor. Returns a structured decision:
 *
 *   {
 *     allowed: boolean,
 *     scope_type: string|null,
 *     reasons: string[],            // why it failed (empty if allowed)
 *     violated_red_lines: string[], // machine-readable codes
 *     alternatives: string[],       // legal tasks to do instead
 *     normalized: { scope_type, target_urls, subject_label } // present if allowed
 *   }
 */
function validateScope(input) {
  const reasons = [];
  const violated = new Set();
  let alternativeKey = 'default';

  if (!input || typeof input !== 'object') {
    return reject(['Input is missing or not an object.'], ['malformed_input'], 'default');
  }

  const scopeType = typeof input.scope_type === 'string' ? input.scope_type.trim() : '';

  // 1) scope_type must be in the allow-list. Prohibited scopes never reach here
  //    through the UI (they are absent from input_schema enums), but the API /
  //    metamorph path could still inject them, so we enforce in code too.
  if (!scopeType) {
    reasons.push('scope_type is required.');
    violated.add('missing_scope_type');
  } else if (!ALLOWED_SCOPES.includes(scopeType)) {
    reasons.push(
      `scope_type "${scopeType}" is not permitted. Allowed: ${ALLOWED_SCOPES.join(', ')}.`,
    );
    violated.add('disallowed_scope_type');
    // If it smells like private-person tracking, route alternatives accordingly.
    if (/ex|partner|crush|coworker|stranger|person|someone/i.test(scopeType)) {
      alternativeKey = 'private_person_tracking';
    }
  }

  // 2) Prohibited analyses are rejected no matter what scope_type says.
  const requested = collectRequestedAnalysis(input);
  for (const a of requested) {
    if (PROHIBITED_ANALYSIS.includes(a)) {
      reasons.push(`Analysis "${a}" is categorically prohibited by this product.`);
      violated.add(`prohibited_analysis:${a}`);
      if (ALTERNATIVE_TASKS[a]) alternativeKey = a;
    }
  }

  // 2b) Natural-language intent scan. This closes the laundering path where a
  // caller supplies scope_type="self" or "brand" plus a plausible URL, but the
  // prompt asks for stalking / dating-app / image-attribute inference.
  const intentText = collectIntentText(input);
  if (intentText) {
    for (const rule of PROHIBITED_TEXT_PATTERNS) {
      if (rule.pattern.test(intentText)) {
        reasons.push(rule.reason);
        violated.add(`prohibited_intent:${rule.code}`);
        if (ALTERNATIVE_TASKS[rule.code]) alternativeKey = rule.code;
      }
    }
  }

  // 3) consented scope MUST carry authorization_evidence_url.
  if (SCOPES_REQUIRING_AUTHORIZATION.includes(scopeType)) {
    const auth = typeof input.authorization_evidence_url === 'string'
      ? input.authorization_evidence_url.trim()
      : '';
    if (!auth || !hostOf(auth)) {
      reasons.push(
        'scope_type="consented" requires a valid authorization_evidence_url '
        + '(a URL to written consent from the subject).',
      );
      violated.add('missing_authorization_evidence');
    }
  }

  // 4) Collect & sanity-check target URLs.
  const rawTargets = []
    .concat(input.target_urls || [])
    .concat(input.start_urls || [])
    .concat(input.targets || [])
    .filter((u) => typeof u === 'string' && u.trim().length > 0)
    .map((u) => u.trim());

  if (scopeType && ALLOWED_SCOPES.includes(scopeType) && rawTargets.length === 0) {
    reasons.push('At least one target_url is required.');
    violated.add('no_targets');
  }

  // 5) Block private-social / login-walled hosts outright.
  for (const t of rawTargets) {
    const h = hostOf(t);
    if (!h) {
      reasons.push(`target_url "${t}" is not a valid URL.`);
      violated.add('invalid_target_url');
      continue;
    }
    if (PRIVATE_SOCIAL_HOSTS.includes(h)) {
      reasons.push(
        `Host "${h}" is blocked: its useful data sits behind a login wall / private social graph. `
        + 'We do not bypass login walls or scrape private followers/likes/swipes.',
      );
      violated.add(`private_social_host:${h}`);
      alternativeKey = 'private_social';
    }
  }

  if (reasons.length > 0) {
    return reject([...reasons], [...violated], alternativeKey);
  }

  // Passed every check — return a normalized, minimal payload for downstream actors.
  return {
    allowed: true,
    scope_type: scopeType,
    reasons: [],
    violated_red_lines: [],
    alternatives: [],
    normalized: {
      scope_type: scopeType,
      target_urls: rawTargets,
      subject_label: typeof input.subject_label === 'string' ? input.subject_label.trim() : '',
      authorization_evidence_url:
        typeof input.authorization_evidence_url === 'string'
          ? input.authorization_evidence_url.trim()
          : null,
    },
  };
}

function reject(reasons, violated, alternativeKey) {
  return {
    allowed: false,
    scope_type: null,
    reasons,
    violated_red_lines: violated,
    alternatives: ALTERNATIVE_TASKS[alternativeKey] || ALTERNATIVE_TASKS.default,
    normalized: null,
  };
}

module.exports = {
  ALLOWED_SCOPES,
  PROHIBITED_ANALYSIS,
  SCOPES_REQUIRING_AUTHORIZATION,
  PRIVATE_SOCIAL_HOSTS,
  ALTERNATIVE_TASKS,
  PROHIBITED_TEXT_PATTERNS,
  validateScope,
  hostOf,
};
