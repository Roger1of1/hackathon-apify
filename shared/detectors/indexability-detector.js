/**
 * shared/detectors/indexability-detector.js
 *
 * DISCOVERABILITY / INDEXABILITY detector MODULE.
 *
 * Every other detector answers "WHAT is exposed?" (an email, a tracker, a
 * breached credential). This module answers the orthogonal, equally-decisive
 * question for a self-audit: "HOW FINDABLE is that exposure to a stranger who
 * does not already have the URL?" A self-published email on a page that search
 * engines have been told NOT to index, and that no archive has captured, is a
 * very different exposure from the same email on a fully search-indexable,
 * Wayback-archived page. The user's remediation choice (rewrite the page vs.
 * file a search-engine removal vs. do nothing) hinges entirely on this.
 *
 * It does NOT invent visibility. It reads ONLY indexing-control DIRECTIVES that
 * were ACTUALLY OBSERVED on the captured page by the crawler — the same signals
 * a search engine itself obeys — and reports the discoverability they imply,
 * with the directive it relied on so the finding is explainable.
 *
 * ──── The two reference architectures applied ────────────────────────────────
 *
 *   (1) The Robots Exclusion / indexing-control standard as obeyed by Google
 *       Search ("Block Search indexing with noindex", "Robots meta tag,
 *       data-nosnippet and X-Robots-Tag specifications", and the "Remove a page
 *       hosted on your site" / "Refresh Outdated Content" tools backing Google's
 *       consumer "Results about you" deindexing flow). These define the EXACT
 *       precedence we model: an `X-Robots-Tag: noindex` HTTP header or a
 *       `<meta name="robots" content="noindex">` tag removes a page from the
 *       index; `<link rel="canonical">` pointing elsewhere demotes the duplicate;
 *       a `robots.txt Disallow` only blocks CRAWLING (a disallowed URL can STILL
 *       be indexed from inbound links — Google documents this caveat explicitly),
 *       so we treat Disallow as a WEAKER signal than noindex, not a stronger one.
 *       Refs: developers.google.com/search/docs/crawling-indexing/block-indexing
 *             developers.google.com/search/docs/crawling-indexing/robots-meta-tag
 *             support.google.com/websearch — "Results about you" removal requests
 *
 *   (2) The Markup's BLACKLIGHT framing — "report what is TRIVIALLY observable
 *       to a third party" — extended from trackers to discoverability. Blacklight
 *       inspects a page as loaded and states plainly what an outside party can
 *       see; we inspect the page's indexing posture and state plainly how
 *       discoverable the exposure on it is. We REUSE the project's frozen
 *       VISIBILITY vocabulary (private < linked < indexed) rather than inventing a
 *       parallel scale, and emit a typed module_event with provenance + an honest
 *       confidence, exactly like every sibling detector.
 *       Ref: https://themarkup.org/blacklight
 *
 * ──── RED LINES (by construction) ───────────────────────────────────────────
 *   - Operates ONLY on already-captured directives from a public, gate-approved
 *     page the SELF (or public_figure) subject controls. It performs NO network
 *     call, fetches no robots.txt, queries no search engine — the crawler already
 *     supplied the observed directives. Absence of a signal yields NO event
 *     (precision-first; never a fabricated "this is indexed" claim).
 *   - It reports DISCOVERABILITY of the subject's OWN page. It makes no inference
 *     about any person and has no slot for romance/gender/sexuality/live-location.
 *
 * Pure function, no I/O, no state. Safe to require at module load.
 */

'use strict';

const {
  EVENT_TYPES, VISIBILITY, VISIBILITY_RANK, RISK, makeEvent,
} = require('./event-types.js');

const MODULE = 'indexability_detector';

/**
 * The directive tokens we recognise inside a robots-style content value (meta
 * robots / X-Robots-Tag share the same token vocabulary per Google's spec).
 * We only act on the indexing-relevant ones; we list the rest so an unknown
 * token never silently changes behaviour.
 */
const NOINDEX_TOKENS = Object.freeze(['noindex', 'none']); // `none` == noindex,nofollow
const NOARCHIVE_TOKENS = Object.freeze(['noarchive', 'nosnippet']);

/**
 * Normalize a robots-style directive string into a lowercased token set.
 * Accepts e.g. "noindex, nofollow" or "max-snippet:-1, noarchive".
 */
function tokenize(directive) {
  if (typeof directive !== 'string') return new Set();
  return new Set(
    directive
      .toLowerCase()
      .split(',')
      .map((t) => t.trim().split(':')[0].trim())
      .filter(Boolean),
  );
}

function hasAny(tokenSet, list) {
  for (const t of list) if (tokenSet.has(t)) return true;
  return false;
}

/**
 * Decide the discoverability posture of ONE captured page from its observed
 * indexing directives, applying Google's documented precedence:
 *
 *   noindex (meta or X-Robots-Tag)  -> NOT in search index  => visibility "linked"
 *                                       (reachable if you have/follow the URL only)
 *   canonical -> a different URL     -> this URL demoted/deduped => "linked"
 *   robots.txt Disallow ONLY         -> crawl-blocked but CAN still be indexed from
 *                                       inbound links (Google's documented caveat)
 *                                       => stays "indexed" but flagged ambiguous
 *   archived (Wayback/cache present) -> durably discoverable  => "indexed", harder
 *                                       to remove (removing the live page does not
 *                                       remove the archived copy)
 *   nothing blocking + indexable     -> "indexed" (trivially discoverable)
 *
 * @param {object} page  captured page artifact (see detectIndexability)
 * @returns {{ visibility:string, reason:string, removable:boolean, durable:boolean, signals:string[] }}
 */
function classifyPage(page = {}) {
  const url = typeof page.url === 'string' ? page.url : null;
  const signals = [];

  // Collect robots directives from BOTH carriers (meta tag + HTTP header). Per
  // Google, either one carrying `noindex` is sufficient to deindex.
  const metaTokens = tokenize(page.meta_robots);
  const headerTokens = tokenize(page.x_robots_tag);
  const robotsTokens = new Set([...metaTokens, ...headerTokens]);

  const noindex = hasAny(robotsTokens, NOINDEX_TOKENS);
  const noarchive = hasAny(robotsTokens, NOARCHIVE_TOKENS);

  // Canonical pointing to a DIFFERENT url demotes this duplicate.
  let canonicalElsewhere = false;
  if (typeof page.canonical_url === 'string' && url) {
    try {
      canonicalElsewhere = new URL(page.canonical_url).href !== new URL(url).href;
    } catch { canonicalElsewhere = page.canonical_url !== url; }
  }

  // robots.txt Disallow only blocks crawling — NOT indexing (documented caveat).
  const robotsTxtDisallow = page.robots_txt_disallow === true;

  // Durable copies the subject cannot unilaterally remove by editing the page.
  const archived = page.archived === true && !noarchive;

  if (noindex) {
    signals.push(metaTokens.has('noindex') || metaTokens.has('none') ? 'meta:noindex' : 'x-robots:noindex');
    return {
      visibility: VISIBILITY.LINKED,
      reason: 'noindex directive present — excluded from the search index; reachable only via a known/followed URL.',
      removable: true,
      durable: archived, // an archived copy survives even a deindexed live page
      signals: archived ? [...signals, 'archived'] : signals,
    };
  }

  if (canonicalElsewhere) {
    signals.push('canonical:elsewhere');
    return {
      visibility: VISIBILITY.LINKED,
      reason: 'canonical points to a different URL — this duplicate is demoted/deduplicated by search engines.',
      removable: true,
      durable: archived,
      signals: archived ? [...signals, 'archived'] : signals,
    };
  }

  // From here the page is indexable. Distinguish the durable/archived case and
  // the robots.txt-disallow ambiguity, both of which the user must understand.
  if (archived) signals.push('archived');
  if (robotsTxtDisallow) signals.push('robots-txt:disallow');

  return {
    visibility: VISIBILITY.INDEXED,
    reason: robotsTxtDisallow
      ? 'robots.txt Disallow blocks CRAWLING but does NOT prevent indexing from inbound links — still discoverable.'
      : (archived
        ? 'indexable AND archived — durably discoverable; editing the live page will not remove archived copies.'
        : 'no indexing restriction observed — trivially discoverable in search.'),
    removable: !archived, // archived copies need a separate archive-removal step
    durable: archived,
    signals,
  };
}

/**
 * Run the indexability module against a captured page artifact.
 *
 * Inputs are signals the crawler already observed — we add no crawl:
 *   @param {object} page
 *   @param {string}  [page.url]                first-party page URL
 *   @param {string}  [page.meta_robots]        value of <meta name="robots" content="...">
 *   @param {string}  [page.x_robots_tag]       value of the X-Robots-Tag response header
 *   @param {string}  [page.canonical_url]      value of <link rel="canonical" href="...">
 *   @param {boolean} [page.robots_txt_disallow] whether robots.txt disallows this path
 *   @param {boolean} [page.archived]           whether a durable archive/cache copy was observed
 *   @param {object[]} [page.exposed_events]    OPTIONAL: events already detected on THIS page
 *                                              (used only to count what the posture affects)
 * @returns {object[]} module_event[]  (zero or one EXPOSURE_SUMMARY event per page)
 */
function detectIndexability(page = {}) {
  const url = typeof page.url === 'string' ? page.url : null;
  // Honest no-op: with no URL and no directive carriers at all, we cannot make a
  // discoverability claim — emit nothing (never a fabricated default).
  const hasAnyDirective = page.meta_robots != null
    || page.x_robots_tag != null
    || page.canonical_url != null
    || page.robots_txt_disallow != null
    || page.archived != null;
  if (!url && !hasAnyDirective) return [];

  const cls = classifyPage(page);

  // How many already-detected exposures this posture governs (honest count of
  // real sibling events on the same page; 0 if none were passed).
  const exposed = Array.isArray(page.exposed_events) ? page.exposed_events.length : 0;

  // Risk of the POSTURE itself: an indexed page bearing exposures is worse than a
  // deindexed one. We never exceed MEDIUM here — the exposures themselves carry
  // their own risk; this event describes findability, not the leak's own gravity.
  let risk = RISK.INFO;
  if (cls.visibility === VISIBILITY.INDEXED) {
    risk = exposed > 0 ? RISK.MEDIUM : RISK.LOW;
  } else if (exposed > 0) {
    risk = RISK.LOW; // deindexed but still reachable via a known URL
  }

  // Confidence: a present, machine-readable directive (noindex/canonical) is a
  // strong, unambiguous signal; the "indexed by default" inference is weaker
  // because absence-of-restriction is not positive proof of being in the index.
  const directiveDriven = cls.signals.some(
    (s) => s.startsWith('meta:') || s.startsWith('x-robots:') || s.startsWith('canonical'),
  );
  const confidence = directiveDriven ? 0.85 : 0.55;

  return [makeEvent({
    event_type: EVENT_TYPES.EXPOSURE_SUMMARY,
    source_module: MODULE,
    data: { discoverability: cls.visibility, removable: cls.removable, durable: cls.durable },
    confidence,
    visibility: cls.visibility,
    risk,
    source_url: url,
    meta: {
      reason: cls.reason,
      signals: cls.signals,
      // Plain, action-oriented guidance keyed to the posture — what the user can DO.
      remediation: remediationFor(cls),
      governs_exposures: exposed,
      visibility_rank: VISIBILITY_RANK[cls.visibility] || null,
    },
  })];
}

/**
 * Plain remediation guidance keyed to the discoverability posture. No gimmicks —
 * just the concrete next action a user can take, grounded in Google's own tools.
 */
function remediationFor(cls) {
  if (cls.durable) {
    return 'Editing or deleting the live page is NOT enough — an archived/cached copy persists. '
      + 'Request removal from the archive/cache in addition to fixing the live page.';
  }
  if (cls.visibility === VISIBILITY.INDEXED) {
    return cls.signals.includes('robots-txt:disallow')
      ? 'robots.txt alone will not deindex this — add a noindex directive (meta robots or X-Robots-Tag), '
        + 'or use the search engine\'s URL-removal / "results about you" request.'
      : 'Add a noindex directive, restrict access, or file a search-engine removal request to stop it surfacing in search.';
  }
  return 'Already excluded from the search index — lower priority; reachable only by someone who has the direct URL.';
}

module.exports = {
  MODULE,
  detectIndexability,
  classifyPage,
  tokenize,
  NOINDEX_TOKENS,
  NOARCHIVE_TOKENS,
};
