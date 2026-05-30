/* MirrorTrace — SYNTHETIC correlation-demo fixture for the Exposure Map.
 *
 * NOT a real scan. These findings are a clearly-labelled SYNTHETIC sample whose
 * ONLY purpose is to demonstrate the cross-source CORRELATION picture (the same
 * email/handle reused across several sites) and the low-risk long-tail folding —
 * something the single-host example-report.json fixture cannot show.
 *
 * It is rendered through the SAME real buildExposureGraph contract
 * (shared/graph/build-exposure-graph.js, mirrored client-side); nothing about the
 * MAP is fabricated — only the input findings are synthetic, and they are flagged
 * as such everywhere via __label. No plaintext email is stored after hashing; the
 * email_prefix link is derived via the HIBP k-anonymity SHA-1 prefix at runtime.
 *
 * file://-safe: loaded as a <script> that sets window.__MIRRORTRACE_GRAPH_DEMO__.
 */
window.__MIRRORTRACE_GRAPH_DEMO__ = {
  "__label": "SYNTHETIC correlation-demo fixture (cross-source example, not a live crawl)",
  "__notice": "These clearly labeled synthetic findings demonstrate how one email address or handle reused across sites becomes correlatable, plus low-risk folding. The map is rendered by the real buildExposureGraph contract and fabricates no link.",
  "__source": "synthetic correlation demo (template) · real graph builder",
  "generated_at": "(synthetic correlation demo)",
  "findings": [
    { "event_type": "PII_EMAIL_PUBLIC", "source_module": "pii_detector", "risk": "high", "visibility": "indexed", "confidence": 0.95, "source_url": "https://forum.example/u/jane", "data": "jane.doe@example.com", "severity_band": "high" },
    { "event_type": "PII_HANDLE_PUBLIC", "source_module": "pii_detector", "risk": "medium", "visibility": "indexed", "confidence": 0.8, "source_url": "https://forum.example/u/jane", "data": "@janedoe", "severity_band": "medium" },
    { "event_type": "PII_EMAIL_PUBLIC", "source_module": "pii_detector", "risk": "high", "visibility": "indexed", "confidence": 0.9, "source_url": "https://broker-x.example/p/12", "data": "jane.doe@example.com", "severity_band": "high" },
    { "event_type": "PII_PHONE_PUBLIC", "source_module": "pii_detector", "risk": "high", "visibility": "linked", "confidence": 0.7, "source_url": "https://broker-x.example/p/12", "severity_band": "high" },
    { "event_type": "PII_POSTAL_PUBLIC", "source_module": "pii_detector", "risk": "high", "visibility": "linked", "confidence": 0.7, "source_url": "https://broker-x.example/p/12", "severity_band": "critical" },
    { "event_type": "PII_HANDLE_PUBLIC", "source_module": "pii_detector", "risk": "medium", "visibility": "indexed", "confidence": 0.8, "source_url": "https://social.example/janedoe", "data": "@janedoe", "severity_band": "medium" },
    { "event_type": "BREACH_RANGE_HIT", "source_module": "breach_range_detector", "risk": "high", "visibility": "private", "confidence": 0.99, "source_url": null, "severity_band": "high" },
    { "event_type": "SELF_PROFILE_URL", "source_module": "accounts_detector", "risk": "low", "visibility": "indexed", "confidence": 0.6, "source_url": "https://blog.example/about", "severity_band": "low" },
    { "event_type": "TRACKER_THIRD_PARTY", "source_module": "tracker_detector", "risk": "low", "visibility": "indexed", "confidence": 0.6, "source_url": "https://blog.example/about", "severity_band": "low" },
    { "event_type": "PII_GEO_HINT_PUBLIC", "source_module": "pii_detector", "risk": "low", "visibility": "indexed", "confidence": 0.5, "source_url": "https://meetup.example/jane", "severity_band": "low" },
    { "event_type": "SELF_PROFILE_URL", "source_module": "accounts_detector", "risk": "low", "visibility": "indexed", "confidence": 0.5, "source_url": "https://oldsite.example/~jane", "severity_band": "low" }
  ]
};
