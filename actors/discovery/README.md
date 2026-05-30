# A2 — Discovery

Builds the crawl frontier for a case using a **named Request Queue**, then
metamorphs into the crawler.

## Behavior
- Re-runs `validateScope` (defense in depth — never trusts that the gate ran).
- Reads the immutable `CASE` record from the inherited named KV store.
- Opens a named queue `ex-ditector-frontier-<caseId>` and enqueues seeds.
  Crawlee dedupes by `uniqueKey` (the URL), so re-running discovery only adds
  **genuinely new** URLs → cheap, incremental repeat audits.
- Respects `max_pages` as a hard enqueue cap.
- Metamorphs into `CRAWLER_ACTOR_ID`, passing the queue name (storage inherited).

## Human config
- `CRAWLER_ACTOR_ID` env → `YOUR_USERNAME/ex-ditector-crawler`.

## Notes
- Normally reached via metamorph from A0; running it standalone still enforces
  scope and requires a `CASE` record.
- Queue ops cap ~400 rps on Apify; the bounded frontier stays well under.
