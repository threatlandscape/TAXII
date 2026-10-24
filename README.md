# Threat Landscape TAXII 2.1 API

## Two APIs. One Purpose.

Not every use case needs the same data. We built two distinct APIs so analysts and engineers each get exactly what they need — nothing more, nothing less.

| | Intelligence API | IOC API |
|---|---|---|
| **For** | Analysts & platforms | Tool integrations |
| **Data** | Full STIX 2.1 object graph | Indicators only |
| **Collection ID** | `91aae408-a1e4-4b3a-84b4-de6f7f6c52e6` | `4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6` |

> **Base URL:** `https://api.threatlandscape.io/taxii2`

The Threat Landscape TAXII server is a read-only Collections Server compatible with any TAXII 2.1 client. Both APIs are served from the same TAXII root over the [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) protocol.

---

## Contents

- [Authentication](#authentication)
- [Accept Header](#accept-header)
- [Quick Start](#quick-start)
- [Shared Endpoints](#endpoint-reference)
  - [GET / — Discovery](#get---discovery)
  - [GET /api1/ — API Root](#get-api1---api-root)
  - [GET /api1/collections/ — Collections](#get-api1collections---collections)
  - [GET /api1/collections/{id}/ — Single Collection](#get-api1collectionsid---single-collection)
- [Threat Landscape Intelligence API](#threat-landscape-intelligence-api)
  - [GET /api1/collections/{id}/objects/ — Get Objects](#get-api1collectionsidObjects---get-objects)
- [Threat Landscape IOC API](#threat-landscape-ioc-api)
  - [IOC Feed Collection](#ioc-feed-collection)
- [Query Parameters](#query-parameters)
- [Pagination](#pagination)
- [Filtering by STIX Type](#filtering-by-stix-type)
- [Filtering by STIX ID](#filtering-by-stix-id)
- [Response Format](#response-format)
- [Response Headers](#response-headers)
- [Error Responses](#error-responses)
- [Common Query Recipes — Intelligence API](#common-query-recipes)
- [IOC Feed — Common Query Recipes](#ioc-feed--common-query-recipes)

---

## Authentication

All endpoints except Discovery require an API key. Three formats are accepted:

**HTTP Basic Auth** (standard TAXII format — recommended):

```bash
-H "Authorization: Basic $(echo -n ':YOUR_THREATLANDSCAPE_API_KEY' | base64)"
```

The username field is ignored; place your API key in the password field.

**Bearer token:**

```bash
-H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

**`apikey` header:**

```bash
-H "apikey: YOUR_THREATLANDSCAPE_API_KEY"
```

A missing or invalid key returns `401 Unauthorized` with a `WWW-Authenticate: Basic` challenge. Keep your key secret — do not include it in client-side code, public repositories, or logs. Contact support to rotate a compromised key.

---

## Accept Header

Every request **must** include an `Accept` header containing `application/taxii+json`:

```bash
-H "Accept: application/taxii+json;version=2.1"
```

Requests without a matching `Accept` header return `406 Not Acceptable`.

---

## Quick Start

```bash
# Discover available API roots (no auth required)
curl 'https://api.threatlandscape.io/taxii2/' \
  -H "Accept: application/taxii+json;version=2.1"

# List collections
curl 'https://api.threatlandscape.io/taxii2/api1/collections/' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"

# Fetch the first page of STIX objects
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?limit=20' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

---

## Endpoint Reference

All TAXII paths end with a trailing slash, as required by the TAXII 2.1 specification.

---

### GET / — Discovery

```
GET https://api.threatlandscape.io/taxii2/
```

Returns server metadata and the list of API roots. No authentication required.

**Example response:**

```json
{
  "title": "Threat Landscape TAXII Server",
  "description": "Read-only TAXII 2.1 server providing continuously updated STIX 2.1 threat intelligence.",
  "contact": "support@threatlandscape.io",
  "default": "/taxii2/api1/",
  "api_roots": ["/taxii2/api1/"]
}
```

---

### GET /api1/ — API Root

```
GET https://api.threatlandscape.io/taxii2/api1/
```

Returns metadata for the `api1` API root. Authentication required.

**Example response:**

```json
{
  "title": "Threat Landscape Intelligence Feed",
  "description": "STIX 2.1 objects from OSINT and darknet sources, served via TAXII 2.1.",
  "versions": ["application/taxii+json;version=2.1"],
  "max_content_length": 10485760
}
```

---

### GET /api1/collections/ — Collections

```
GET https://api.threatlandscape.io/taxii2/api1/collections/
```

Returns the list of available collections. Authentication required.

**Example response:**

```json
{
  "collections": [
    {
      "id": "91aae408-a1e4-4b3a-84b4-de6f7f6c52e6",
      "title": "Threat Landscape Intelligence Feed",
      "description": "Continuously updated STIX 2.1 objects from OSINT and darknet sources.",
      "can_read": true,
      "can_write": false,
      "media_types": ["application/stix+json;version=2.1"]
    },
    {
      "id": "4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6",
      "title": "Threat Landscape IOC Feed",
      "description": "Actionable STIX 2.1 indicator objects (IOCs) with defined validity windows, deduplicated per IOC value.",
      "can_read": true,
      "can_write": false,
      "media_types": ["application/stix+json;version=2.1"]
    }
  ]
}
```

---

### GET /api1/collections/{id}/ — Single Collection

```
GET https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/
```

Returns the metadata object for the specified collection. Authentication required.

Returns `404 Not Found` if the collection ID does not exist.

---

# Threat Landscape Intelligence API

Full-breadth threat intelligence built for analysis, context, and enrichment. Query across the complete STIX 2.1 object graph — threat actors, malware families, campaigns, victims, target sectors, CVEs, TTPs, relationships, and more. Designed for analysts building situational awareness and platforms that need the complete picture.

---

### GET /api1/collections/{id}/objects/ — Get Objects

```
GET https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/
```

Returns a page of STIX 2.1 objects from the collection. Authentication required.

This is the primary data endpoint. Objects are sourced from full STIX 2.1 bundles; all STIX object types within each bundle are returned (unless filtered with `match[type]`).

---

# Threat Landscape IOC API

Lean, fast, and purpose-built for automated indicator ingestion. Delivers only STIX indicator objects via TAXII 2.1 — optimised for direct pipeline consumption into your SIEM, EDR, firewall, or blocklist.

---

### IOC Feed Collection

The **Threat Landscape IOC Feed** is a second collection containing deduplicated, actionable indicator objects (IOCs). Each entry is a single STIX 2.1 `indicator` object with a `valid_until` timestamp.

**Collection ID:** `4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6`

```
GET https://api.threatlandscape.io/taxii2/api1/collections/4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6/objects/
```

Supports the same query parameters (`added_after`, `limit`, `next`, `match[type]`, `match[id]`) as the Intelligence Feed. Because every object in this collection is type `indicator`, `match[type]=indicator` returns the full feed and any other type value returns an empty envelope.

**Difference from the Intelligence Feed:** The Intelligence Feed delivers complete enriched STIX bundles (threat actors, malware, campaigns, relationships, etc.). The IOC Feed delivers only deduplicated indicator objects — one per unique IOC value — suitable for direct ingestion into firewalls, SIEMs, and blocklists.

---

## Query Parameters

| Parameter      | Type    | Default | Description |
|----------------|---------|---------|-------------|
| `added_after`  | string  | —       | Return only objects ingested after this RFC 3339 UTC timestamp (e.g. `2025-06-01T00:00:00Z`). |
| `limit`        | integer | 50      | Maximum number of source bundles to process per page. Maximum: 200. |
| `next`         | string  | —       | Pagination cursor returned in the previous response envelope. |
| `match[type]`  | string  | —       | Comma-separated list of STIX object types to return (e.g. `indicator,malware`). |
| `match[id]`    | string  | —       | Comma-separated list of STIX object IDs to return. |

### `added_after`

Filters by ingestion timestamp — the time the record was added to the Threat Landscape platform. Use this to implement incremental polling: on each run, pass the `X-TAXII-Date-Added-Last` header value from the previous response as `added_after`.

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?added_after=2025-06-01T00:00:00Z' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

### `limit`

Controls how many source bundles are processed per page. Note that each bundle may contain multiple STIX objects, so the number of objects returned can be higher than `limit`. The maximum value is 200; values above this are silently capped.

---

## Pagination

The server uses cursor-based pagination. When more pages are available, the response envelope includes `"more": true` and a `"next"` token:

```json
{
  "objects": [...],
  "more": true,
  "next": "MTI3"
}
```

Pass the `next` value as the `next` query parameter in the following request to retrieve the next page:

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?limit=50&next=MTI3' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

When `"more"` is absent or `false`, you have reached the last page. The `next` token is opaque — do not construct or modify it.

> **Recommended pagination strategy:** Use the `next` token rather than re-issuing the request with a different `added_after` value. The token is stable even when new data is inserted between pages.

---

## Filtering by STIX Type

Use `match[type]` to return only objects of specific STIX types. Pass a comma-separated list of valid STIX type names:

```bash
# Indicators only
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?match[type]=indicator' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"

# Threat actors and malware
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?match[type]=threat-actor,malware' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

Common STIX type values: `attack-pattern`, `campaign`, `identity`, `indicator`, `intrusion-set`, `location`, `malware`, `relationship`, `report`, `threat-actor`, `vulnerability`.

---

## Filtering by STIX ID

Use `match[id]` to retrieve specific STIX objects by their full STIX ID:

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?match[id]=indicator--a3d9e0c1-1234-5678-abcd-ef0123456789' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

`match[type]` and `match[id]` can be combined.

---

## Response Format

All responses use `Content-Type: application/taxii+json;version=2.1`.

### TAXII Envelope

The Get Objects endpoint returns a TAXII envelope object:

```json
{
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--...",
      "name": "...",
      ...
    }
  ],
  "more": true,
  "next": "MTI3"
}
```

| Field     | Type    | Description |
|-----------|---------|-------------|
| `objects` | array   | Array of STIX 2.1 SDOs and SROs. Absent when the result set is empty. |
| `more`    | boolean | `true` if additional pages exist. Absent when `false`. |
| `next`    | string  | Cursor token to pass as `?next=` in the next request. Present only when `more` is `true`. |

### STIX Object Types

Objects in the response conform to [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html). The feed includes all standard STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs) as produced by the Threat Landscape enrichment pipeline.

---

## Response Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | Always `application/taxii+json;version=2.1` |
| `X-TAXII-Date-Added-First` | Ingestion timestamp of the **first** object in the page (microsecond precision, UTC). |
| `X-TAXII-Date-Added-Last` | Ingestion timestamp of the **last** object in the page (microsecond precision, UTC). |

`X-TAXII-Date-Added-First` and `X-TAXII-Date-Added-Last` are present on all non-empty responses from the Get Objects endpoint. Use `X-TAXII-Date-Added-Last` as the `added_after` value when implementing incremental polling without cursor pagination.

---

## Error Responses

All errors use the TAXII error format with `Content-Type: application/taxii+json;version=2.1`:

```json
{
  "title": "Bad Request",
  "description": "added_after must be a valid RFC 3339 UTC timestamp.",
  "http_status": "400"
}
```

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Invalid query parameter value (e.g. malformed timestamp, non-integer limit, tampered `next` token). |
| `401 Unauthorized` | Missing or invalid API key. Response includes `WWW-Authenticate: Basic realm="ThreatLandscape TAXII"`. |
| `404 Not Found` | Unknown collection ID or endpoint path. |
| `405 Method Not Allowed` | This server is read-only; only `GET` is accepted. |
| `406 Not Acceptable` | `Accept` header does not include `application/taxii+json`. |
| `429 Too Many Requests` | Rate limit exceeded. Retry after the number of seconds indicated in the `Retry-After` response header. |
| `502 Bad Gateway` | Upstream data retrieval failed. |

---

## Common Query Recipes

### Incremental polling — new objects since last run

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?added_after=2026-05-01T00:00:00Z&limit=100' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

### All indicators (IOCs) — first page

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?match[type]=indicator&limit=100' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

### All vulnerability objects

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?match[type]=vulnerability&limit=100' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

### Paginate through the full collection

```bash
#!/bin/bash
BASE="https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/"
KEY="YOUR_THREATLANDSCAPE_API_KEY"
NEXT=""

while true; do
  URL="$BASE?limit=100"
  [[ -n "$NEXT" ]] && URL="$URL&next=$NEXT"

  RESPONSE=$(curl -s "$URL" \
    -H "Accept: application/taxii+json;version=2.1" \
    -H "Authorization: Bearer $KEY")

  echo "$RESPONSE" | jq '.objects // [] | length' | xargs -I{} echo "Got {} objects"

  NEXT=$(echo "$RESPONSE" | jq -r '.next // empty')
  MORE=$(echo "$RESPONSE" | jq -r '.more // false')

  [[ "$MORE" != "true" ]] && break
done
```

### Print object types and counts from one page

```bash
curl -s 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?limit=50' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY" \
  | jq '[.objects[].type] | group_by(.) | map({type: .[0], count: length})'
```

### Look up a specific STIX object by ID

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/91aae408-a1e4-4b3a-84b4-de6f7f6c52e6/objects/?match[id]=malware--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

---

## IOC Feed — Common Query Recipes

**Collection ID:** `4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6`

### Fetch the first page of IOCs

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6/objects/?limit=100' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

### Incremental polling — new IOCs since last run

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6/objects/?added_after=2026-05-01T00:00:00Z&limit=100' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```

### Paginate through all IOCs

```bash
#!/bin/bash
BASE="https://api.threatlandscape.io/taxii2/api1/collections/4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6/objects/"
KEY="YOUR_THREATLANDSCAPE_API_KEY"
NEXT=""

while true; do
  URL="$BASE?limit=200"
  [[ -n "$NEXT" ]] && URL="$URL&next=$NEXT"

  RESPONSE=$(curl -s "$URL" \
    -H "Accept: application/taxii+json;version=2.1" \
    -H "Authorization: Bearer $KEY")

  echo "$RESPONSE" | jq '.objects // [] | length' | xargs -I{} echo "Got {} IOCs"

  NEXT=$(echo "$RESPONSE" | jq -r '.next // empty')
  MORE=$(echo "$RESPONSE" | jq -r '.more // false')

  [[ "$MORE" != "true" ]] && break
done
```

### Look up a specific IOC by STIX ID

```bash
curl 'https://api.threatlandscape.io/taxii2/api1/collections/4c3b2a1d-5e6f-4a8b-8c0d-e1f2a3b4c5d6/objects/?match[id]=indicator--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
  -H "Accept: application/taxii+json;version=2.1" \
  -H "Authorization: Bearer YOUR_THREATLANDSCAPE_API_KEY"
```
