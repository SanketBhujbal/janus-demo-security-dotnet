# JANUS Demo — .NET Security Mission

> **DO NOT DEPLOY.** Intentionally vulnerable ASP.NET Core payments API.

## Seeded vulnerabilities

| # | Severity | Rule | Endpoint | Expected outcome |
|---|---|---|---|---|
| 0 | HIGH | `pan-cvv-logging` | `POST /api/payments/charge` | ✅ VALIDATED |
| 1 | HIGH | `webhook-amount-trust` | `POST /api/webhook/gateway` | ✅ VALIDATED |
| 2 | HIGH | `broken-authz` | `GET /api/account/{id}` | ✅ VALIDATED |
| 3 | MED | `missing-idempotency` | `POST /api/payments/transfer` | ❌ FAILED |

Finding 3 fails because the healer adds an `Idempotency-Key` header requirement.
The existing test `test_transfer_no_idempotency_key` sends the request without the header,
which now returns `400 Bad Request` — validator detects the regression → **FAILED**.

## Demo settings

| Field | Value |
|---|---|
| **Repository path** | `C:\Users\bhujbalsa\janus-demo-security-dotnet` |
| **Mode** | `Full loop — exploit → patch → validate` |
| **Min severity** | `Medium` |
| **Max findings** | `4` |

## Credentials

| User | Password | Balance |
|---|---|---|
| alice | alice-pw | $1,000 |
| bob | bob-pw | $500 |
