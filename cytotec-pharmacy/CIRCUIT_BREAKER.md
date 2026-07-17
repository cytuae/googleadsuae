# Attack Circuit Breaker

The circuit breaker observes only requests that meet all of these conditions:

- the existing security engine already decided to block the request;
- the requested path is `/` or `/index.html`;
- the original Edge request contains `gclid`, `gbraid`, or `wbraid`.

It never automatically re-enables a campaign.

## Modes

- `off`: do not evaluate attack signals.
- `monitor` (default): calculate the rolling window and log `would_pause` only.
- `enforce`: pause the explicit campaign allowlist when the safety gates pass.

Start with `monitor`. Do not use `enforce` until production logs show that the
threshold matches real attack traffic without false positives.

## Required for monitoring

```text
CIRCUIT_INGEST_SECRET=<long-random-secret>
ATTACK_CIRCUIT_MODE=monitor
```

Persistent rolling windows use either of these Vercel/Upstash pairs:

```text
UPSTASH_REDIS_REST_URL=
UPSTASH_REDIS_REST_TOKEN=
```

or:

```text
KV_REST_API_URL=
KV_REST_API_TOKEN=
```

Without Redis, `monitor` uses a best-effort in-memory preview. `enforce` refuses
to pause from in-memory data.

## Thresholds

Defaults:

```text
ATTACK_CIRCUIT_WINDOW_SECONDS=120
ATTACK_CIRCUIT_THRESHOLD=8
ATTACK_CIRCUIT_HARD_THRESHOLD=15
ATTACK_CIRCUIT_MIN_UNIQUE_IPS=3
ATTACK_CIRCUIT_MIN_UNIQUE_ASNS=2
ATTACK_CIRCUIT_COOLDOWN_SECONDS=3600
```

The normal threshold requires diversity across IPs, ASNs, or click IDs. The
hard threshold trips on request volume alone.

Optional alert webhook:

```text
SECURITY_ALERT_WEBHOOK_URL=
```

## Required only for enforce mode

```text
ATTACK_CIRCUIT_MODE=enforce
GOOGLE_ADS_API_VERSION=v24
GOOGLE_ADS_DEVELOPER_TOKEN=
GOOGLE_ADS_CUSTOMER_ID=
GOOGLE_ADS_LOGIN_CUSTOMER_ID=
GOOGLE_ADS_CLIENT_ID=
GOOGLE_ADS_CLIENT_SECRET=
GOOGLE_ADS_REFRESH_TOKEN=
GOOGLE_ADS_CAMPAIGN_IDS=1234567890,2345678901
```

`GOOGLE_ADS_CAMPAIGN_IDS` is an explicit allowlist. Only those campaigns can be
paused. The circuit breaker has no code path that enables them again.

## Production rollout

1. Deploy with `ATTACK_CIRCUIT_MODE=monitor`.
2. Confirm blocked requests now include click IDs and User-Agent in Vercel logs.
3. Add Redis and observe at least one real attack wave.
4. Review `ATTACK_CIRCUIT_EVALUATION` logs and tune thresholds.
5. Configure Google Ads OAuth/API credentials.
6. Test Google Ads credentials against a non-serving test campaign.
7. Switch to `enforce` only after the test campaign pauses successfully.
