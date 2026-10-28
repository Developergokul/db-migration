# DB Migrator

Core-PHP tool that copies a large local MySQL/MariaDB database (~1 GB+) to a remote one in small, resumable batches. Needs PHP 8.0+ with `pdo_mysql` and `openssl`.

## Run

Put the folder under XAMPP's `htdocs` (or run `php -S 127.0.0.1:8099` inside it) and open `index.php`.
First visit asks you to choose a UI password. The UI only answers to `127.0.0.1`/`::1` by default.

1. Enter local + remote credentials, **Test connection**, **Save credentials** (stored AES-256-GCM encrypted in `data/config.enc`; passwords are never sent back to the browser).
2. Optionally **Choose tables**.
3. **Start**. Pause / Resume / Cancel at any time.

The remote MySQL server must accept connections from your machine (remote access enabled, your IP whitelisted in the hosting panel, port 3306 open).

Headless alternative (no browser, no web timeouts):

```
php cli.php start [--fresh] [--drop] [--no-views] [--tables=a,b]
php cli.php resume
php cli.php status
```

## How it works

- **Time limits** – the browser calls `api.php?action=step` in a loop; each call works for at most ~20 s (less if `max_execution_time` is lower) and returns, so no request ever hits a timeout.
- **Batches** – rows are read by primary-key keyset (`WHERE pk > last ORDER BY pk LIMIT n`), batch size self-tunes to ~2 MB, multi-row `INSERT`s stay under the server's `max_allowed_packet`.
- **Resume / no duplicates** – each batch and its progress marker (`__migrator_progress` on the remote DB) commit in **one transaction**, so a crash/timeout/closed browser resumes at exactly the last committed batch. PK tables use `ON DUPLICATE KEY UPDATE`, so re-runs never duplicate. Tables without a primary key are truncated when first prepared and resumed by offset.
- **Errors** – connection drops are retried (3x, with reconnect); other errors stop the job with status *failed* and the exact table/row count; fix and press Resume.
- **Done** – the progress table is dropped and status becomes *completed*; per-table row counts are compared and mismatches are logged as warnings.

## Options

- **Start fresh** – discard saved progress and re-transfer everything.
- **Drop & recreate remote tables** – `DROP TABLE IF EXISTS` before creating (otherwise existing tables are kept and upserted).
- **Copy views** – created after all tables.

## Security notes

- Keep `data/` out of the web root in production: set `MIGRATOR_DATA_DIR` (env) or `define('DATA_DIR', ...)` in `config.local.php`. `data/.htaccess` already denies web access on Apache.
- Don't expose this tool on a public server. To allow other IPs, set `ALLOWED_IPS` in `config.local.php` and serve over HTTPS.
- Use a dedicated remote DB user, and tick **Use SSL/TLS** when the host supports it.

## Limits

Triggers, stored routines and events are not copied (tables, data, views only). Generated columns are recomputed by the server. Geometry values lose their SRID. Progress/percent is estimated from table statistics, so it can differ slightly from exact bytes.
