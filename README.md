# Uptime

A single-file, self-hosted uptime monitor built with PHP and SQLite.

No frameworks. No Composer. No build tools. One file, one database, done.

## Concept

Uptime was born from a desire for simplicity. Most uptime monitoring tools are bloated, require complex infrastructure, or lock your data behind a subscription. Uptime takes the opposite approach: drop one PHP file on any server with PHP 8.1+ and you have a fully functional uptime monitor with multi-site tracking, groups, webhooks, and a public status page.

The entire application (backend logic, frontend markup, CSS, and JavaScript) lives in a single `index.php` file. The database is a SQLite file created automatically on first run. That's the whole stack.

## Features

- Monitor unlimited sites with configurable check intervals
- Status page with timeline bars (green/grey/red) per site
- Drag-and-drop group reordering
- Webhook notifications (Slack, Telegram, generic JSON)
- Public status page (no login required)
- Dark/light theme toggle
- Recovery key for password recovery
- Automatic data retention cleanup
- Custom User-Agent for crawler identification (`AbtzUptimeCrawler/<version>`)

## Requirements

- PHP 8.1 or later
- SQLite3 extension (usually bundled with PHP)
- curl extension (for HTTP checks)
- A web server (Apache, Nginx, or PHP's built-in server for development)

## Installation

1. Copy `index.php` to your web root (or any directory served by PHP).
2. Make sure the directory is writable (for the SQLite database).
3. Open it in a browser. The setup screen will ask you to create the first admin account.

That's it.

For development (requires [just](https://github.com/casey/just)):

```
just start
```

With a custom port:

```
just start 3000
```

Run in background:

```
just start background
```

Both options combined:

```
just start 3000 background
```

Stop the server:

```
just stop
```

Or directly:

```
php -S localhost:3030 index.php
```

### Scheduled Checks

Site checks are triggered by an external cron job. The cron calls the `run_checks` endpoint, which respects each site's configured interval — only sites that are due get checked. You can safely call it every minute without wasted work.

#### Development

For local testing, run a background loop that triggers checks periodically:

```
just cron          # foreground, every 60s
just cron 30       # foreground, every 30s
just cron background   # background, every 60s
just stop-cron     # stop background cron
```

#### Production

Set up a system cron job to call the endpoint every minute:

```bash
crontab -e
```

Add this line:

```
* * * * * curl -sf "https://your-host/?action=run_checks"
```

Replace `https://your-host` with your actual URL. The `-sf` flags silence output and fail silently on HTTP errors.

If your database is outside the web root (via `UPTIME_DB_FILE`), make sure the cron environment has access to it — e.g.:

```
* * * * * UPTIME_DB_FILE=/var/data/uptime.sqlite curl -sf "https://your-host/?action=run_checks"
```

## User Manual

### First Run

On first access, Uptime shows a setup screen. Create your admin account (name, email, password). This account has full control over the application.

### Sites

Click "+ Add Site" to add a site to monitor. Each site has:

- **Name** — a display label
- **URL** — the endpoint to check
- **Method** — GET or HEAD
- **Expected status** — HTTP status code to consider "up" (default: 200)
- **Expected keyword** — optional string to look for in the response body
- **Timeout** — maximum seconds to wait for a response
- **Interval** — how often to check (in seconds)
- **Group** — assign to a group for organization
- **Notifications** — enable/disable webhook alerts per site

Sites can be temporarily disabled without deleting them. Disabled sites are skipped during checks.

### Groups

Groups let you organize sites logically (e.g., Production, Staging). Drag the `⠿` handle to reorder groups. Sites can be assigned to a group via the site edit modal.

### Dashboard

The dashboard shows all sites with:

- Current status (green dot = up, red = down, grey = unknown)
- Response time of the last check
- 24h uptime percentage
- Timeline bar showing recent check history

The sites list auto-refreshes every 30 seconds.

### Status Page

The public status page (`/`) shows a read-only view of all visible sites, organized by group. No login required. It auto-refreshes every 30 seconds.

Only sites with "visible" enabled appear on the status page.

### Notifications

**Webhooks** are configured per site (site edit modal, Webhooks tab). Supported types: Slack (Incoming Webhook), Telegram (Bot API), and generic JSON POST. You can test webhooks before saving.

Webhook notifications include a 5-minute spam cooldown per site to avoid alert floods.

**Generic JSON payload example:**

```json
{
  "event": "down",
  "site": "My Website",
  "url": "https://example.com",
  "message": "Expected HTTP 200, got 503",
  "timestamp": "2026-08-20T02:00:00+00:00"
}
```

**Slack/Telegram payload:** A formatted text message with an emoji indicator (🔴 for down, 🟢 for recover).

### User-Agent

Uptime identifies itself when checking sites using the User-Agent header: `AbtzUptimeCrawler/<version>`. You can allowlist this in your firewall or server configuration if needed.

### Recovery Key

On first setup, a recovery key is generated and shown once. Save it securely — it can replace your password if you forget it. The key is displayed only once and cannot be retrieved later.

To use the recovery key, enter it in the password field on the login page. After logging in with the key, you'll be prompted to set a new password. The old key is rotated and a new one is generated automatically.

### Retention

Check history is retained for 180 days by default (configurable in App Settings). Old records are cleaned up automatically via the `cleanup_checks` endpoint.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `S` | Sites |
| `G` | Groups |
| `A` | Account |
| `⌘ ,` | App Settings |
| `⌘ S` | Save (in any form) |
| `Esc` | Close modal |
| `?` | Show help |

On Windows/Linux, use `Ctrl` instead of `⌘`.

## Deployment

For production, use Apache or Nginx with PHP-FPM. The key security considerations:

- **Database location.** By default the SQLite file (`uptime.sqlite`) is created in the same directory as `index.php`. Set the `UPTIME_DB_FILE` environment variable to place it outside the web root (recommended). Examples:

  ```bash
  # PHP built-in server (dev)
  UPTIME_DB_FILE=/path/to/data/uptime.sqlite php -S localhost:3030 index.php

  # Apache (.htaccess or vhost)
  SetEnv UPTIME_DB_FILE /var/data/uptime.sqlite

  # Nginx + PHP-FPM (server or location block)
  fastcgi_param UPTIME_DB_FILE /var/data/uptime.sqlite;

  # Docker / systemd
  Environment=UPTIME_DB_FILE=/var/data/uptime.sqlite
  ```
- **Deny direct file access.** The application blocks requests to `.sqlite`, `.env`, and `.git` paths internally, but your web server should also enforce this as a second layer.
- **Do not deploy `test.php` to production.** It is a development-only file.

### Apache

A `.htaccess` file is included in the repository. It routes requests through `index.php`, blocks access to database and sensitive files, and denies access to `test.php`. No extra setup needed if your Apache has `mod_rewrite` and `AllowOverride All`.

### Nginx

```nginx
location ~ \.(sqlite|sqlite3|db|sql|env|bak)$ {
    deny all;
}

location ~ /\.git {
    deny all;
}

location / {
    try_files $uri /index.php$is_args$args;
}
```

## Running Tests

The test suite spins up its own server on port 8090 (with a temporary database):

```
just test
```

Or directly:

```
php test.php
```

Tests use a temporary database and clean up after themselves.

## Contributing

Contributions are welcome. Please keep these principles in mind:

1. **Single-file architecture.** All application code stays in `index.php`. This is a deliberate constraint, not a limitation to work around.

2. **No external PHP dependencies.** No Composer, no autoloaders. If you need a library, either implement the necessary logic directly or reconsider the approach.

3. **Write tests.** New features should include corresponding tests in `test.php`. Use TDD when possible (write failing tests first, then implement).

4. **Keep it simple.** If 50 lines of straightforward code solve the problem, don't write 200 lines of abstracted code. Match the existing style.

5. **Surgical changes.** A pull request should do one thing. Don't bundle unrelated cleanups or formatting changes.

### How to Contribute

1. Fork the repository.
2. Create a feature branch.
3. Write tests for your change.
4. Implement the change (make tests pass).
5. Submit a pull request with a clear description of what and why.

### Reporting Issues

Open an issue with steps to reproduce. Include your PHP version, browser, and any relevant error messages.

## License

[O'SAASy](https://osaasy.dev/). See [LICENSE](LICENSE) for details.

In short: use it, modify it, self-host it, distribute it. Just don't offer it as a competing hosted service where the software itself is the primary value.

Designed and built by [Rogerio Taques](https://x.com/rogeriotaques), the guy behind [Abtz Labs](https://abtz.co).
