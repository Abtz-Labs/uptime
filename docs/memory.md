# Memory

Session checkpoints for continuity across sessions.

## 2026-09-15

- **Nord color scheme** adopted across all surfaces (status page, login, setup, dashboard). Reference: nordtheme.com. Palettes mapped from Tailwind slate/emerald into Polar Night (nord0-nord3), Snow Storm (nord4-nord6), Frost (nord7-nord10), Aurora (nord11-nord15)
- Dark theme: `--bg`=nord0, `--surface`=nord1, `--border`=nord2, `--text`=nord6, `--text-muted`=nord4, `--primary`=nord8, `--primary-hover`=nord10, `--green`=nord14, `--red`=nord11, `--gray`=nord3, `--blue`=nord9
- New CSS vars: `--amber`=nord13 (degraded), `--orange`=nord12 (severely degraded) — replaced hard-coded `#f59e0b`/`#f97316` across CSS + incident color map
- Light theme: `--bg`=nord6, `--surface`=#ffffff, `--border`=nord4, `--text`=nord0, `--text-muted`=nord3, `--primary`=nord10, `--primary-hover`=nord9
- Button text now `var(--bg)` (nord0 dark / nord6 light) for contrast on frost primary buttons; footer link hovers use light-mode primary override for contrast
- Updated: all `rgba()` badge/chart colors to Nord RGB, canvas chart line/area colors, 4 favicon data URIs (nord2 rect + nord6 text)
- Version bumped 0.1.1 → 0.2.0 (`package.json` + `APP_VERSION`)
- Dashboard & incidents table rows: light theme rows now use `var(--surface)` to match group title color
- **Status thresholds** updated from 4-tier to 5-tier: ≥96% → Operational, ≥80% → Degraded, ≥50% → Severely Degraded, ≥10% → Mostly Down, <10% → Down. New `mostly_down` status across PHP/CSS/JS. `--red-dark: #A05058` for Down, `--red: #BF616A` for Mostly Down. Status colors: vibrant green `#4ADE80`, amber `#FBBF24`, orange `#F97316`; red kept at original Nord
- **Assumed Operational** status: when no checks in 24h but historical checks exist, status page shows "Assumed Operational" (green check) instead of "Unknown". True "Unknown" (gray !) only when zero checks ever. Applied to overall and per-group status in `apiStatusPage()`.
- Test count: 288 (all passing)

## 2026-09-03

- **Health check endpoint**: `?action=health_check` returns `{"status":"healthy"}` (200) or `{"status":"unhealthy","error":"..."}` (503); pings DB via `SELECT 1`; no auth or cron token required
- Added to README under "Health Check" section with curl example
- Test count: 281 (all passing)

## 2026-08-28

- **Sticky navbar**: `.topbar` changed from `position: relative` to `position: sticky; top: 0; z-index: 1000`
- **Keyboard shortcut**: `A` (account) changed to `⌘A`/`Ctrl+A` with `e.preventDefault()`; updated in code, README, help modal, memory.md
- **Site indicators column**: new column between Status and Name in dashboard site table; 4 inline SVG icons (circle-check, eye, link, bell) for enabled/visible/show_url/notify; ON = green full opacity, OFF = muted 35% opacity
- **Notifications indicator logic**: bell icon ON only when `site.notify && site.webhook_count > 0`; `apiListSites()` now includes `(SELECT COUNT(*) FROM webhooks WHERE site_id = s.id) AS webhook_count`
- **Mobile responsive**: on < 641px, hidden columns: Indicators, URL, Interval; actions replaced with `⋯` dropdown menu (same pattern for both Sites and Incidents tables)
- **Actions dropdown**: shared `.site-actions-menu` / `.site-actions-dropdown` component; `toggleSiteActions()` function; closes on click-outside and on option click
- **Overflow fix**: `.dashboard-group` and `.dashboard-ungrouped` changed from `overflow: hidden` to `overflow: visible` to unclip dropdowns
- **Incidents table**: Update/Delete buttons replaced with same `⋯` dropdown as Sites
- Test count: 277 → 281 (health check added)

## 2026-08-25

- **Per-site `show_url` toggle**: new `show_url` column on `sites` table (default 1). When disabled, the status page API strips the `url` field from the site response — no link, no URL text displayed publicly. DB migration v3→v4.
- **Overall uptime section on Status Page**: shows a status indicator (Operational/Degraded/Severely Degraded/Down) with colored icon + a 4-column grid showing uptime percentages for 24h, 7d, 30d, 90d. Responsive: 2x2 grid on mobile (<480px).
- **Status thresholds**: ≥85% → Operational (green #22c55e), 20–84% → Degraded (amber #f59e0b), 1–19% → Severely Degraded (orange #f97316), 0% → Down (red #ef4444).
- **Per-group uptime**: group headers in the status page show 24h average uptime percentage (right-aligned).
- **App Name scoping**: `app_name` setting now only affects the Status Page title/heading. Dashboard and Login always show "Uptime". Settings label renamed to "Status Page Title".
- Test count: 149 (all passing)

## 2026-08-19

- Built single-file uptime monitor (`index.php`) with PHP + SQLite
- Features: multi-site monitoring, groups, webhooks, email notifications, public status page, dark/light theme, drag-and-drop group reordering
- Added keyboard shortcuts: `S` sites, `G` groups, `⌘A` account, `⌘,` settings, `⌘S` save, `Esc` close, `?` help
- Added Help modal with user instructions and shortcut reference
- Added "Report bug" link in dropdown pointing to GitHub issues
- Account modal refactored: single Save button handles both profile and password changes
- Toast notifications for all forms: site CRUD, group CRUD, account update, password change, settings
- Cmd+S works consistently across all modals (site, group, account, settings)
- Webhooks tab: Save button now closes modal when on webhooks tab
- Recovery key feature: generated on setup, can be used as password replacement, auto-rotates on use, requires new password after recovery login
- DB migration: `recovery_key_hash` column added to users table (Tasssks-style PRAGMA table_info check)
- DB migration: refactored to `PRAGMA user_version` strategy aligned with Tasssks (`migrateDatabase()` at v3)
- Test count: 96 (all passing)

## 2026-08-24

- Cron token feature: `verifyCronToken()` gates `run_checks` and `cleanup_checks` endpoints; timing-safe `hash_equals` validation via `?token=...` query param; backward compatible (no token set = open access)
- `generate_cron_token` API action: generates 32-char hex token, stores in settings table; protected from `update_settings` overwrite
- Settings modal refactored with tabs: General (existing settings) + Automation (cron token + examples)
- Token bypass for dev: skips validation on PHP built-in server (`cli-server` SAPI) unless `UPTIME_STRICT_CRON=1` env is set (used by test suite)
- SCHEDULED status: enabled sites with no checks show blue "SCHEDULED" badge instead of grey "UNKNOWN"; `--blue` CSS variable added; `s.enabled` added to `apiStatusPage()` query
- Documentation: all three surfaces (README, in-app help, Automation tab) show both `run_checks` and `cleanup_checks` cron examples with token
- Test count: 114 (all passing)

## 2026-08-24 (PM)

- **Production bug fix**: `checkSite()` strict comparison `$httpCode !== $site['expected_status']` failed on PHP 8.0 where SQLite PDO returns strings not integers (`"200" !== 200` → always down). Fixed with `(int)` cast.
- **Root cause**: HestiaCP Apache vhost for `uptime.abtz.co` configured with `php8.0-fpm` socket, not 8.1 as expected. PHP 8.0 SQLite returns column values as strings; PHP 8.1 returns proper ints.
- **Production crontab fix**: `action= cleanup_checks` had a stray space — cleanup never ran.
- **Test improvement**: assertions now verify healthy sites report `up` (not just "valid status"); test count 115 (all passing)
- Renamed `test.php` → `tests.php` (updated all refs: Justfile, .htaccess, README.md)

## 2026-08-20

- DB migration: refactored `initDatabase()` + new `migrateDatabase()` using `PRAGMA user_version` (v3), legacy DB detection, versioned blocks for webhooks site_id and users recovery_key_hash
- Help modal: added "Scheduled Checks" section with cron endpoint explanation, production curl line, dev `just cron` recipes
- README.md: expanded "Simulated Cron" → "Scheduled Checks" with Development/Production subsections, `crontab -e` setup, `-sf` curl flags, `UPTIME_DB_FILE` env note
- Auto-update feature: added `check_update` and `apply_update` API actions (Tasssks strategy), `GITHUB_RAW_URL` constant, `setSetting()` helper, `apiAuthStatus()` returns `version` + `update_available`
- Auto-update UI: topbar amber badge (hidden by default), Settings modal "Updates" section with Check/Apply buttons, `APP_STATUS` global fetched on page load
- Test count: 100 (all passing)

## 2026-08-26

- Check Logs modal: "Logs" button per site in dashboard opens modal with historical check table (time, status badge, code, response time, message)
- Period filter: dropdown defaults to "Last 6 hours", supports 1h/6h/24h/7d/30d/All time; `apiListChecks()` now accepts `from`/`to` query params (limit raised to 500)
- Messages: empty messages show "Success"; non-empty (down events) wrapped in `<code>` tag
- Action buttons restyled: Logs/Edit/Delete all outlined; blue hover for Logs/Edit, red hover for Delete
- Modal title format: `"{site name} logs"` (not "Check Logs — ...")
- Test count: 115 (all passing)

## 2026-08-27

- **Telegram webhook integration**: Bot Token, Chat ID, Message Template fields; auto-constructs `https://api.telegram.org/bot<TOKEN>/sendMessage`; template supports `{{event}}`, `{{site_name}}`, `{{url}}`, `{{message}}`, `{{timestamp}}`; falls back to raw JSON if no template
- **Slack webhook improvements**: Message Template support with same placeholders; URL placeholder shows example format; help hint links to https://api.slack.com/apps
- **Form UX**: Type field moved first (was URL → Type → Events); URL field hidden for Telegram (auto-constructed); conditional fields per type
- **DB migration v5→v6**: `bot_token`, `chat_id`, `message_template` columns on `webhooks` table
- **Backend**: `formatWebhookPayload()` processes templates for both Slack and Telegram; `sendNotifications()` overrides URL for Telegram; `sendWebhook()` simplified (removed unused `$type` param)
- **Edit webhook**: Edit button per webhook item; reuses form with hidden edit ID; `update_webhook` API for edits
- **Telegram MarkdownV2**: `parse_mode: MarkdownV2` with auto-escaping of special characters
- **Template flexibility**: `\{\{\s*key\s*\}\}` regex supports `{{url}}` and `{{ url }}` (optional spaces); template values escaped, template syntax preserved
- **Incidents system** (restored from backup): `incidents` + `incident_updates` tables (DB v6→v7); full CRUD API; status page shows active/recent/history; dashboard tab with modal
- **Locale/date formatting**: `locale` setting; `fmtDate()`, `fmtTime()`, `fmtDateBare()`, `fmtResolvedRelative()`; 10 locale options (UTC, ja-JP, en-US, en-GB, de-DE, fr-FR, pt-BR, ko-KR, zh-CN)
- **Tests**: 262 total (all passing); 75 new tests covering webhooks, incidents, incident updates, status page incident filtering (time-based buckets)
- **Status page tweaks**: group uptime label capitalized ("Uptime"), website cards show percentage only (no "uptime" text)
- **Bug fix**: `showSiteModal()` now async, awaits `loadGroupOptions()` so group select is populated before setting value on edit
- **Dashboard merge** (plan `2026-08-27-merge-websites-groups`): replaced two-tab (Websites / Groups) navigation with single unified page; groups render with nested sites; ungrouped sites under "(Ungrouped)" section; group-level and site-level drag-and-drop reorder; removed `loadGroups()`, `showSection()` simplified, group modal position field removed; `G` keyboard shortcut removed; help modal updated; CSS for `.dashboard-group`, `.dashboard-group-header`, `.dashboard-group-sites`, `.dashboard-ungrouped`
- **Dashboard contract tests**: 15 new tests verifying `group_id` in site responses, `position` in group responses, groups ordered by position, group membership changes
- Test count: 277 (all passing)
