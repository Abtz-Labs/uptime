# Memory

Session checkpoints for continuity across sessions.

## 2026-08-19

- Built single-file uptime monitor (`index.php`) with PHP + SQLite
- Features: multi-site monitoring, groups, webhooks, email notifications, public status page, dark/light theme, drag-and-drop group reordering
- Added keyboard shortcuts: `S` sites, `G` groups, `A` account, `⌘,` settings, `⌘S` save, `Esc` close, `?` help
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

## 2026-08-20

- DB migration: refactored `initDatabase()` + new `migrateDatabase()` using `PRAGMA user_version` (v3), legacy DB detection, versioned blocks for webhooks site_id and users recovery_key_hash
- Help modal: added "Scheduled Checks" section with cron endpoint explanation, production curl line, dev `just cron` recipes
- README.md: expanded "Simulated Cron" → "Scheduled Checks" with Development/Production subsections, `crontab -e` setup, `-sf` curl flags, `UPTIME_DB_FILE` env note
- Auto-update feature: added `check_update` and `apply_update` API actions (Tasssks strategy), `GITHUB_RAW_URL` constant, `setSetting()` helper, `apiAuthStatus()` returns `version` + `update_available`
- Auto-update UI: topbar amber badge (hidden by default), Settings modal "Updates" section with Check/Apply buttons, `APP_STATUS` global fetched on page load
- Test count: 100 (all passing)
