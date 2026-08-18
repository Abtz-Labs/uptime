# Move Webhooks Inside Site Modal

## Status: done

## Context
Webhooks are currently global — one global webhook table, one global "Webhooks" nav section, and `sendNotifications()` fires all enabled webhooks for every site event. This is wrong: webhooks should be per-site, managed inside the site add/edit modal.

**Breaking API change**: `create_webhook` now requires `site_id`; `list_webhooks` scopes by `site_id`. Acceptable for a self-hosted single-admin app.

**Additional scope** (same session): Account/Settings converted to modals, theme toggle moved to user dropdown, icons added to nav/menu items, app icon added.

## Approach

### 1. Schema: Add `site_id` FK to `webhooks`
- Migration runs BEFORE `CREATE TABLE IF NOT EXISTS` block — detects old schema via `PRAGMA table_info`, drops old table, then main schema block recreates it correctly
- New schema:
  ```sql
  CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'generic',
      enabled INTEGER DEFAULT 1,
      events TEXT DEFAULT 'down,recover',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_webhooks_site ON webhooks(site_id);
  ```

### 2. API: Scope webhooks to `site_id`
- `create_webhook`: require `site_id` in payload; validate site exists (return 404 if not) before insert
- `update_webhook`: keep as-is (works on webhook id)
- `delete_webhook`: keep as-is
- `list_webhooks`: require `site_id` param, filter by it (POST with JSON body)
- `test_webhook`: keep as-is
- All five API endpoints remain in the route dispatch — only the global UI section is removed

### 3. Backend: Update `sendNotifications()`
- Query: `SELECT * FROM webhooks WHERE enabled = 1 AND site_id = ?` (instead of global)

### 4. UI: Remove global "Webhooks" section
- Removed "Webhooks" nav button (both desktop and mobile nav)
- Removed the `#webhooks` section div from the dashboard
- Removed `loadWebhooks()`, `showWebhookModal()`, `deleteWebhook()`, webhook form submit handler, webhook modal HTML
- Removed `'webhooks'` from `validSections` array
- Removed the `showSection('webhooks')` branch in `showSection()`
- Removed the `#webhooks` branch in the initial-hash loader

### 5. UI: Fix confirm-modal z-index collision
- Raised `#confirm-modal` z-index to `150` (above site modal at `100`) so confirm dialogs render above the site modal when webhook delete is triggered from inside it

### 6. UI: Site modal with tabs
- Restructured site modal into two tabs: **Site** (form fields) and **Webhooks** (inline list + add form)
- Tabs use `.modal-tabs` / `.modal-tab` CSS classes
- Webhooks tab only visible when editing an existing site (or after first save)
- `switchSiteTab()` handles tab switching, resets to Site tab on every open
- Cancel + Save buttons shared outside both tab panels (always visible)
- Buttons use `justify-content: space-between` (Cancel left, Save right)
- Added spacing: title-to-tabs `1rem`, footer separated by border + padding

### 7. UI: Keyboard shortcuts
- `ESC` closes the active modal
- `Cmd+S` / `Ctrl+S` triggers Save (submits the form when Site tab is active)

### 8. UI: Webhook test button feedback
- Button shows "Sending..." while request is in flight
- Shows "Sent!" on success, "Failed" on error
- Toast notification via `showToast()` with success/error message and error details
- Button reverts after 2s

### 9. UI: Group position field
- Added `position` number input to group add/edit modal
- `showGroupModal()` populates position from group data
- Form submit handler includes position in the payload

### 10. Bugfix: `apiCreateSite()` undefined key
- `$input['group_id']` warning when group_id not in payload — fixed with `($input['group_id'] ?? null) ?: null`

### 11. Tests
- All webhook tests pass `site_id`
- Added: `missing site_id rejected` test
- Added: cascade delete test (delete site → webhooks gone)
- Added: cross-site isolation test (other site's webhooks unaffected)
- Added: group position update test

### 12. UI: Account and Settings as modals
- `#account` and `#settings` sections replaced with `#account-modal` and `#settings-modal` overlays
- `showSection('account'/'settings')` replaced with `showAccountModal()` / `showSettingsModal()`
- Account modal uses `modal-lg` (640px) for profile + password cards; Settings is standard width
- Both close with ESC, Cancel, or clicking outside
- Removed `'account'` and `'settings'` from `validSections` and hash loader
- `focusFirstInput()` fires after async innerHTML set (not before)

### 13. UI: App icon
- Added activity/pulse SVG icon next to app title `<h1>` in topbar

### 14. UI: Icons on nav and menu items
- Desktop nav: monitor (Sites), layers (Groups), external-link (Status Page)
- Mobile menu: same + user (Account), gear (Settings), log-out (Logout)
- User dropdown: same three items with matching icons
- All icons use 14px Lucide SVG with consistent vertical alignment

### 15. UI: Theme toggle in dropdown
- Removed standalone `.theme-toggle` button from topbar
- Added to user dropdown with sun/moon icon switching
- Light mode: moon icon + "Dark mode"
- Dark mode: sun icon + "Light mode"
- `setThemeUI(isLight)` helper updates icon + label on toggle and page load
- Theme toggle label also appears in mobile menu via dropdown access

## Files modified
- `index.php` — schema, API handlers, notification dispatch, UI (modals, nav, JS, icons, theme)
- `test.php` — webhook + group test cases
