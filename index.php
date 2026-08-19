<?php
/**
 * Uptime — A single-file self-hosted uptime monitor.
 * Inspired by Uptime Kuma, built with the same philosophy as Tasssks.
 *
 * Requirements: PHP 8.1+ with SQLite3 and curl extensions.
 *
 * Dev server: php -S localhost:3030 index.php
 */

// When used as PHP built-in server router, serve allowed static files directly
if (php_sapi_name() === 'cli-server') {
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if ($uri !== '/' && $uri !== '' && file_exists(__DIR__ . $uri)) {
        if (preg_match('/\.(sqlite|sqlite3|db|sql|env|htaccess|htpasswd)$/i', $uri)
            || str_contains($uri, '/.git')
        ) {
            http_response_code(403);
            return true;
        }
        return false;
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

define('APP_NAME', 'Uptime');
define('APP_VERSION', '0.1.0');
define('DB_FILE', getenv('UPTIME_DB_FILE') ?: __DIR__ . '/uptime.sqlite');
define('DEFAULT_RETENTION_DAYS', 180);

// ============================================================================
// DATABASE SETUP
// ============================================================================

function getDb(): PDO {
    static $db = null;
    if ($db === null) {
        $db = new PDO('sqlite:' . DB_FILE, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA foreign_keys=ON');
    }
    return $db;
}

function initDatabase(): void {
    $db = getDb();
    // Migration: detect old webhooks table without site_id, drop to recreate below
    $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='webhooks'")->fetch();
    if ($tables) {
        $cols = $db->query("PRAGMA table_info(webhooks)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('site_id', $cols)) {
            $db->exec("DROP TABLE webhooks");
        }
    }
    $db->exec("
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            expected_status INTEGER DEFAULT 200,
            expected_keyword TEXT DEFAULT '',
            timeout INTEGER DEFAULT 10,
            interval INTEGER NOT NULL DEFAULT 60,
            group_id INTEGER,
            enabled INTEGER DEFAULT 1,
            visible INTEGER DEFAULT 1,
            notify INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            status_code INTEGER,
            response_time INTEGER,
            message TEXT DEFAULT '',
            checked_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_checks_site_time ON checks(site_id, checked_at DESC);
        CREATE TABLE IF NOT EXISTS site_status (
            site_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'unknown',
            last_check TEXT,
            last_up TEXT,
            last_down TEXT,
            last_notified_at TEXT,
            FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
        );
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
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip TEXT NOT NULL,
            attempted_at TEXT DEFAULT (datetime('now'))
        );
    ");
}

// ============================================================================
// SECURITY
// ============================================================================

// Block direct access to sensitive files
$requestUri = $_SERVER['REQUEST_URI'] ?? '';
$requestPath = strtolower(parse_url($requestUri, PHP_URL_PATH));
if (preg_match('/\.(sqlite|sqlite3|db|sql)$/i', $requestPath)
    || preg_match('/\.(env|git|htaccess|htpasswd)$/i', $requestPath)
    || str_contains($requestPath, '/.git/')
) {
    http_response_code(403);
    exit;
}

header_remove('X-Powered-By');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

// ============================================================================
// HELPERS
// ============================================================================

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Strict',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}

function verifyCsrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!$token || !hash_equals($_SESSION['csrf_token'], $token)) {
        jsonResponse(['error' => 'Invalid CSRF token'], 403);
    }
}

function jsonResponse(mixed $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function getInput(): array {
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (str_contains($contentType, 'application/json')) {
        return json_decode(file_get_contents('php://input'), true) ?? [];
    }
    return $_POST;
}

function generateToken(int $length = 32): string {
    return bin2hex(random_bytes($length / 2));
}

function hasUsers(): bool {
    $db = getDb();
    $stmt = $db->query("SELECT COUNT(*) as cnt FROM users");
    return (int) $stmt->fetch()['cnt'] > 0;
}

function needsSetup(): bool {
    return !hasUsers();
}

function getCurrentUser(): ?array {
    $userId = $_SESSION['user_id'] ?? null;
    if (!$userId) return null;
    $db = getDb();
    $stmt = $db->prepare("SELECT id, name, email FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetch() ?: null;
}

function isAuthenticated(): bool {
    return getCurrentUser() !== null;
}

function requireAuth(): void {
    if (!isAuthenticated()) {
        jsonResponse(['error' => 'Unauthorized'], 401);
    }
}

function getClientIp(): string {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function checkRateLimit(): void {
    $ip = getClientIp();
    $db = getDb();
    $window = 15; // minutes
    $maxAttempts = 5;

    // Clean old attempts
    $db->prepare("DELETE FROM login_attempts WHERE attempted_at < datetime('now', ?)")->execute(["-$window minutes"]);

    // Count recent attempts
    $stmt = $db->prepare("SELECT COUNT(*) as cnt FROM login_attempts WHERE ip = ? AND attempted_at > datetime('now', ?)");
    $stmt->execute([$ip, "-$window minutes"]);
    $count = (int) $stmt->fetch()['cnt'];

    if ($count >= $maxAttempts) {
        jsonResponse(['error' => 'Too many attempts. Try again later.'], 429);
    }
}

function recordFailedAttempt(): void {
    $db = getDb();
    $db->prepare("INSERT INTO login_attempts (ip) VALUES (?)")->execute([getClientIp()]);
}

function clearAttempts(): void {
    $db = getDb();
    $db->prepare("DELETE FROM login_attempts WHERE ip = ?")->execute([getClientIp()]);
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

function sendNotifications(int $siteId, string $event, string $siteName, string $siteUrl, ?string $message = null): void {
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM webhooks WHERE enabled = 1 AND site_id = ?");
    $stmt->execute([$siteId]);
    $hooks = $stmt->fetchAll();
    if (!$hooks) return;

    foreach ($hooks as $hook) {
        // Check if this webhook subscribes to this event
        $events = array_map('trim', explode(',', $hook['events']));
        if (!in_array($event, $events)) continue;

        $body = formatWebhookPayload($hook['type'], $event, $siteName, $siteUrl, $message);
        sendWebhook($hook['url'], $body, $hook['type']);
    }

    // Update last_notified_at
    $db->prepare("UPDATE site_status SET last_notified_at = datetime('now') WHERE site_id = ?")->execute([$siteId]);
}

function formatWebhookPayload(string $hookType, string $event, string $siteName, string $siteUrl, ?string $message): string {
    $emoji = $event === 'down' ? '🔴' : '🟢';
    $text = "$emoji Site $event: $siteName ($siteUrl)";
    if ($message) $text .= "\n$message";

    return match ($hookType) {
        'slack' => json_encode(['text' => $text]),
        'telegram' => json_encode(['text' => $text, 'parse_mode' => 'HTML']),
        default => json_encode([
            'event' => $event,
            'site' => $siteName,
            'url' => $siteUrl,
            'message' => $message,
            'timestamp' => date('c'),
        ]),
    };
}

function sendWebhook(string $url, string $body, string $type): void {
    $headers = ['Content-Type: application/json'];
    $ctx = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => implode("\r\n", $headers),
        'content' => $body,
        'timeout' => 5,
        'ignore_errors' => true,
    ]]);
    @file_get_contents($url, false, $ctx);
}

// ============================================================================
// CHECK ENGINE
// ============================================================================

function runChecks(): array {
    $db = getDb();
    $sites = $db->query("SELECT * FROM sites WHERE enabled = 1")->fetchAll();
    $checked = 0;

    foreach ($sites as $site) {
        // Check if enough time has passed since last check
        $status = $db->prepare("SELECT last_check FROM site_status WHERE site_id = ?");
        $status->execute([$site['id']]);
        $row = $status->fetch();

        if ($row && $row['last_check']) {
            $lastCheck = strtotime($row['last_check']);
            $elapsed = time() - $lastCheck;
            if ($elapsed < $site['interval']) {
                continue; // Not time yet
            }
        }

        // Perform the check
        $result = checkSite($site);

        // Insert check record
        $stmt = $db->prepare("INSERT INTO checks (site_id, status, status_code, response_time, message) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$site['id'], $result['status'], $result['status_code'], $result['response_time'], $result['message']]);

        // Get previous status
        $prevStatus = $db->prepare("SELECT status FROM site_status WHERE site_id = ?");
        $prevStatus->execute([$site['id']]);
        $prev = $prevStatus->fetch();
        $prevStatusValue = $prev ? $prev['status'] : 'unknown';

        // Update site_status
        $now = date('c');
        $db->prepare("
            INSERT INTO site_status (site_id, status, last_check, last_up, last_down)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(site_id) DO UPDATE SET
                status = excluded.status,
                last_check = excluded.last_check,
                last_up = CASE WHEN excluded.status = 'up' THEN excluded.last_check ELSE last_up END,
                last_down = CASE WHEN excluded.status = 'down' THEN excluded.last_check ELSE last_down END
        ")->execute([$site['id'], $result['status'], $now, $result['status'] === 'up' ? $now : null, $result['status'] === 'down' ? $now : null]);

        // Send notification on status change
        if ($site['notify'] && $prevStatusValue !== 'unknown' && $prevStatusValue !== $result['status']) {
            // Check last_notified_at to prevent spam (5-minute cooldown)
            $notified = $db->prepare("SELECT last_notified_at FROM site_status WHERE site_id = ?");
            $notified->execute([$site['id']]);
            $notifiedRow = $notified->fetch();

            $shouldNotify = true;
            if ($notifiedRow && $notifiedRow['last_notified_at']) {
                $lastNotified = strtotime($notifiedRow['last_notified_at']);
                if ((time() - $lastNotified) < 300) { // 5 minutes
                    $shouldNotify = false;
                }
            }

            if ($shouldNotify) {
                $event = $result['status'] === 'down' ? 'down' : 'recover';
                sendNotifications($site['id'], $event, $site['name'], $site['url'], $result['message']);
            }
        }

        $checked++;
    }

    return ['checked' => $checked];
}

function checkSite(array $site): array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $site['url'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_TIMEOUT => $site['timeout'],
        CURLOPT_CONNECTTIMEOUT => $site['timeout'],
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_NOBODY => $site['method'] === 'HEAD',
        CURLOPT_CUSTOMREQUEST => $site['method'],
        CURLOPT_USERAGENT => 'AbtzUptimeCrawler/' . APP_VERSION,
    ]);

    $start = microtime(true);
    $response = curl_exec($ch);
    $elapsed = round((microtime(true) - $start) * 1000);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);

    if ($response === false) {
        return [
            'status' => 'down',
            'status_code' => 0,
            'response_time' => $elapsed,
            'message' => $error ?: 'Connection failed',
        ];
    }

    // Check status code
    $status = 'up';
    $message = '';

    if ($httpCode !== $site['expected_status']) {
        $status = 'down';
        $message = "Expected HTTP {$site['expected_status']}, got $httpCode";
    }

    // Check for expected keyword
    if ($status === 'up' && !empty($site['expected_keyword'])) {
        $body = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
        if (!str_contains($body, $site['expected_keyword'])) {
            $status = 'down';
            $message = "Expected keyword '{$site['expected_keyword']}' not found";
        }
    }

    return [
        'status' => $status,
        'status_code' => $httpCode,
        'response_time' => $elapsed,
        'message' => $message,
    ];
}

// ============================================================================
// CLEANUP
// ============================================================================

function cleanupChecks(): array {
    $db = getDb();
    $retention = $db->query("SELECT value FROM settings WHERE key = 'retention_days'")->fetch();
    $days = $retention ? (int) $retention['value'] : DEFAULT_RETENTION_DAYS;

    $stmt = $db->prepare("DELETE FROM checks WHERE checked_at < datetime('now', ?)");
    $stmt->execute(["-$days days"]);
    $deleted = $stmt->rowCount();

    return ['deleted' => $deleted];
}

// ============================================================================
// API ROUTER
// ============================================================================

initDatabase();

$action = $_GET['action'] ?? '';

// Handle CLI check command
if (php_sapi_name() === 'cli' || isset($_SERVER['argv'])) {
    $argv = $_SERVER['argv'] ?? [];
    foreach ($argv as $arg) {
        if (str_starts_with($arg, '--action=')) {
            $action = substr($arg, 9);
        }
    }
}

if ($action) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !in_array($action, ['auth_login', 'auth_setup', 'run_checks', 'status_page'])) {
        verifyCsrf();
    }
    match ($action) {
        // Auth
        'auth_status' => apiAuthStatus(),
        'auth_setup' => apiAuthSetup(),
        'auth_login' => apiAuthLogin(),
        'auth_logout' => apiAuthLogout(),

        // Account
        'account_update' => apiAccountUpdate(),

        // Sites
        'list_sites' => apiListSites(),
        'create_site' => apiCreateSite(),
        'update_site' => apiUpdateSite(),
        'delete_site' => apiDeleteSite(),

        // Checks
        'run_checks' => apiRunChecks(),
        'list_checks' => apiListChecks(),

        // Groups
        'list_groups' => apiListGroups(),
        'create_group' => apiCreateGroup(),
        'update_group' => apiUpdateGroup(),
        'delete_group' => apiDeleteGroup(),
        'reorder_groups' => apiReorderGroups(),

        // Webhooks
        'list_webhooks' => apiListWebhooks(),
        'create_webhook' => apiCreateWebhook(),
        'update_webhook' => apiUpdateWebhook(),
        'delete_webhook' => apiDeleteWebhook(),
        'test_webhook' => apiTestWebhook(),

        // Status
        'status_page' => apiStatusPage(),

        // Settings
        'get_settings' => apiGetSettings(),
        'update_settings' => apiUpdateSettings(),

        // Cleanup
        'cleanup_checks' => apiCleanupChecks(),

        default => jsonResponse(['error' => 'Unknown action'], 404),
    };
    exit;
}

// ============================================================================
// ROUTING: Serve HTML pages
// ============================================================================

$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($requestUri, PHP_URL_PATH);

if ($path === '/dash') {
    if (needsSetup()) {
        header('Location: /dash/setup');
        exit;
    }
    if (!isAuthenticated()) {
        header('Location: /dash/login');
        exit;
    }
    serveDashboard();
} elseif ($path === '/dash/setup') {
    if (!needsSetup()) {
        header('Location: /dash');
        exit;
    }
    serveSetupPage();
} elseif ($path === '/dash/login') {
    if (needsSetup()) {
        header('Location: /dash/setup');
        exit;
    }
    if (isAuthenticated()) {
        header('Location: /dash');
        exit;
    }
    serveLoginPage();
} else {
    serveStatusPage();
}

// ============================================================================
// HTML PAGES
// ============================================================================

function serveStatusPage(): void {
    $db = getDb();
    $appNameRow = $db->query("SELECT value FROM settings WHERE key = 'app_name'")->fetch();
    $appName = ($appNameRow && $appNameRow['value']) ? $appNameRow['value'] : APP_NAME;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($appName) ?> — Status</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --green: #22c55e;
            --red: #ef4444;
            --gray: #64748b;
            --radius: 8px;
        }
        .light {
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-muted: #64748b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 1rem;
        }
        .container { max-width: 800px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 2rem 0;
            position: relative;
        }
        .header h1 { font-size: 1.5rem; font-weight: 600; }
        .header .subtitle { color: var(--text-muted); font-size: 0.875rem; margin-top: 0.5rem; }
        .theme-toggle {
            position: absolute;
            top: 2rem;
            right: 0;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            width: 36px;
            height: 36px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.125rem;
        }
        .theme-toggle:hover { opacity: 0.8; }
        .group {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .group-header {
            padding: 1rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }
        .site {
            display: flex;
            align-items: center;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            gap: 0.75rem;
        }
        .site:last-child { border-bottom: none; }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .status-dot.up { background: var(--green); }
        .status-dot.down { background: var(--red); }
        .status-dot.unknown { background: var(--gray); }
        .site-info { flex: 1; min-width: 0; }
        .site-name {
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .site-name a { color: inherit; text-decoration: none; }
        .site-name a:hover { text-decoration: underline; }
        .site-url { color: var(--text-muted); font-size: 0.75rem; }
        .site-meta {
            text-align: right;
            flex-shrink: 0;
        }
        .site-response { font-size: 0.875rem; font-variant-numeric: tabular-nums; }
        .site-time { color: var(--text-muted); font-size: 0.75rem; }
        .timeline {
            display: flex;
            gap: 1px;
            align-items: stretch;
            height: 24px;
            margin-top: 0.5rem;
            border-radius: 3px;
            overflow: hidden;
        }
        .timeline-bar {
            flex: 1;
            min-width: 2px;
            border-radius: 1px;
        }
        .timeline-bar.up { background: var(--green); }
        .timeline-bar.degraded { background: #f59e0b; }
        .timeline-bar.down { background: var(--red); }
        .timeline-bar.unknown { background: var(--border); }
        .timeline-labels {
            display: flex;
            justify-content: space-between;
            font-size: 0.6875rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }
        .uptime-pct { font-size: 0.75rem; color: var(--text-muted); text-align: center; }
        .empty { text-align: center; padding: 3rem; color: var(--text-muted); }
        .footer {
            text-align: center;
            padding: 2rem 0 0;
            color: var(--text-muted);
            font-size: 0.75rem;
        }
        .footer p + div { margin-top: 1.5rem; }
        .footer p + p { margin-top: 0.5rem; }

        @media (min-width: 768px) {
            body { padding: 2rem; }
            .header h1 { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><?= htmlspecialchars($appName) ?></h1>
            <div class="subtitle">System Status</div>
            <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
            </button>
        </div>
        <div id="status-content">
            <div class="empty">Loading...</div>
        </div>
        <div class="footer">
            <p>
              Last updated: <span id="last-updated">—</span> UTC · Refresh in <span id="countdown">30</span>s
           </p>
           <div>
              <p>Powered by <a href="https://github.com/Abtz-Labs/uptime" target="_blank" rel="noopener noreferrer">Uptime</a> &mdash; <a href="https://github.com/Abtz-Labs/uptime/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">O'Saasy</a> Licensed</p>
              <p>#<?= APP_VERSION ?> &copy; Abtz Labs.</p>
          </div>
       </div>
    </div>
    <script>
        async function loadStatus() {
            try {
                const res = await fetch('/?action=status_page');
                const data = await res.json();
                renderStatus(data);
                document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();
            } catch (e) {
                document.getElementById('status-content').innerHTML = '<div class="empty">Failed to load status</div>';
            }
        }

        function renderStatus(data) {
            const container = document.getElementById('status-content');
            const groups = data.groups || [];
            const sites = data.sites || [];

            if (groups.length === 0 && sites.length === 0) {
                container.innerHTML = '<div class="empty">No sites monitored yet</div>';
                return;
            }

            let html = '';

            // Render grouped sites
            for (const group of groups) {
                const groupSites = sites.filter(s => s.group_id == group.id);
                if (groupSites.length === 0) continue;

                html += `<div class="group">`;
                html += `<div class="group-header">${escapeHtml(group.name)}</div>`;
                for (const site of groupSites) {
                    html += renderSite(site);
                }
                html += `</div>`;
            }

            // Render ungrouped sites
            const ungrouped = sites.filter(s => !s.group_id);
            if (ungrouped.length > 0) {
                html += `<div class="group">`;
                for (const site of ungrouped) {
                    html += renderSite(site);
                }
                html += `</div>`;
            }

            container.innerHTML = html;
        }

        function renderSite(site) {
            const status = site.status || 'unknown';
            const response = site.response_time ? site.response_time + 'ms' : '—';
            const time = site.last_check ? timeAgo(site.last_check) : 'Never';
            const uptime = site.uptime_24h;

            // Timeline bars — fixed 50 slots, checks fill from the right (now)
            let timelineHtml = '';
            const timeline = site.timeline || [];
            const SLOTS = 50;
            if (timeline.length > 0) {
                const reversed = [...timeline].reverse();
                const toMs = (d) => new Date(d + 'Z').getTime();
                const slots = new Array(SLOTS).fill('unknown');
                for (let i = 0; i < reversed.length; i++) {
                    slots[SLOTS - 1 - i] = reversed[reversed.length - 1 - i].status;
                }
                const bars = slots.map(s => {
                    const tip = s === 'unknown' ? 'no data' : s;
                    return `<div class="timeline-bar ${s}" title="${tip}"></div>`;
                }).join('');
                timelineHtml = `
                    <div class="timeline">${bars}</div>
                    <div class="timeline-labels"><span>${timeAgo(reversed[0].checked_at)}</span><span>now</span></div>
                `;
            }

            return `
                <div class="site">
                    <div class="status-dot ${status}"></div>
                    <div class="site-info">
                        <div class="site-name"><a href="${escapeHtml(site.url)}" target="_blank" rel="noopener">${escapeHtml(site.name)}</a></div>
                        <div class="site-url">${escapeHtml(site.url)}</div>
                        ${timelineHtml}
                    </div>
                    <div class="site-meta">
                        <div class="site-response">${response}</div>
                        ${uptime !== null ? `<div class="uptime-pct">${uptime}% uptime</div>` : ''}
                    </div>
                </div>
            `;
        }

        function timeAgo(dateStr) {
            const diff = (Date.now() - new Date(dateStr + 'Z').getTime()) / 1000;
            if (diff < 60) return 'Just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            return Math.floor(diff / 86400) + 'd ago';
        }

        function escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        function applyTheme() {
            const saved = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const isLight = saved ? saved === 'light' : !prefersDark;
            document.documentElement.classList.toggle('light', isLight);
        }

        function toggleTheme() {
            const isLight = document.documentElement.classList.toggle('light');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
        }

        applyTheme();
        loadStatus();

        function startRefreshTimer(elId, interval, cb) {
            let countdown = interval;
            setInterval(() => {
                countdown--;
                const el = document.getElementById(elId);
                if (el) el.textContent = countdown;
                if (countdown <= 0) { cb(); countdown = interval; }
            }, 1000);
        }
        startRefreshTimer('countdown', 30, loadStatus);
    </script>
</body>
</html>
<?php
}

function serveLoginPage(): void {
    $db = getDb();
    $appNameRow = $db->query("SELECT value FROM settings WHERE key = 'app_name'")->fetch();
    $appName = ($appNameRow && $appNameRow['value']) ? $appNameRow['value'] : APP_NAME;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — <?= htmlspecialchars($appName) ?></title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --red: #ef4444;
            --radius: 8px;
        }
        .light {
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-muted: #64748b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .login-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2rem;
            width: 100%;
            max-width: 400px;
            position: relative;
        }
        .theme-toggle {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: none;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            color: var(--text);
            font-size: 1.125rem;
            width: 36px;
            height: 36px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .theme-toggle:hover { opacity: 0.8; }
        .login-card h1 { font-size: 1.5rem; text-align: center; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; font-size: 0.875rem; margin-bottom: 0.25rem; }
        .form-group input {
            width: 100%;
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: var(--bg);
            color: var(--text);
            font-size: 1rem;
        }
        .form-group input:focus { outline: 2px solid var(--primary); outline-offset: -1px; }
        .btn {
            width: 100%;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: var(--radius);
            background: var(--primary);
            color: white;
            font-size: 1rem;
            cursor: pointer;
        }
        .btn:hover { background: var(--primary-hover); }
        .error { color: var(--red); font-size: 0.875rem; margin-top: 0.5rem; text-align: center; display: none; }
    </style>
</head>
<body>
    <div class="login-card">
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
        </button>
        <h1><?= htmlspecialchars($appName) ?></h1>
        <form id="login-form">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autocomplete="email">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn">Login</button>
            <div class="error" id="error"></div>
        </form>
    </div>
    <script>
        function applyTheme() {
            const saved = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const isLight = saved ? saved === 'light' : !prefersDark;
            document.documentElement.classList.toggle('light', isLight);
        }
        function toggleTheme() {
            const isLight = document.documentElement.classList.toggle('light');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
        }
        applyTheme();

        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const errorEl = document.getElementById('error');
            errorEl.style.display = 'none';

            const res = await fetch('/?action=auth_login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: document.getElementById('email').value,
                    password: document.getElementById('password').value,
                }),
            });
            const data = await res.json();

            if (data.ok) {
                window.location.href = '/dash';
            } else {
                errorEl.textContent = data.error || 'Login failed';
                errorEl.style.display = 'block';
            }
        });
    </script>
</body>
</html>
<?php
}

function serveSetupPage(): void {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup — <?= APP_NAME ?></title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --red: #ef4444;
            --radius: 8px;
        }
        .light {
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-muted: #64748b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .setup-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2rem;
            width: 100%;
            max-width: 400px;
            position: relative;
        }
        .theme-toggle {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: none;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            color: var(--text);
            font-size: 1.125rem;
            width: 36px;
            height: 36px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .theme-toggle:hover { opacity: 0.8; }
        .setup-card h1 { font-size: 1.5rem; text-align: center; margin-bottom: 0.5rem; }
        .setup-card .subtitle { text-align: center; color: var(--text-muted); margin-bottom: 1.5rem; font-size: 0.875rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; font-size: 0.875rem; margin-bottom: 0.25rem; }
        .form-group input {
            width: 100%;
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: var(--bg);
            color: var(--text);
            font-size: 1rem;
        }
        .form-group input:focus { outline: 2px solid var(--primary); outline-offset: -1px; }
        .btn {
            width: 100%;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: var(--radius);
            background: var(--primary);
            color: white;
            font-size: 1rem;
            cursor: pointer;
        }
        .btn:hover { background: var(--primary-hover); }
        .error { color: var(--red); font-size: 0.875rem; margin-top: 0.5rem; text-align: center; display: none; }
    </style>
</head>
<body>
    <div class="setup-card">
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
        </button>
        <h1>Welcome to <?= APP_NAME ?></h1>
        <p class="subtitle">Create your admin account to get started.</p>
        <form id="setup-form">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" id="name" name="name" required autocomplete="name">
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autocomplete="email">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required minlength="6" autocomplete="new-password">
            </div>
            <button type="submit" class="btn">Create Account</button>
            <div class="error" id="error"></div>
        </form>
    </div>
    <script>
        function applyTheme() {
            const saved = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const isLight = saved ? saved === 'light' : !prefersDark;
            document.documentElement.classList.toggle('light', isLight);
        }
        function toggleTheme() {
            const isLight = document.documentElement.classList.toggle('light');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
        }
        applyTheme();

        document.getElementById('setup-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const errorEl = document.getElementById('error');
            errorEl.style.display = 'none';

            const res = await fetch('/?action=auth_setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: document.getElementById('name').value,
                    email: document.getElementById('email').value,
                    password: document.getElementById('password').value,
                }),
            });
            const data = await res.json();

            if (data.ok) {
                window.location.href = '/dash';
            } else {
                errorEl.textContent = data.error || 'Setup failed';
                errorEl.style.display = 'block';
            }
        });
    </script>
</body>
</html>
<?php
}

function serveDashboard(): void {
    $db = getDb();
    $appNameRow = $db->query("SELECT value FROM settings WHERE key = 'app_name'")->fetch();
    $appName = ($appNameRow && $appNameRow['value']) ? $appNameRow['value'] : APP_NAME;
    $user = getCurrentUser();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard — <?= htmlspecialchars($appName) ?></title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --green: #22c55e;
            --red: #ef4444;
            --gray: #64748b;
            --radius: 8px;
        }
        .light {
            --bg: #f8fafc;
            --surface: #ffffff;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-muted: #64748b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            position: relative;
        }
        .topbar h1 { font-size: 1.25rem; white-space: nowrap; }
        .topbar-right { display: flex; align-items: center; gap: 0.5rem; }
        .hamburger {
            display: none;
            background: none;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            color: var(--text);
            font-size: 1.25rem;
            width: 36px;
            height: 36px;
            cursor: pointer;
            align-items: center;
            justify-content: center;
        }
        .hamburger:hover { opacity: 0.8; }
        .nav-links {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        .nav-links button {
            padding: 0.5rem 0.75rem;
            border: none;
            border-radius: var(--radius);
            background: transparent;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.875rem;
            white-space: nowrap;
            transition: color 0.15s;
        }
        .nav-links button:hover { color: var(--text); }
        .nav-links button.active { color: var(--text); font-weight: 500; }
        .nav-link-btn {
            padding: 0.5rem 0.75rem;
            border: none;
            border-radius: var(--radius);
            background: transparent;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.875rem;
            white-space: nowrap;
            text-decoration: none;
            display: inline-block;
            transition: color 0.15s;
        }
        .nav-link-btn:hover { color: var(--text); }
        .user-dropdown { position: relative; }
        .user-trigger {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.375rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: transparent;
            color: var(--text);
            cursor: pointer;
            font-size: 0.875rem;
        }
        .user-trigger:hover { background: var(--bg); }
        .user-name { max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .user-menu {
            display: none;
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 0.25rem;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            min-width: 160px;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .user-menu.open { display: block; }
        .user-menu button {
            display: block;
            width: 100%;
            padding: 0.5rem 1rem;
            border: none;
            background: none;
            color: var(--text);
            text-align: left;
            cursor: pointer;
            font-size: 0.875rem;
        }
        .user-menu button:hover { background: var(--bg); }
        .user-menu hr {
            border: none;
            border-top: 1px solid var(--border);
            margin: 0.25rem 0;
        }
        .mobile-menu {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            flex-direction: column;
            padding: 0.5rem;
            gap: 0;
            z-index: 50;
        }
        .mobile-menu.open { display: flex; }
        .mobile-menu button, .mobile-menu .nav-link-btn {
            width: 100%;
            text-align: left;
            padding: 0.75rem 1rem;
            border: none;
            border-radius: var(--radius);
            background: transparent;
            color: var(--text-muted);
            cursor: pointer;
            font-size: 0.875rem;
            text-decoration: none;
        }
        .mobile-menu button:hover, .mobile-menu .nav-link-btn:hover { color: var(--text); background: var(--bg); }
        .mobile-menu hr { border: none; border-top: 1px solid var(--border); margin: 0.25rem 0; }
        .content { padding: 1rem; max-width: 1200px; margin: 0 auto; }
        .section { display: none; }
        .section.active { display: block; }
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        .section-header h2 { font-size: 1.25rem; }
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: var(--radius);
            background: var(--primary);
            color: white;
            cursor: pointer;
            font-size: 0.875rem;
        }
        .btn:hover { background: var(--primary-hover); }
        .btn-danger { background: var(--red); }
        .btn-danger:hover { background: #dc2626; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1rem;
            margin-bottom: 1rem;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th:last-child, td:last-child { text-align: right; }
        th { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
        .status-badge {
            display: inline-block;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
            text-transform: uppercase;
        }
        .status-badge.up { background: rgba(34, 197, 94, 0.15); color: var(--green); }
        .status-badge.down { background: rgba(239, 68, 68, 0.15); color: var(--red); }
        .status-badge.unknown { background: rgba(100, 116, 139, 0.15); color: var(--gray); }
        .modal-overlay {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.5);
            z-index: 100;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .modal-overlay.active { display: flex; }
        #confirm-modal { z-index: 150; }
        .modal {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.5rem;
            width: 100%;
            max-width: 500px;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal h3 { margin-bottom: 1rem; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; font-size: 0.875rem; margin-bottom: 0.25rem; }
        .form-group input, .form-group select {
            width: 100%;
            padding: 0.5rem 0.75rem;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: var(--bg);
            color: var(--text);
            font-size: 1rem;
        }
        .form-group input:focus, .form-group select:focus { outline: 2px solid var(--primary); outline-offset: -1px; }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .checkbox-group input[type="checkbox"] {
            width: auto;
            accent-color: var(--primary);
        }
        .checkbox-group label { margin-bottom: 0; cursor: pointer; }
        .drag-handle {
            cursor: grab;
            color: var(--text-muted);
            user-select: none;
        }
        .drag-handle:active { cursor: grabbing; }
        .sortable-ghost { opacity: 0.4; }
        .form-actions { display: flex; gap: 0.5rem; justify-content: space-between; margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border); }
        .modal-tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin: 0 -1.5rem 1rem -1.5rem; padding: 0 1.5rem; }
        .modal-tabs button { background: none; border: none; border-bottom: 2px solid transparent; color: var(--text-muted); padding: 0.75rem 1rem; cursor: pointer; font-size: 0.875rem; font-weight: 500; }
        .modal-tabs button:hover { color: var(--text); }
        .modal-tabs button.active { color: var(--text); border-bottom-color: var(--primary); }
        .modal-tab { display: none; }
        .modal-tab.active { display: block; }
        .modal-lg { max-width: 640px; }
        .empty { text-align: center; padding: 2rem; color: var(--text-muted); }
        .toast {
            position: fixed;
            bottom: 1.5rem;
            left: 50%;
            transform: translateX(-50%) translateY(120%);
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 0.75rem 1.5rem;
            font-size: 0.875rem;
            z-index: 200;
            opacity: 0;
            transition: transform 0.3s, opacity 0.3s;
            pointer-events: none;
        }
        .toast.show {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
        .toast.error { border-color: var(--red); color: var(--red); }
        .toast.success { border-color: var(--green); color: var(--green); }
        @media (max-width: 640px) {
            .nav-links { display: none !important; }
            .user-dropdown { display: none !important; }
            .hamburger { display: flex; }
            table { font-size: 0.875rem; }
            th, td { padding: 0.375rem; }
            .hide-mobile { display: none; }
        }
        .app-footer {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1.5rem 1rem;
            font-size: 0.75rem;
            color: var(--text-muted);
        }
        .app-footer p + p { margin-top: 0.25rem; }
        .app-footer p + div { margin-top: 1.5rem; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.6/Sortable.min.js"></script>
</head>
<body>
    <div class="topbar">
        <h1><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px;margin-right:0.375rem"><path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/></svg><?= htmlspecialchars($appName) ?></h1>
        <div class="topbar-right">
            <nav class="nav-links" id="nav-links">
                <button class="active" onclick="showSection('sites')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.25rem"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>Sites</button>
                <button onclick="showSection('groups')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.25rem"><path d="M16 20V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/><rect width="20" height="14" x="2" y="6" rx="2"/></svg>Groups</button>
                <a href="/" target="_blank" class="nav-link-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.25rem"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>Status Page</a>
            </nav>
            <div class="user-dropdown">
                <button class="user-trigger" onclick="document.getElementById('user-menu').classList.toggle('open')">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    <span class="user-name"><?= htmlspecialchars($user['name']) ?></span>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
                </button>
                <div class="user-menu" id="user-menu">
                    <button onclick="showAccountModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account</button>
                    <button onclick="showSettingsModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>Settings</button>
                    <hr>
                    <button onclick="toggleTheme()" id="theme-toggle-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg><span id="theme-toggle-label">Theme</span></button>
                    <button onclick="logout()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>Logout</button>
                </div>
            </div>
            <button class="hamburger" onclick="document.getElementById('mobile-menu').classList.toggle('open')" aria-label="Menu">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
            </button>
        </div>
        <nav class="mobile-menu" id="mobile-menu">
            <button class="active" onclick="showSection('sites')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>Sites</button>
            <button onclick="showSection('groups')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M16 20V4a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/><rect width="20" height="14" x="2" y="6" rx="2"/></svg>Groups</button>
            <a href="/" target="_blank" class="nav-link-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>Status Page</a>
            <hr>
            <button onclick="showAccountModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account</button>
            <button onclick="showSettingsModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>Settings</button>
            <button onclick="logout()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>Logout</button>
        </nav>
    </div>
    <div class="content">
        <!-- Sites Section -->
        <div id="sites" class="section active">
            <div class="section-header">
                <h2>Sites</h2>
                <button class="btn" onclick="showSiteModal()">+ Add Site</button>
            </div>
            <div id="sites-list"><div class="empty">Loading...</div></div>
        </div>

        <!-- Groups Section -->
        <div id="groups" class="section">
            <div class="section-header">
                <h2>Groups</h2>
                <button class="btn" onclick="showGroupModal()">+ Add Group</button>
            </div>
            <div id="groups-list"><div class="empty">Loading...</div></div>
        </div>

    </div>
    <div class="app-footer">
      <p>Refresh in <span id="sites-refresh">30</span>s</p>
      <div>
        <p>Designed, built, and backed by <a href="https://x.com/rogeriotaques" target="_blank" rel="noopener noreferrer">Rogerio Taques</a>, the guy behind <a href="https://abtz.co?ref=Uptime&utm_source=Uptime&utm_media=Instance" target="_blank" rel="noopener noreferrer">Abtz Labs</a>.</p>
        <p>&copy; Abtz Labs. • #<?= APP_VERSION ?></p>
      </div>
    </div>

    <!-- Account Modal -->
    <div class="modal-overlay" id="account-modal">
        <div class="modal modal-lg">
            <h3>Account</h3>
            <div id="account-form"><div class="empty">Loading...</div></div>
            <div class="form-actions">
                <button type="button" class="btn" style="background:var(--gray)" onclick="closeModal('account-modal')">Close</button>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div class="modal-overlay" id="settings-modal">
        <div class="modal">
            <h3>Settings</h3>
            <div id="settings-form"><div class="empty">Loading...</div></div>
            <div class="form-actions">
                <button type="button" class="btn" style="background:var(--gray)" onclick="closeModal('settings-modal')">Cancel</button>
                <button type="button" class="btn" onclick="saveSettings()">Save</button>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="toast"></div>

    <!-- Confirm Modal -->
    <div class="modal-overlay" id="confirm-modal">
        <div class="modal" style="max-width:360px">
            <h3 id="confirm-title">Confirm</h3>
            <p id="confirm-message" style="margin-bottom:1.5rem;color:var(--text-muted)"></p>
            <div class="form-actions">
                <button class="btn" style="background:var(--gray)" onclick="closeModal('confirm-modal')">Cancel</button>
                <button class="btn btn-danger" id="confirm-ok">Confirm</button>
            </div>
        </div>
    </div>

    <!-- Site Modal -->
    <div class="modal-overlay" id="site-modal">
        <div class="modal">
            <h3 id="site-modal-title">Add Site</h3>
            <div class="modal-tabs" id="site-modal-tabs">
                <button class="active" onclick="switchSiteTab('site')">Site</button>
                <button id="site-modal-webhooks-tab" style="display:none" onclick="switchSiteTab('webhooks')">Webhooks</button>
            </div>
            <div class="modal-tab active" id="site-tab-site">
                <form id="site-form">
                    <input type="hidden" id="site-id">
                    <div class="form-group">
                        <label for="site-name">Name</label>
                        <input type="text" id="site-name" required>
                    </div>
                    <div class="form-group">
                        <label for="site-url">URL</label>
                        <input type="url" id="site-url" required placeholder="https://example.com">
                    </div>
                    <div class="form-group">
                        <label for="site-method">Method</label>
                        <select id="site-method">
                            <option value="GET">GET</option>
                            <option value="HEAD">HEAD</option>
                            <option value="POST">POST</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="site-expected-status">Expected Status</label>
                        <input type="number" id="site-expected-status" value="200">
                    </div>
                    <div class="form-group">
                        <label for="site-expected-keyword">Expected Keyword (optional)</label>
                        <input type="text" id="site-expected-keyword">
                    </div>
                    <div class="form-group">
                        <label for="site-timeout">Timeout (seconds)</label>
                        <input type="number" id="site-timeout" value="10">
                    </div>
                    <div class="form-group">
                        <label for="site-interval">Check Interval</label>
                        <select id="site-interval">
                            <option value="60">Every minute</option>
                            <option value="120">Every 2 minutes</option>
                            <option value="300">Every 5 minutes</option>
                            <option value="600">Every 10 minutes</option>
                            <option value="900">Every 15 minutes</option>
                            <option value="1800">Every 30 minutes</option>
                            <option value="3600">Every hour</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="site-group">Group</label>
                        <select id="site-group"><option value="">None</option></select>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="site-enabled" checked>
                        <label for="site-enabled">Enabled</label>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="site-visible" checked>
                        <label for="site-visible">Visible on status page</label>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="site-notify" checked>
                        <label for="site-notify">Send notifications</label>
                    </div>
                </form>
            </div>
            <div class="modal-tab" id="site-tab-webhooks">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem">
                    <span style="font-size:0.875rem;color:var(--text-muted)">Manage webhooks for this site</span>
                    <button type="button" class="btn btn-sm" onclick="toggleWebhookForm()">+ Add</button>
                </div>
                <div id="site-webhooks-list"></div>
                <div id="site-webhook-form" style="display:none;margin-top:0.75rem;padding:0.75rem;background:var(--bg);border-radius:var(--radius)">
                    <div class="form-group">
                        <label for="site-webhook-url">URL</label>
                        <input type="url" id="site-webhook-url" required placeholder="https://hooks.slack.com/...">
                    </div>
                    <div class="form-group">
                        <label for="site-webhook-type">Type</label>
                        <select id="site-webhook-type">
                            <option value="generic">Generic JSON</option>
                            <option value="slack">Slack</option>
                            <option value="telegram">Telegram</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Events</label>
                        <div class="checkbox-group">
                            <input type="checkbox" id="site-webhook-event-down" checked>
                            <label for="site-webhook-event-down">Down</label>
                        </div>
                        <div class="checkbox-group">
                            <input type="checkbox" id="site-webhook-event-recover" checked>
                            <label for="site-webhook-event-recover">Recover</label>
                        </div>
                    </div>
                    <div style="display:flex;gap:0.5rem">
                        <button type="button" class="btn btn-sm" onclick="saveSiteWebhook()">Save</button>
                        <button type="button" class="btn btn-sm" style="background:var(--gray)" onclick="toggleWebhookForm()">Cancel</button>
                    </div>
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn" style="background:var(--gray)" onclick="closeModal('site-modal')">Cancel</button>
                <button type="button" class="btn" id="site-modal-save-btn">Save</button>
            </div>
        </div>
    </div>

    <!-- Group Modal -->
    <div class="modal-overlay" id="group-modal">
        <div class="modal">
            <h3 id="group-modal-title">Add Group</h3>
            <form id="group-form">
                <input type="hidden" id="group-id">
                <div class="form-group">
                    <label for="group-name">Name</label>
                    <input type="text" id="group-name" required>
                </div>
                <div class="form-group">
                    <label for="group-position">Position</label>
                    <input type="number" id="group-position" value="0" min="0">
                </div>
                <div class="form-actions">
                    <button type="button" class="btn" style="background:var(--gray)" onclick="closeModal('group-modal')">Cancel</button>
                    <button type="submit" class="btn">Save</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        const SUN_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>';
        const MOON_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>';
        function setThemeUI(isLight) {
            const btn = document.getElementById('theme-toggle-btn');
            if (btn) btn.innerHTML = (isLight ? MOON_ICON : SUN_ICON) + '<span id="theme-toggle-label">' + (isLight ? 'Dark mode' : 'Light mode') + '</span>';
        }
        function applyTheme() {
            const saved = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const isLight = saved ? saved === 'light' : !prefersDark;
            document.documentElement.classList.toggle('light', isLight);
            setThemeUI(isLight);
        }
        function toggleTheme() {
            const isLight = document.documentElement.classList.toggle('light');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
            setThemeUI(isLight);
        }
        applyTheme();

        const CSRF = '<?= $_SESSION['csrf_token'] ?? '' ?>';

        async function api(action, data = {}, method = 'GET') {
            const opts = {
                method,
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
            };
            if (method === 'POST') opts.body = JSON.stringify(data);
            const res = await fetch(`/?action=${action}${method === 'GET' && Object.keys(data).length ? '&' + new URLSearchParams(data) : ''}`, opts);
            return res.json();
        }

        function showSection(id) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            document.querySelectorAll('.nav-links button, .mobile-menu button').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            closeUserMenu();
            closeMobileMenu();
            history.replaceState(null, '', '#' + id);
            if (id === 'sites') loadSites();
            if (id === 'groups') loadGroups();
        }

        function showAccountModal() {
            closeUserMenu();
            closeMobileMenu();
            loadAccount();
            document.getElementById('account-modal').classList.add('active');
        }

        function showSettingsModal() {
            closeUserMenu();
            closeMobileMenu();
            loadSettings();
            document.getElementById('settings-modal').classList.add('active');
        }

        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
        }

        function focusFirstInput(modalId) {
            requestAnimationFrame(() => {
                const el = document.querySelector(`#${modalId} input:not([type=hidden]):not([type=checkbox]), #${modalId} select`);
                if (el) el.focus();
            });
        }

        function closeUserMenu() {
            document.getElementById('user-menu').classList.remove('open');
        }

        function closeMobileMenu() {
            document.getElementById('mobile-menu').classList.remove('open');
        }

        // Close menus when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.user-dropdown')) closeUserMenu();
            if (!e.target.closest('.hamburger') && !e.target.closest('.mobile-menu')) closeMobileMenu();
        });

        async function logout() {
            await api('auth_logout', {}, 'POST');
            window.location.href = '/dash/login';
        }

        // ─── SITES ───────────────────────────────────────
        async function loadSites() {
            const [sites, groups] = await Promise.all([api('list_sites'), api('list_groups')]);
            const container = document.getElementById('sites-list');

            if (!sites.length) {
                container.innerHTML = '<div class="empty">No sites yet. Add one to start monitoring.</div>';
                return;
            }

            let html = '<table><thead><tr><th>Status</th><th>Name</th><th class="hide-mobile">URL</th><th>Interval</th><th>Actions</th></tr></thead><tbody>';
            for (const site of sites) {
                const status = site.status || 'unknown';
                html += `<tr>
                    <td><span class="status-badge ${status}">${status}</span></td>
                    <td>${escapeHtml(site.name)}</td>
                    <td class="hide-mobile"><a href="${escapeHtml(site.url)}" target="_blank" style="color:var(--text-muted)">${escapeHtml(site.url)}</a></td>
                    <td>${site.interval}s</td>
                    <td>
                        <button class="btn btn-sm" onclick="editSite(${site.id})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteSite(${site.id}, '${escapeHtml(site.name)}')">Delete</button>
                    </td>
                </tr>`;
            }
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        async function loadGroupOptions() {
            const groups = await api('list_groups');
            const select = document.getElementById('site-group');
            select.innerHTML = '<option value="">None</option>';
            for (const g of groups) {
                select.innerHTML += `<option value="${g.id}">${escapeHtml(g.name)}</option>`;
            }
        }

        function switchSiteTab(tab) {
            document.querySelectorAll('#site-modal .modal-tabs button').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('#site-modal .modal-tab').forEach(t => t.classList.remove('active'));
            const btn = document.querySelector(`#site-modal .modal-tabs button[onclick*="${tab}"]`);
            if (btn) btn.classList.add('active');
            document.getElementById('site-tab-' + tab).classList.add('active');
        }

        function showSiteModal(site = null) {
            loadGroupOptions();
            document.getElementById('site-modal-title').textContent = site ? 'Edit Site' : 'Add Site';
            document.getElementById('site-id').value = site ? site.id : '';
            document.getElementById('site-name').value = site ? site.name : '';
            document.getElementById('site-url').value = site ? site.url : '';
            document.getElementById('site-method').value = site ? site.method : 'GET';
            document.getElementById('site-expected-status').value = site ? site.expected_status : 200;
            document.getElementById('site-expected-keyword').value = site ? site.expected_keyword : '';
            document.getElementById('site-timeout').value = site ? site.timeout : 10;
            document.getElementById('site-interval').value = site ? site.interval : 60;
            document.getElementById('site-group').value = site ? (site.group_id || '') : '';
            document.getElementById('site-enabled').checked = site ? !!site.enabled : true;
            document.getElementById('site-visible').checked = site ? !!site.visible : true;
            document.getElementById('site-notify').checked = site ? !!site.notify : true;
            const whTab = document.getElementById('site-modal-webhooks-tab');
            if (site && site.id) {
                whTab.style.display = '';
                document.getElementById('site-webhook-form').style.display = 'none';
                loadSiteWebhooks(site.id);
            } else {
                whTab.style.display = 'none';
            }
            switchSiteTab('site');
            document.getElementById('site-modal').classList.add('active');
            focusFirstInput('site-modal');
        }

        async function editSite(id) {
            const sites = await api('list_sites');
            const site = sites.find(s => s.id == id);
            if (site) showSiteModal(site);
        }

        async function deleteSite(id, name) {
            if (!await showConfirm('Delete Site', `Delete site "${name}"?`)) return;
            await api('delete_site', { id }, 'POST');
            loadSites();
        }

        document.getElementById('site-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const id = document.getElementById('site-id').value;
            const data = {
                name: document.getElementById('site-name').value,
                url: document.getElementById('site-url').value,
                method: document.getElementById('site-method').value,
                expected_status: parseInt(document.getElementById('site-expected-status').value),
                expected_keyword: document.getElementById('site-expected-keyword').value,
                timeout: parseInt(document.getElementById('site-timeout').value),
                interval: parseInt(document.getElementById('site-interval').value),
                group_id: document.getElementById('site-group').value || null,
                enabled: document.getElementById('site-enabled').checked ? 1 : 0,
                visible: document.getElementById('site-visible').checked ? 1 : 0,
                notify: document.getElementById('site-notify').checked ? 1 : 0,
            };
            if (id) data.id = id;
            const res = await api(id ? 'update_site' : 'create_site', data, 'POST');
            if (!id && res.id) {
                document.getElementById('site-id').value = res.id;
                document.getElementById('site-modal-title').textContent = 'Edit Site';
                document.getElementById('site-modal-webhooks-tab').style.display = '';
                document.getElementById('site-webhooks-list').innerHTML = '<div class="empty" style="font-size:0.875rem">No webhooks yet.</div>';
                loadSites();
            } else {
                closeModal('site-modal');
                loadSites();
            }
        });

        document.getElementById('site-modal-save-btn').addEventListener('click', () => {
            if (document.getElementById('site-tab-site').classList.contains('active')) {
                document.getElementById('site-form').requestSubmit();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const active = document.querySelector('.modal-overlay.active');
                if (active) { closeModal(active.id); e.preventDefault(); }
            }
            if ((e.metaKey || e.ctrlKey) && e.key === 's') {
                const siteModal = document.getElementById('site-modal');
                if (siteModal.classList.contains('active')) {
                    e.preventDefault();
                    document.getElementById('site-modal-save-btn').click();
                }
            }
        });

        // ─── SITE WEBHOOKS (embedded in site modal) ──────
        async function loadSiteWebhooks(siteId) {
            const webhooks = await api('list_webhooks', { site_id: siteId }, 'POST');
            const container = document.getElementById('site-webhooks-list');
            if (!webhooks.length) {
                container.innerHTML = '<div class="empty" style="font-size:0.875rem">No webhooks yet.</div>';
                return;
            }
            let html = '';
            for (const h of webhooks) {
                html += `<div style="display:flex;justify-content:space-between;align-items:center;padding:0.375rem 0;border-bottom:1px solid var(--border);font-size:0.875rem">
                    <div style="min-width:0">
                        <span style="font-weight:500">${escapeHtml(h.type)}</span>
                        <span style="color:var(--text-muted);margin-left:0.5rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;max-width:180px;vertical-align:middle">${escapeHtml(h.url)}</span>
                        <span style="color:var(--text-muted);margin-left:0.5rem">${escapeHtml(h.events)}</span>
                    </div>
                    <div style="display:flex;gap:0.25rem;flex-shrink:0">
                        <button type="button" class="btn btn-sm" onclick="testSiteWebhook(${h.id}, this)" title="Test">Test</button>
                        <button type="button" class="btn btn-sm btn-danger" onclick="deleteSiteWebhook(${h.id})">Delete</button>
                    </div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function toggleWebhookForm() {
            const form = document.getElementById('site-webhook-form');
            const isOpen = form.style.display !== 'none';
            form.style.display = isOpen ? 'none' : '';
            if (!isOpen) {
                document.getElementById('site-webhook-url').value = '';
                document.getElementById('site-webhook-type').value = 'generic';
                document.getElementById('site-webhook-event-down').checked = true;
                document.getElementById('site-webhook-event-recover').checked = true;
            }
        }

        async function saveSiteWebhook() {
            const siteId = document.getElementById('site-id').value;
            if (!siteId) return;
            const events = [];
            if (document.getElementById('site-webhook-event-down').checked) events.push('down');
            if (document.getElementById('site-webhook-event-recover').checked) events.push('recover');
            const data = {
                site_id: parseInt(siteId),
                url: document.getElementById('site-webhook-url').value,
                type: document.getElementById('site-webhook-type').value,
                events: events.join(','),
            };
            await api('create_webhook', data, 'POST');
            toggleWebhookForm();
            loadSiteWebhooks(siteId);
        }

        async function deleteSiteWebhook(id) {
            if (!await showConfirm('Delete Webhook', 'Delete this webhook?')) return;
            const siteId = document.getElementById('site-id').value;
            await api('delete_webhook', { id }, 'POST');
            loadSiteWebhooks(siteId);
        }

        async function testSiteWebhook(id, btn) {
            btn.disabled = true;
            btn.textContent = 'Sending...';
            try {
                const res = await api('test_webhook', { id }, 'POST');
                if (res.error) {
                    btn.textContent = 'Failed';
                    showToast('Test failed: ' + res.error, 'error');
                } else {
                    btn.textContent = 'Sent!';
                    showToast('Test webhook sent successfully', 'success');
                }
            } catch {
                btn.textContent = 'Failed';
                showToast('Test failed: network error', 'error');
            }
            setTimeout(() => { btn.textContent = 'Test'; btn.disabled = false; }, 2000);
        }

        // ─── GROUPS ──────────────────────────────────────
        async function loadGroups() {
            const groups = await api('list_groups');
            const container = document.getElementById('groups-list');

            if (!groups.length) {
                container.innerHTML = '<div class="empty">No groups yet.</div>';
                return;
            }

            let html = '<table id="group-sortable"><thead><tr><th></th><th>Name</th><th>Actions</th></tr></thead><tbody>';
            for (const group of groups) {
                html += `<tr data-id="${group.id}">
                    <td><span class="drag-handle" title="Drag to reorder">⠿</span></td>
                    <td>${escapeHtml(group.name)}</td>
                    <td>
                        <button class="btn btn-sm" onclick="editGroup(${group.id}, '${escapeHtml(group.name)}', ${group.position ?? 0})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteGroup(${group.id}, '${escapeHtml(group.name)}')">Delete</button>
                    </td>
                </tr>`;
            }
            html += '</tbody></table>';
            container.innerHTML = html;

            Sortable.create(document.querySelector('#group-sortable tbody'), {
                handle: '.drag-handle',
                animation: 150,
                ghostClass: 'sortable-ghost',
                onEnd: async function () {
                    const ids = [...document.querySelectorAll('#group-sortable tbody tr')]
                        .map(tr => parseInt(tr.dataset.id));
                    await api('reorder_groups', { ids }, 'POST');
                }
            });
        }

        function showGroupModal(group = null) {
            document.getElementById('group-modal-title').textContent = group ? 'Edit Group' : 'Add Group';
            document.getElementById('group-id').value = group ? group.id : '';
            document.getElementById('group-name').value = group ? group.name : '';
            document.getElementById('group-position').value = group ? (group.position ?? 0) : 0;
            document.getElementById('group-modal').classList.add('active');
            focusFirstInput('group-modal');
        }

        function editGroup(id, name, position) {
            showGroupModal({ id, name, position });
        }

        async function deleteGroup(id, name) {
            if (!await showConfirm('Delete Group', `Delete group "${name}"? Sites in this group will become ungrouped.`)) return;
            await api('delete_group', { id }, 'POST');
            loadGroups();
        }

        document.getElementById('group-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const id = document.getElementById('group-id').value;
            const data = {
                name: document.getElementById('group-name').value,
                position: parseInt(document.getElementById('group-position').value) || 0,
            };
            if (id) data.id = id;
            await api(id ? 'update_group' : 'create_group', data, 'POST');
            closeModal('group-modal');
            loadGroups();
        });

        // ─── ACCOUNT ─────────────────────────────────────
        async function loadAccount() {
            const status = await api('auth_status');
            const user = status.user;
            const container = document.getElementById('account-form');
            container.innerHTML = `
                <h4 style="margin-bottom:0.75rem;font-size:0.875rem;color:var(--text-muted)">Profile</h4>
                <div class="form-group">
                    <label for="account-name">Name</label>
                    <input type="text" id="account-name" value="${escapeHtml(user.name)}">
                </div>
                <div class="form-group">
                    <label for="account-email">Email</label>
                    <input type="email" id="account-email" value="${escapeHtml(user.email)}">
                </div>
                <button class="btn btn-sm" onclick="saveAccount()">Save Profile</button>
                <hr style="margin:1.25rem 0;border:none;border-top:1px solid var(--border)">
                <h4 style="margin-bottom:0.75rem;font-size:0.875rem;color:var(--text-muted)">Change Password</h4>
                <div class="form-group">
                    <label for="account-current-password">Current Password</label>
                    <input type="password" id="account-current-password">
                </div>
                <div class="form-group">
                    <label for="account-new-password">New Password</label>
                    <input type="password" id="account-new-password" minlength="6">
                </div>
                <div class="form-group">
                    <label for="account-confirm-password">Confirm New Password</label>
                    <input type="password" id="account-confirm-password" minlength="6">
                </div>
                <button class="btn btn-sm" onclick="changePassword()">Change Password</button>
            `;
            focusFirstInput('account-modal');
        }

        async function saveAccount() {
            const name = document.getElementById('account-name').value;
            const email = document.getElementById('account-email').value;
            if (!name || !email) { showToast('Name and email are required', 'error'); return; }
            const res = await api('account_update', { name, email }, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            showToast('Profile updated');
        }

        async function changePassword() {
            const current = document.getElementById('account-current-password').value;
            const newPw = document.getElementById('account-new-password').value;
            const confirmPw = document.getElementById('account-confirm-password').value;
            if (!current || !newPw) { showToast('All fields are required', 'error'); return; }
            if (newPw !== confirmPw) { showToast('Passwords do not match', 'error'); return; }
            if (newPw.length < 6) { showToast('Password must be at least 6 characters', 'error'); return; }
            const res = await api('account_update', { password: newPw, current_password: current }, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            showToast('Password changed');
            document.getElementById('account-current-password').value = '';
            document.getElementById('account-new-password').value = '';
            document.getElementById('account-confirm-password').value = '';
        }

        // ─── SETTINGS ────────────────────────────────────
        async function loadSettings() {
            const settings = await api('get_settings');
            const container = document.getElementById('settings-form');
            container.innerHTML = `
                <div class="form-group">
                    <label for="settings-app-name">App Name</label>
                    <input type="text" id="settings-app-name" value="${escapeHtml(settings.app_name || '')}">
                </div>
                <div class="form-group">
                    <label for="settings-retention">Retention (days)</label>
                    <input type="number" id="settings-retention" value="${settings.retention_days || 180}">
                </div>
            `;
            focusFirstInput('settings-modal');
        }

        async function saveSettings() {
            await api('update_settings', {
                app_name: document.getElementById('settings-app-name').value,
                retention_days: parseInt(document.getElementById('settings-retention').value),
            }, 'POST');
            showToast('Settings saved');
            closeModal('settings-modal');
        }

        // ─── HELPERS ─────────────────────────────────────
        function escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        function showToast(message, type = 'success') {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2500);
        }

        function showConfirm(title, message) {
            return new Promise(resolve => {
                document.getElementById('confirm-title').textContent = title;
                document.getElementById('confirm-message').textContent = message;
                document.getElementById('confirm-modal').classList.add('active');
                document.getElementById('confirm-ok').focus();
                const okBtn = document.getElementById('confirm-ok');
                const handler = () => {
                    okBtn.removeEventListener('click', handler);
                    closeModal('confirm-modal');
                    resolve(true);
                };
                okBtn.addEventListener('click', handler);
                document.querySelector('#confirm-modal .btn[style]').onclick = () => {
                    closeModal('confirm-modal');
                    resolve(false);
                };
            });
        }

        // Load initial data from URL hash
        const validSections = ['sites', 'groups'];
        const initialSection = location.hash.replace('#', '');
        if (validSections.includes(initialSection)) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(initialSection).classList.add('active');
            document.querySelectorAll('.nav-links button, .mobile-menu button').forEach(b => {
                b.classList.remove('active');
                if (b.textContent.trim().toLowerCase() === initialSection) b.classList.add('active');
            });
            if (initialSection === 'sites') loadSites();
            else if (initialSection === 'groups') loadGroups();
        } else {
            loadSites();
        }

        function startRefreshTimer(elId, interval, cb) {
            let countdown = interval;
            setInterval(() => {
                countdown--;
                const el = document.getElementById(elId);
                if (el) el.textContent = countdown;
                if (countdown <= 0) { cb(); countdown = interval; }
            }, 1000);
        }
        startRefreshTimer('sites-refresh', 30, loadSites);
    </script>
</body>
</html>
<?php
}

// ============================================================================
// API: AUTH
// ============================================================================

function apiAuthStatus(): void {
    jsonResponse([
        'needs_setup' => needsSetup(),
        'authenticated' => isAuthenticated(),
        'user' => getCurrentUser(),
        'csrf_token' => $_SESSION['csrf_token'] ?? '',
    ]);
}

function apiAuthSetup(): void {
    if (!needsSetup()) {
        jsonResponse(['error' => 'Setup already completed'], 400);
    }

    $input = getInput();
    $name = trim($input['name'] ?? '');
    $email = trim(strtolower($input['email'] ?? ''));
    $password = $input['password'] ?? '';

    if (!$name || !$email || !$password) {
        jsonResponse(['error' => 'All fields are required'], 400);
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        jsonResponse(['error' => 'Invalid email'], 400);
    }
    if (strlen($password) < 6) {
        jsonResponse(['error' => 'Password must be at least 6 characters'], 400);
    }

    $hash = password_hash($password, PASSWORD_BCRYPT);
    $db = getDb();
    $stmt = $db->prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)");
    $stmt->execute([$name, $email, $hash]);
    $userId = (int) $db->lastInsertId();

    session_regenerate_id(true);
    $_SESSION['user_id'] = $userId;
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));

    jsonResponse(['ok' => true, 'csrf_token' => $_SESSION['csrf_token']]);
}

function apiAuthLogin(): void {
    if (needsSetup()) {
        jsonResponse(['error' => 'Setup required'], 400);
    }

    $input = getInput();
    $email = trim(strtolower($input['email'] ?? ''));
    $password = $input['password'] ?? '';

    if (!$email || !$password) {
        jsonResponse(['error' => 'Email and password are required'], 400);
    }

    checkRateLimit();

    $db = getDb();
    $stmt = $db->prepare("SELECT id, password_hash FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        recordFailedAttempt();
        jsonResponse(['error' => 'Invalid email or password'], 403);
    }

    clearAttempts();
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    jsonResponse(['ok' => true, 'csrf_token' => $_SESSION['csrf_token']]);
}

function apiAuthLogout(): void {
    session_destroy();
    jsonResponse(['ok' => true]);
}

// ============================================================================
// API: ACCOUNT
// ============================================================================

function apiAccountUpdate(): void {
    requireAuth();
    $user = getCurrentUser();
    $input = getInput();

    $name = trim($input['name'] ?? '');
    $email = trim(strtolower($input['email'] ?? ''));
    $password = $input['password'] ?? '';
    $currentPassword = $input['current_password'] ?? '';

    if (!$name) jsonResponse(['error' => 'Name is required'], 400);
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        jsonResponse(['error' => 'Valid email is required'], 400);
    }

    $db = getDb();

    // Check email uniqueness
    $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
    $stmt->execute([$email, $user['id']]);
    if ($stmt->fetch()) {
        jsonResponse(['error' => 'Email already in use'], 400);
    }

    // If changing password, verify current password
    if ($password) {
        if (strlen($password) < 6) {
            jsonResponse(['error' => 'New password must be at least 6 characters'], 400);
        }
        $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->execute([$user['id']]);
        $row = $stmt->fetch();
        if (!password_verify($currentPassword, $row['password_hash'])) {
            jsonResponse(['error' => 'Current password is incorrect'], 403);
        }
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $db->prepare("UPDATE users SET name = ?, email = ?, password_hash = ? WHERE id = ?")->execute([$name, $email, $hash, $user['id']]);
    } else {
        $db->prepare("UPDATE users SET name = ?, email = ? WHERE id = ?")->execute([$name, $email, $user['id']]);
    }

    jsonResponse(['ok' => true]);
}

// ============================================================================
// API: SITES
// ============================================================================

function apiListSites(): void {
    requireAuth();
    $db = getDb();
    $sites = $db->query("
        SELECT s.*, ss.status, ss.last_check, ss.last_up, ss.last_down
        FROM sites s
        LEFT JOIN site_status ss ON s.id = ss.site_id
        ORDER BY s.name
    ")->fetchAll();
    jsonResponse($sites);
}

function apiCreateSite(): void {
    requireAuth();
    $input = getInput();
    $name = trim($input['name'] ?? '');
    $url = trim($input['url'] ?? '');

    if (!$name || !$url) jsonResponse(['error' => 'Name and URL are required'], 400);
    if (!filter_var($url, FILTER_VALIDATE_URL)) jsonResponse(['error' => 'Invalid URL'], 400);

    $db = getDb();
    $stmt = $db->prepare("INSERT INTO sites (name, url, method, expected_status, expected_keyword, timeout, interval, group_id, enabled, visible, notify) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([
        $name,
        $url,
        $input['method'] ?? 'GET',
        $input['expected_status'] ?? 200,
        $input['expected_keyword'] ?? '',
        $input['timeout'] ?? 10,
        $input['interval'] ?? 60,
        ($input['group_id'] ?? null) ?: null,
        $input['enabled'] ?? 1,
        $input['visible'] ?? 1,
        $input['notify'] ?? 1,
    ]);
    $siteId = (int) $db->lastInsertId();

    // Initialize site_status
    $db->prepare("INSERT INTO site_status (site_id) VALUES (?)")->execute([$siteId]);

    jsonResponse(['id' => $siteId]);
}

function apiUpdateSite(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $fields = [];
    $params = [];

    foreach (['name', 'url', 'method', 'expected_status', 'expected_keyword', 'timeout', 'interval', 'group_id', 'enabled', 'visible', 'notify'] as $field) {
        if (array_key_exists($field, $input)) {
            $fields[] = "$field = ?";
            $params[] = $input[$field];
        }
    }

    if (!$fields) jsonResponse(['error' => 'No fields to update'], 400);

    $params[] = $id;
    $db->prepare("UPDATE sites SET " . implode(', ', $fields) . " WHERE id = ?")->execute($params);
    jsonResponse(['ok' => true]);
}

function apiDeleteSite(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $db->prepare("DELETE FROM sites WHERE id = ?")->execute([$id]);
    jsonResponse(['ok' => true]);
}

// ============================================================================
// API: CHECKS
// ============================================================================

function apiRunChecks(): void {
    // No CSRF check needed for cron endpoint
    $result = runChecks();
    jsonResponse($result);
}

function apiListChecks(): void {
    requireAuth();
    $siteId = (int) ($_GET['site_id'] ?? 0);
    if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);

    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM checks WHERE site_id = ? ORDER BY checked_at DESC LIMIT 100");
    $stmt->execute([$siteId]);
    jsonResponse($stmt->fetchAll());
}

// ============================================================================
// API: GROUPS
// ============================================================================

function apiListGroups(): void {
    requireAuth();
    $db = getDb();
    $groups = $db->query("SELECT * FROM groups ORDER BY position, name")->fetchAll();
    jsonResponse($groups);
}

function apiCreateGroup(): void {
    requireAuth();
    $input = getInput();
    $name = trim($input['name'] ?? '');
    if (!$name) jsonResponse(['error' => 'Name is required'], 400);

    $db = getDb();
    $maxPos = $db->query("SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM groups")->fetch()['next_pos'];
    $db->prepare("INSERT INTO groups (name, position) VALUES (?, ?)")->execute([$name, $maxPos]);
    jsonResponse(['id' => (int) $db->lastInsertId()]);
}

function apiUpdateGroup(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $fields = [];
    $params = [];

    if (isset($input['name'])) { $fields[] = 'name = ?'; $params[] = trim($input['name']); }
    if (isset($input['position'])) { $fields[] = 'position = ?'; $params[] = (int) $input['position']; }

    if (!$fields) jsonResponse(['error' => 'No fields to update'], 400);

    $params[] = $id;
    $db->prepare("UPDATE groups SET " . implode(', ', $fields) . " WHERE id = ?")->execute($params);
    jsonResponse(['ok' => true]);
}

function apiDeleteGroup(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $db->prepare("DELETE FROM groups WHERE id = ?")->execute([$id]);
    jsonResponse(['ok' => true]);
}

function apiReorderGroups(): void {
    requireAuth();
    $input = getInput();
    $ids = $input['ids'] ?? [];
    if (!is_array($ids) || count($ids) === 0) jsonResponse(['error' => 'Missing ids'], 400);

    $db = getDb();
    $db->exec('BEGIN');
    $stmt = $db->prepare("UPDATE groups SET position = ? WHERE id = ?");
    foreach ($ids as $position => $id) {
        $stmt->execute([(int) $position, (int) $id]);
    }
    $db->exec('COMMIT');
    jsonResponse(['ok' => true]);
}

// ============================================================================
// API: WEBHOOKS
// ============================================================================

function apiListWebhooks(): void {
    requireAuth();
    $input = getInput();
    $siteId = (int) ($input['site_id'] ?? 0);
    if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);

    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM webhooks WHERE site_id = ? ORDER BY created_at DESC");
    $stmt->execute([$siteId]);
    jsonResponse($stmt->fetchAll());
}

function apiCreateWebhook(): void {
    requireAuth();
    $input = getInput();
    $url = trim($input['url'] ?? '');
    $type = $input['type'] ?? 'generic';
    $siteId = (int) ($input['site_id'] ?? 0);

    if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);
    if (!$url) jsonResponse(['error' => 'URL is required'], 400);
    if (!filter_var($url, FILTER_VALIDATE_URL)) jsonResponse(['error' => 'Invalid URL'], 400);
    if (!in_array($type, ['slack', 'telegram', 'generic'])) jsonResponse(['error' => 'Invalid type'], 400);

    $db = getDb();
    // Verify site exists
    $check = $db->prepare("SELECT id FROM sites WHERE id = ?");
    $check->execute([$siteId]);
    if (!$check->fetch()) jsonResponse(['error' => 'Site not found'], 404);

    $db->prepare("INSERT INTO webhooks (site_id, url, type, events) VALUES (?, ?, ?, ?)")->execute([$siteId, $url, $type, $input['events'] ?? 'down,recover']);
    jsonResponse(['id' => (int) $db->lastInsertId()]);
}

function apiUpdateWebhook(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $fields = [];
    $params = [];

    if (isset($input['url'])) { $fields[] = 'url = ?'; $params[] = trim($input['url']); }
    if (isset($input['type'])) { $fields[] = 'type = ?'; $params[] = $input['type']; }
    if (isset($input['events'])) { $fields[] = 'events = ?'; $params[] = $input['events']; }
    if (isset($input['enabled'])) { $fields[] = 'enabled = ?'; $params[] = (int) $input['enabled']; }

    if (!$fields) jsonResponse(['error' => 'No fields to update'], 400);

    $params[] = $id;
    $db->prepare("UPDATE webhooks SET " . implode(', ', $fields) . " WHERE id = ?")->execute($params);
    jsonResponse(['ok' => true]);
}

function apiDeleteWebhook(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $db->prepare("DELETE FROM webhooks WHERE id = ?")->execute([$id]);
    jsonResponse(['ok' => true]);
}

function apiTestWebhook(): void {
    requireAuth();
    $input = getInput();
    $id = (int) ($input['id'] ?? 0);
    if (!$id) jsonResponse(['error' => 'Missing id'], 400);

    $db = getDb();
    $hook = $db->prepare("SELECT * FROM webhooks WHERE id = ?");
    $hook->execute([$id]);
    $webhook = $hook->fetch();
    if (!$webhook) jsonResponse(['error' => 'Webhook not found'], 404);

    $body = formatWebhookPayload($webhook['type'], 'test', 'Test Site', 'https://example.com', 'This is a test notification');
    sendWebhook($webhook['url'], $body, $webhook['type']);
    jsonResponse(['ok' => true]);
}

// ============================================================================
// API: STATUS PAGE
// ============================================================================

function apiStatusPage(): void {
    $db = getDb();

    $groups = $db->query("SELECT * FROM groups ORDER BY position, name")->fetchAll();

    $sites = $db->query("
        SELECT s.id, s.name, s.url, s.group_id, s.visible,
               ss.status, ss.last_check, ss.last_up, ss.last_down,
               (SELECT response_time FROM checks WHERE site_id = s.id ORDER BY checked_at DESC LIMIT 1) as response_time
        FROM sites s
        LEFT JOIN site_status ss ON s.id = ss.site_id
        WHERE s.visible = 1
        ORDER BY s.name
    ")->fetchAll();

    foreach ($sites as &$site) {
        // Uptime percentage (last 24 hours)
        $total = $db->prepare("SELECT COUNT(*) as cnt FROM checks WHERE site_id = ? AND checked_at > datetime('now', '-24 hours')");
        $total->execute([$site['id']]);
        $totalCount = (int) $total->fetch()['cnt'];

        if ($totalCount > 0) {
            $upCount = $db->prepare("SELECT COUNT(*) as cnt FROM checks WHERE site_id = ? AND status = 'up' AND checked_at > datetime('now', '-24 hours')");
            $upCount->execute([$site['id']]);
            $site['uptime_24h'] = round(((int) $upCount->fetch()['cnt'] / $totalCount) * 100, 1);
        } else {
            $site['uptime_24h'] = null;
        }

        // Recent checks — one bar per check (last 50 checks)
        $checks = $db->prepare("
            SELECT status, checked_at FROM checks
            WHERE site_id = ?
            ORDER BY checked_at DESC LIMIT 50
        ");
        $checks->execute([$site['id']]);
        $site['timeline'] = $checks->fetchAll();
    }

    jsonResponse(['groups' => $groups, 'sites' => $sites]);
}

// ============================================================================
// API: SETTINGS
// ============================================================================

function apiGetSettings(): void {
    requireAuth();
    $db = getDb();
    $rows = $db->query("SELECT key, value FROM settings")->fetchAll();
    $settings = [];
    foreach ($rows as $row) {
        $settings[$row['key']] = $row['value'];
    }
    jsonResponse($settings);
}

function apiUpdateSettings(): void {
    requireAuth();
    $input = getInput();
    $db = getDb();

    foreach ($input as $key => $value) {
        $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")->execute([$key, $value]);
    }
    jsonResponse(['ok' => true]);
}

// ============================================================================
// API: CLEANUP
// ============================================================================

function apiCleanupChecks(): void {
    $result = cleanupChecks();
    jsonResponse($result);
}
