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
define('CRAWLER_VERSION', '1.0.0');
define('DB_FILE', getenv('UPTIME_DB_FILE') ?: __DIR__ . '/uptime.sqlite');
define('DEFAULT_RETENTION_DAYS', 180);
define('GITHUB_RAW_URL', 'https://raw.githubusercontent.com/Abtz-Labs/uptime/main/index.php');

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
            recovery_key_hash TEXT,
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

    migrateDatabase($db);
}

function migrateDatabase(PDO $db): void {
    $version = (int) $db->query('PRAGMA user_version')->fetchColumn();

    // Existing DB created before version-based migrations — stamp and skip
    if ($version === 0 && $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")->fetch()) {
        $version = 1;
    }

    // Version 1 → 2: Webhooks site_id column
    if ($version < 2) {
        $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='webhooks'")->fetch();
        if ($tables) {
            $cols = $db->query("PRAGMA table_info(webhooks)")->fetchAll(PDO::FETCH_COLUMN, 1);
            if (!in_array('site_id', $cols)) {
                $db->exec("DROP TABLE webhooks");
            }
        }
    }

    // Version 2 → 3: recovery_key_hash column on users
    if ($version < 3) {
        $cols = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('recovery_key_hash', $cols)) {
            $db->exec("ALTER TABLE users ADD COLUMN recovery_key_hash TEXT");
        }
    }

    // Version 3 → 4: show_url column on sites
    if ($version < 4) {
        $cols = $db->query("PRAGMA table_info(sites)")->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array('show_url', $cols)) {
            $db->exec("ALTER TABLE sites ADD COLUMN show_url INTEGER DEFAULT 1");
        }
    }

    $db->exec('PRAGMA user_version = 4');
}

function rotateRecoveryKey(int $userId): string {
    $key = bin2hex(random_bytes(16));
    getDb()->prepare("UPDATE users SET recovery_key_hash = ? WHERE id = ?")
        ->execute([hash('sha256', $key), $userId]);
    return $key;
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

function verifyCronToken(): void {
    if (php_sapi_name() === 'cli-server' && !getenv('UPTIME_STRICT_CRON')) return;

    $db = getDb();
    $row = $db->query("SELECT value FROM settings WHERE key = 'cron_token'")->fetch();
    if ($row && $row['value']) {
        $provided = $_GET['token'] ?? '';
        if (!$provided || !hash_equals($row['value'], $provided)) {
            jsonResponse(['error' => 'Invalid or missing cron token'], 401);
        }
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

function setSetting(string $key, string $value): void {
    getDb()->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
        ->execute([$key, $value]);
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
        CURLOPT_USERAGENT => 'AbtzUptimeCrawler/' . CRAWLER_VERSION,
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

    $expected = (int) $site['expected_status'];
    if ($httpCode !== $expected) {
        $status = 'down';
        $message = "Expected HTTP $expected, got $httpCode";
    }

    // Check for expected keyword (case-insensitive)
    if ($status === 'up' && !empty($site['expected_keyword'])) {
        $body = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
        if (stripos($body, $site['expected_keyword']) === false) {
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
        'regenerate_recovery_key' => apiRegenerateRecoveryKey(),

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
        'generate_cron_token' => apiGenerateCronToken(),

        // Updates
        'check_update' => apiCheckUpdate(),
        'apply_update' => apiApplyUpdate(),

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
            --blue: #3b82f6;
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
            display: flex;
            flex-direction: column;
        }
        .container { max-width: 800px; margin: 0 auto; flex: 1; width: 100%; display: flex; flex-direction: column; }
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
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
        }
        .group-meta {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.75rem;
            font-weight: 400;
            color: var(--text-muted);
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
        .status-dot.up, .status-dot.operational { background: var(--green); }
        .status-dot.down { background: var(--red); }
        .status-dot.unknown { background: var(--gray); }
        .status-dot.scheduled { background: var(--blue); }
        .status-dot.degraded { background: #f59e0b; }
        .status-dot.severely_degraded { background: #f97316; }
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
        .timeline-bar.scheduled { background: var(--blue); }
        .timeline-labels {
            display: flex;
            justify-content: space-between;
            font-size: 0.6875rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }
        .uptime-pct { font-size: 0.75rem; color: var(--text-muted); text-align: center; }
        .overall-status {
            text-align: center;
            margin: 1rem 0;
        }
        .overall-status-icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 0.5rem;
        }
        .overall-status-icon.operational { background: var(--green); }
        .overall-status-icon.degraded { background: #f59e0b; }
        .overall-status-icon.severely_degraded { background: #f97316; }
        .overall-status-icon.down { background: var(--red); }
        .overall-status-icon.unknown { background: var(--gray); }
        .overall-status-label {
            font-size: 1.125rem;
            font-weight: 600;
        }
        .overall-uptime {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1px;
            background: var(--border);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            margin: 1rem 0;
        }
        @media (min-width: 480px) {
            .overall-uptime { grid-template-columns: repeat(4, 1fr); }
        }
        .overall-uptime-cell {
            background: var(--surface);
            padding: 0.75rem 0.5rem;
            text-align: center;
        }
        .overall-uptime-value {
            font-size: 1.125rem;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }
        .overall-uptime-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }
        .empty { text-align: center; padding: 3rem; color: var(--text-muted); }
        .footer {
            text-align: center;
            padding: 2rem 0 0;
            color: var(--text-muted);
            font-size: 0.75rem;
            margin-top: auto;
        }
        .footer a { color: var(--text); }
        .footer a:hover { color: var(--primary); }
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
              <p>Powered by <a href="https://github.com/Abtz-Labs/uptime" target="_blank" rel="noopener noreferrer">Uptime</a> &mdash; <a href="https://github.com/Abtz-Labs/uptime/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">O'SAASy</a> Licensed</p>
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

            // Overall status indicator + uptime grid
            const overall = data.overall || {};
            if (overall.status) {
                const statusLabels = {
                    operational: 'Operational',
                    degraded: 'Degraded',
                    severely_degraded: 'Severely Degraded',
                    down: 'Down',
                    unknown: 'Unknown',
                };
                const checkSvg = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
                const warnSvg = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
                const xSvg = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>';
                const icon = overall.status === 'operational' ? checkSvg : (overall.status === 'down' ? xSvg : warnSvg);

                const fmt = (v) => v !== null ? v.toFixed(1) + '%' : '—';
                html += `
                    <div class="overall-status">
                        <div class="overall-status-icon ${overall.status}">${icon}</div>
                        <div class="overall-status-label">${statusLabels[overall.status]}</div>
                    </div>
                    <div class="overall-uptime">
                        <div class="overall-uptime-cell">
                            <div class="overall-uptime-value">${fmt(overall.uptime_24h)}</div>
                            <div class="overall-uptime-label">Last 24 hours</div>
                        </div>
                        <div class="overall-uptime-cell">
                            <div class="overall-uptime-value">${fmt(overall.uptime_7d)}</div>
                            <div class="overall-uptime-label">Last 7 days</div>
                        </div>
                        <div class="overall-uptime-cell">
                            <div class="overall-uptime-value">${fmt(overall.uptime_30d)}</div>
                            <div class="overall-uptime-label">Last 30 days</div>
                        </div>
                        <div class="overall-uptime-cell">
                            <div class="overall-uptime-value">${fmt(overall.uptime_90d)}</div>
                            <div class="overall-uptime-label">Last 90 days</div>
                        </div>
                    </div>`;
            }

            // Render grouped sites
            for (const group of groups) {
                const groupSites = sites.filter(s => s.group_id == group.id);
                if (groupSites.length === 0) continue;

                const gUptime = group.uptime_24h !== null ? group.uptime_24h.toFixed(1) + '% uptime' : '';
                html += `<div class="group">`;
                html += `<div class="group-header"><span>${escapeHtml(group.name)}</span><span class="group-meta">${gUptime}</span></div>`;
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
            const rawStatus = site.status || 'unknown';
            const status = rawStatus === 'unknown' && site.enabled ? 'scheduled' : rawStatus;
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

            const nameHtml = site.url
                ? `<a href="${escapeHtml(site.url)}" target="_blank" rel="noopener">${escapeHtml(site.name)}</a>`
                : escapeHtml(site.name);
            const urlHtml = site.url ? `<div class="site-url">${escapeHtml(site.url)}</div>` : '';

            return `
                <div class="site">
                    <div class="status-dot ${status}"></div>
                    <div class="site-info">
                        <div class="site-name">${nameHtml}</div>
                        ${urlHtml}
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login — <?= APP_NAME ?></title>
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
        .footer { text-align: center; padding: 1.5rem 0 0; color: var(--text-muted); font-size: 0.75rem; }
        .footer a { color: var(--text-muted); }
        .footer a:hover { color: var(--primary); }
        .auth-wrapper { display: flex; flex-direction: column; align-items: center; width: 100%; max-width: 400px; }
    </style>
</head>
<body>
    <div class="auth-wrapper">
    <div class="login-card">
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>
        </button>
        <h1><?= APP_NAME ?></h1>
        <form id="login-form">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="you@example.com" required autocomplete="email">
            </div>
            <div class="form-group">
                <label for="password">Password or recovery key</label>
                <input type="password" id="password" name="password" placeholder="Password or recovery key" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn">Login</button>
            <div class="error" id="error"></div>
        </form>
    </div>
    <div class="footer">
        <p>Powered by <a href="https://github.com/Abtz-Labs/uptime" target="_blank" rel="noopener noreferrer">Uptime</a> &mdash; <a href="https://github.com/Abtz-Labs/uptime/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">O'Saasy</a> Licensed</p>
        <p>#<?= htmlspecialchars(APP_VERSION) ?> &copy; Abtz Labs.</p>
    </div>
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

        sessionStorage.removeItem('rk');
        sessionStorage.removeItem('rk_reset');

        const savedEmail = localStorage.getItem('uptime_email');
        const emailEl = document.getElementById('email');
        const passwordEl = document.getElementById('password');
        if (savedEmail) {
            emailEl.value = savedEmail;
            passwordEl.focus();
        } else {
            emailEl.focus();
        }

        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const errorEl = document.getElementById('error');
            errorEl.style.display = 'none';

            const email = document.getElementById('email').value;
            const res = await fetch('/?action=auth_login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: email,
                    password: document.getElementById('password').value,
                }),
            });
            const data = await res.json();

            if (data.ok) {
                localStorage.setItem('uptime_email', email);
                if (data.recovery_key) {
                    sessionStorage.setItem('rk', data.recovery_key);
                    sessionStorage.setItem('rk_reset', data.password_reset ? '1' : '0');
                }
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
        .footer { text-align: center; padding: 1.5rem 0 0; color: var(--text-muted); font-size: 0.75rem; }
        .footer a { color: var(--text-muted); }
        .footer a:hover { color: var(--primary); }
        .auth-wrapper { display: flex; flex-direction: column; align-items: center; width: 100%; max-width: 400px; }
    </style>
</head>
<body>
    <div class="auth-wrapper">
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
    <div class="footer">
        <p>Powered by <a href="https://github.com/Abtz-Labs/uptime" target="_blank" rel="noopener noreferrer">Uptime</a> &mdash; <a href="https://github.com/Abtz-Labs/uptime/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">O'Saasy</a> Licensed</p>
        <p>#<?= htmlspecialchars(APP_VERSION) ?> &copy; Abtz Labs.</p>
    </div>
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
        sessionStorage.removeItem('rk');
        sessionStorage.removeItem('rk_reset');

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
                if (data.recovery_key) {
                    sessionStorage.setItem('rk', data.recovery_key);
                    sessionStorage.setItem('rk_reset', '0');
                }
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
    $user = getCurrentUser();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard — <?= APP_NAME ?></title>
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
            --blue: #3b82f6;
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
            flex-direction: column;
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
            display: flex;
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
            display: none;
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
        .user-dropdown { position: relative; display: none; }
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
        .user-menu a {
            display: block;
            padding: 0.5rem 1rem;
            color: var(--text);
            font-size: 0.875rem;
        }
        .user-menu a:hover { background: var(--bg); }
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
        .content { padding: 1rem; max-width: 1200px; margin: 0 auto; flex: 1; width: 100%; }
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
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn:disabled:hover { background: var(--primary); }
        .btn-danger { background: var(--red); }
        .btn-danger:hover { background: #dc2626; }
        .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
        .btn-outlined { background: transparent; border: 1px solid var(--border); color: var(--text-muted); }
        .btn-outlined:hover { background: rgba(59, 130, 246, 0.15); color: var(--primary); border-color: var(--primary); }
        .btn-outlined-danger:hover { background: rgba(239, 68, 68, 0.15); color: var(--red); border-color: var(--red); }
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
        .status-badge.scheduled { background: rgba(59, 130, 246, 0.15); color: var(--blue); }
        .update-badge {
            display: none;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.7rem;
            font-weight: 500;
            background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
            cursor: pointer;
            white-space: nowrap;
            vertical-align: middle;
            margin-left: 0.5rem;
        }
        .update-badge.visible { display: inline-block; }
        .updates-section { margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
        .updates-current { font-size: 0.85rem; color: var(--text-secondary, #6b7280); margin-bottom: 0.5rem; }
        .updates-status { font-size: 0.85rem; margin: 0.5rem 0; }
        .updates-status.available { color: #f59e0b; font-weight: 500; }
        .updates-status.uptodate { color: var(--green, #22c55e); }
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
        .btn-gray { background: var(--gray); }
        .btn-gray:hover { background: #475569; }
        .modal-sm { max-width: 360px; }
        .modal-md { max-width: 440px; }
        .rk-content { text-align: center; }
        .rk-warn { color: var(--red); font-size: 0.75rem; margin-top: 0.75rem; }
        .rk-pw-field { display: none; margin-top: 1rem; text-align: left; }
        .rk-check { display: flex; align-items: center; gap: 0.375rem; justify-content: center; margin-top: 1rem; font-size: 0.875rem; cursor: pointer; }
        .form-actions-center { justify-content: center; border-top: none; padding-top: 0; }
        .webhook-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
        .webhook-form { margin-top: 0.75rem; padding: 0.75rem; background: var(--bg); border-radius: var(--radius); }
        .webhook-item { display: flex; justify-content: space-between; align-items: center; padding: 0.375rem 0; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
        .webhook-item-info { min-width: 0; }
        .webhook-item-type { font-weight: 500; }
        .webhook-item-url { color: var(--text-muted); margin-left: 0.5rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; max-width: 180px; vertical-align: middle; }
        .webhook-item-events { color: var(--text-muted); margin-left: 0.5rem; }
        .webhook-item-actions { display: flex; gap: 0.5rem; }
        .help-hint { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem; }
        .help-version { color: var(--text-muted); }
        .site-url-link { color: var(--text-muted); }
        .confirm-msg { margin-bottom: 1.5rem; color: var(--text-muted); }
        .rk-copy-btn { margin-left: 0.5rem; padding: 0.25rem 0.5rem; }
        .webhook-label { font-size: 0.875rem; color: var(--text-muted); }
        .sortable-ghost { opacity: 0.4; }
        .form-actions { display: flex; gap: 0.5rem; justify-content: space-between; margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border); }
        .modal-tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin: 0 -1.5rem 1rem -1.5rem; padding: 0 1.5rem; }
        .modal-tabs button { background: none; border: none; border-bottom: 2px solid transparent; color: var(--text-muted); padding: 0.75rem 1rem; cursor: pointer; font-size: 0.875rem; font-weight: 500; }
        .modal-tabs button:hover { color: var(--text); }
        .modal-tabs button.active { color: var(--text); border-bottom-color: var(--primary); }
        .modal-tab { display: none; }
        .modal-tab.active { display: block; }
        .modal-lg { max-width: 640px; }
        .modal-xl { max-width: 800px; }
        .checks-table { font-size: 0.8125rem; }
        .checks-table td:nth-child(2), .checks-table td:nth-child(3), .checks-table td:nth-child(4) { white-space: nowrap; }
        .checks-table code { font-size: 0.8125rem; background: var(--bg); padding: 0.125rem 0.375rem; border-radius: var(--radius); }
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
        .help-content { max-height: 60vh; overflow-y: auto; }
        .help-section { margin-bottom: 1.5rem; }
        .help-section h4 { margin-bottom: 0.5rem; font-size: 0.875rem; color: var(--text-muted); }
        .help-section p { font-size: 0.875rem; line-height: 1.5; }
        .help-table { font-size: 0.875rem; width: 100%; border-collapse: collapse; }
        .help-table td { padding: 0.375rem 0.5rem; }
        .help-table tr:nth-child(odd) { background: var(--bg); }
        .help-table td:first-child { width: 80px; }
        .help-table kbd { background: var(--bg); border: 1px solid var(--border); border-radius: 3px; padding: 0.125rem 0.375rem; font-size: 0.75rem; font-family: inherit; }
        .recovery-key-display { display: inline-flex; align-items: center; gap: 0.5rem; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.75rem 1rem; margin-top: 0.5rem; }
        .recovery-key-display code { font-family: monospace; font-size: 1rem; letter-spacing: 0.08em; user-select: all; color: var(--text); }
        .hidden { display: none !important; }
        .hide-mobile { display: none; }
        table { font-size: 0.875rem; }
        th, td { padding: 0.375rem; }
        @media (min-width: 641px) {
            .nav-links { display: flex !important; }
            .user-dropdown { display: block !important; }
            .hamburger { display: none; }
            .hide-mobile { display: table-cell; }
        }
        .app-footer {
            max-width: 1200px;
            margin-left: auto;
            margin-right: auto;
            padding: 1.5rem 1rem;
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: auto;
            width: 100%;
        }
        .app-footer a { color: var(--text); }
        .app-footer a:hover { color: var(--primary); }
        .app-footer p + p { margin-top: 0.25rem; }
        .app-footer p + div { margin-top: 1.5rem; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.6/Sortable.min.js"></script>
</head>
<body>
    <div class="topbar">
        <h1><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px;margin-right:0.375rem"><path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/></svg><?= APP_NAME ?><span class="update-badge" id="update-badge" onclick="showSettingsModal()" title="Update available"></span></h1>
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
                    <button onclick="showHelp();closeUserMenu()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="M3 11h1a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H3a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1z"/><path d="M21 11h-1a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1a1 1 0 0 0 1-1v-5a1 1 0 0 0-1-1z"/><path d="M4 11V8a8 8 0 0 1 16 0v3"/><path d="M18 18a4 4 0 0 1-4 4h-2"/></svg>Help</button>
                    <a href="https://github.com/Abtz-Labs/uptime/issues" target="_blank" rel="noopener noreferrer" style="display:block;text-decoration:none"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>Report bug<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="float:right;margin-top:2px"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>
                    <hr>
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
        <p>Designed and built by <a href="https://x.com/rogeriotaques" target="_blank" rel="noopener noreferrer">Rogerio Taques</a>, the guy behind <a href="https://abtz.co?ref=Uptime&utm_source=Uptime&utm_media=Instance" target="_blank" rel="noopener noreferrer">Abtz Labs</a>.</p>
        <p>&copy; Abtz Labs. • #<?= APP_VERSION ?></p>
      </div>
    </div>

    <!-- Account Modal -->
    <div class="modal-overlay" id="account-modal">
        <div class="modal modal-lg">
            <h3>Account</h3>
            <div class="modal-tabs" id="account-modal-tabs">
                <button class="active" onclick="switchAccountTab('profile')">Profile</button>
                <button onclick="switchAccountTab('security')">Security</button>
            </div>
            <div class="modal-tab active" id="account-tab-profile">
                <div id="account-profile-form"><div class="empty">Loading...</div></div>
            </div>
            <div class="modal-tab" id="account-tab-security">
                <div id="account-security-form"><div class="empty">Loading...</div></div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-gray" onclick="closeModal('account-modal')">Cancel</button>
                <button type="button" class="btn" onclick="saveAccount()" data-modal-save>Save</button>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div class="modal-overlay" id="settings-modal">
        <div class="modal">
            <h3>Settings</h3>
            <div class="modal-tabs" id="settings-modal-tabs">
                <button class="active" onclick="switchSettingsTab('general')">General</button>
                <button onclick="switchSettingsTab('automation')">Automation</button>
            </div>
            <div class="modal-tab active" id="settings-tab-general">
                <div class="updates-section" id="updates-section"></div>
                <div id="settings-form"><div class="empty">Loading...</div></div>
            </div>
            <div class="modal-tab" id="settings-tab-automation">
                <div id="settings-automation-form"><div class="empty">Loading...</div></div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-gray" onclick="closeModal('settings-modal')">Cancel</button>
                <button type="button" class="btn" onclick="saveSettings()" data-modal-save>Save</button>
            </div>
        </div>
    </div>

    <!-- Check Logs Modal -->
    <div class="modal-overlay" id="checks-modal">
        <div class="modal modal-xl">
            <h3 id="checks-modal-title">Logs</h3>
            <div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap">
                <label for="checks-period" style="font-size:0.8125rem;color:var(--text-muted)">Filter by</label>
                <select id="checks-period" onchange="loadChecksData()" style="padding:0.375rem 0.5rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);font-size:0.8125rem">
                    <option value="">All time</option>
                    <option value="1h">Last hour</option>
                    <option value="6h" selected>Last 6 hours</option>
                    <option value="24h">Last 24 hours</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                </select>
            </div>
            <div id="checks-content"><div class="empty">Loading...</div></div>
            <div class="form-actions">
                <button type="button" class="btn btn-gray" onclick="closeModal('checks-modal')">Close</button>
            </div>
        </div>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="toast"></div>

    <!-- Confirm Modal -->
    <div class="modal-overlay" id="confirm-modal">
        <div class="modal modal-sm">
            <h3 id="confirm-title">Confirm</h3>
            <p id="confirm-message" class="confirm-msg"></p>
            <div class="form-actions">
                <button class="btn btn-gray" onclick="closeModal('confirm-modal')">Cancel</button>
                <button class="btn btn-danger" id="confirm-ok">Confirm</button>
            </div>
        </div>
    </div>

    <!-- Help Modal -->
    <div class="modal-overlay" id="help-modal">
        <div class="modal modal-lg">
            <h3>Help</h3>
            <div class="help-content">
                <div class="help-section">
                    <h4>Sites</h4>
                    <p>Add websites to monitor by clicking <strong>+ Add Site</strong>. Each site can be configured with a check interval, expected status code, keyword matching, and notification settings. Sites can be temporarily disabled without deletion.</p>
                </div>
                <div class="help-section">
                    <h4>Groups</h4>
                    <p>Organize sites into groups (e.g., Production, Staging). Drag the <strong>⠿</strong> handle to reorder groups. Assign sites to groups via the site edit modal.</p>
                </div>
                <div class="help-section">
                    <h4>Status Page</h4>
                    <p>The public status page (<strong>/</strong>) shows a read-only view of all visible sites. No login required. Auto-refreshes every 30 seconds.</p>
                </div>
                <div class="help-section">
                    <h4>Notifications</h4>
                    <p><strong>Webhooks</strong> — configure per site (Slack, Telegram, or generic JSON). Test before saving.</p>
                    <p style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem"><strong>Generic JSON payload example:</strong></p>
                    <pre style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem;overflow-x:auto;margin-top:0.25rem">{
  "event": "down",
  "site": "My Website",
  "url": "https://example.com",
  "message": "Expected HTTP 200, got 503",
  "timestamp": "2026-08-20T02:00:00+00:00"
}</pre>
                </div>
                <div class="help-section">
                    <h4>Scheduled Checks</h4>
                    <p>Site checks are triggered by an external cron job. The cron calls the <code style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:0.125rem 0.375rem">run_checks</code> endpoint, which respects each site's configured interval — only sites that are due get checked.</p>
                    <p style="margin-top:0.5rem">Generate a <strong>Cron Token</strong> in Settings → Automation to protect these endpoints from unauthorized access. Once set, the token is required as a <code style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:0.125rem 0.375rem">?token=...</code> query parameter.</p>
                    <p style="margin-top:0.5rem"><strong>Production (system cron):</strong></p>
                    <pre style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem;overflow-x:auto;margin-top:0.25rem">* * * * * curl -sf "https://your-host/?action=run_checks&token=YOUR_TOKEN"
0 3 * * * curl -sf "https://your-host/?action=cleanup_checks&token=YOUR_TOKEN"</pre>
                    <p style="margin-top:0.5rem"><strong>Development (just):</strong></p>
                    <pre style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem;overflow-x:auto;margin-top:0.25rem">just cron          # foreground, every 60s
just cron 30       # foreground, every 30s
just cron background   # background, every 60s
just stop-cron     # stop background cron</pre>
                </div>
                <div class="help-section">
                    <h4>User-Agent</h4>
                    <p>Uptime identifies itself when checking sites using the User-Agent header: <code style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:0.125rem 0.375rem">AbtzUptimeCrawler/1.0.0</code>. You can allowlist this in your firewall or server configuration if needed.</p>
                </div>
                <div class="help-section">
                    <h4>Recovery Key</h4>
                    <p>On first setup, a recovery key is generated and shown once. Save it securely — it can replace your password if you forget it. After use, the key is rotated and you receive a new one. You must set a new password after logging in with the key.</p>
                </div>
                <div class="help-section">
                    <h4>Keyboard Shortcuts</h4>
                    <table class="help-table">
                        <tr><td><kbd>S</kbd></td><td>Sites</td></tr>
                        <tr><td><kbd>G</kbd></td><td>Groups</td></tr>
                        <tr><td><kbd>A</kbd></td><td>Account</td></tr>
                        <tr><td><kbd>⌘</kbd> <kbd>,</kbd></td><td>App Settings</td></tr>
                        <tr><td><kbd>⌘</kbd> <kbd>S</kbd></td><td>Save (in any form)</td></tr>
                        <tr><td><kbd>Esc</kbd></td><td>Close modal</td></tr>
                        <tr><td><kbd>?</kbd></td><td>Show this help</td></tr>
                    </table>
                    <p class="help-hint">On Windows/Linux, use <kbd>Ctrl</kbd> instead of <kbd>⌘</kbd>.</p>
                </div>
                <div class="help-section">
                    <h4>Version</h4>
                    <p class="help-version"><?= htmlspecialchars(APP_VERSION) ?></p>
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn" onclick="closeModal('help-modal')">Close</button>
            </div>
        </div>
    </div>

    <!-- Recovery Key Modal -->
    <div class="modal-overlay" id="recovery-modal">
        <div class="modal modal-md">
            <h3>Recovery Key</h3>
            <div class="rk-content">
                <p style="margin-bottom:1rem;font-size:0.875rem"><strong>Save this recovery key in a secure place.</strong><br>You can use it to log in if you forget your password.</p>
                <div class="recovery-key-display">
                    <code id="recovery-key-value"></code>
                    <button type="button" class="btn btn-sm rk-copy-btn" onclick="copyRecoveryKey()" title="Copy">
                        <svg id="rk-copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        <svg id="rk-check-icon" class="hidden" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    </button>
                </div>
                <p class="rk-warn">This key will not be shown again.</p>
                <div id="rk-password-field" class="rk-pw-field">
                    <div class="form-group">
                        <label for="rk-new-password">Set a new password</label>
                        <input type="password" id="rk-new-password" placeholder="Min. 6 characters" autocomplete="new-password" oninput="validateRkModal()">
                    </div>
                </div>
                <label class="rk-check">
                    <input type="checkbox" id="rk-saved-check" onchange="validateRkModal()"> I have saved this key
                </label>
            </div>
            <div class="form-actions form-actions-center">
                <button type="button" class="btn" id="rk-done-btn" disabled onclick="submitRkPassword()">Done</button>
            </div>
        </div>
    </div>

    <!-- Site Modal -->
    <div class="modal-overlay" id="site-modal">
        <div class="modal">
            <h3 id="site-modal-title">Add Site</h3>
            <div class="modal-tabs" id="site-modal-tabs">
                <button class="active" onclick="switchSiteTab('site')">Site</button>
                <button id="site-modal-webhooks-tab" class="hidden" onclick="switchSiteTab('webhooks')">Webhooks</button>
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
                        <input type="text" id="site-expected-keyword" placeholder="e.g. &quot;Welcome&quot; or &quot;OK&quot;">
                        <small style="color:var(--text-muted);margin-top:0.25rem;display:block">Case-insensitive plain text searched in the response body. Site is marked down if the text is not found. Does not support regex. Disabled for HEAD method (no body returned).</small>
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
                        <input type="checkbox" id="site-show-url" checked>
                        <label for="site-show-url">Show URL on status page</label>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="site-notify" checked>
                        <label for="site-notify">Send notifications</label>
                    </div>
                </form>
            </div>
            <div class="modal-tab" id="site-tab-webhooks">
                <div class="webhook-header">
                    <span class="webhook-label">Manage webhooks for this site</span>
                    <button type="button" class="btn btn-sm" onclick="toggleWebhookForm()">+ Add</button>
                </div>
                <div id="site-webhooks-list"></div>
                <div id="site-webhook-form" class="webhook-form hidden">
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
                    <div class="webhook-item-actions">
                        <button type="button" class="btn btn-sm" onclick="saveSiteWebhook()">Save</button>
                        <button type="button" class="btn btn-sm btn-gray" onclick="toggleWebhookForm()">Cancel</button>
                    </div>
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-gray" onclick="closeModal('site-modal')">Cancel</button>
                <button type="button" class="btn" id="site-modal-save-btn" data-modal-save>Save</button>
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
                    <button type="button" class="btn btn-gray" onclick="closeModal('group-modal')">Cancel</button>
                    <button type="submit" class="btn" data-modal-save>Save</button>
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
        let APP_STATUS = {};

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
            document.querySelectorAll('.nav-links button, .mobile-menu button').forEach(b => {
                b.classList.remove('active');
                if (b.textContent.trim().toLowerCase() === id) b.classList.add('active');
            });
            closeUserMenu();
            closeMobileMenu();
            history.replaceState(null, '', '#' + id);
            if (id === 'sites') loadSites();
            if (id === 'groups') loadGroups();
        }

        function showHelp() {
            document.getElementById('help-modal').classList.add('active');
        }

        let _rkPasswordReset = false;

        function showRecoveryKeyModal(key, passwordReset) {
            _rkPasswordReset = passwordReset;
            const formatted = key.replace(/(.{4})/g, '$1-').slice(0, -1).toUpperCase();
            document.getElementById('recovery-key-value').textContent = formatted;
            document.getElementById('rk-saved-check').checked = false;
            document.getElementById('rk-done-btn').disabled = true;
            const pwField = document.getElementById('rk-password-field');
            if (passwordReset) {
                pwField.style.display = '';
                document.getElementById('rk-new-password').value = '';
            } else {
                pwField.style.display = 'none';
            }
            document.getElementById('recovery-modal').classList.add('active');
        }

        function copyRecoveryKey() {
            const text = document.getElementById('recovery-key-value').textContent;
            navigator.clipboard.writeText(text).then(() => {
                document.getElementById('rk-copy-icon').classList.add('hidden');
                document.getElementById('rk-check-icon').classList.remove('hidden');
                setTimeout(() => {
                    document.getElementById('rk-check-icon').classList.add('hidden');
                    document.getElementById('rk-copy-icon').classList.remove('hidden');
                }, 2000);
            });
        }

        function validateRkModal() {
            const checked = document.getElementById('rk-saved-check').checked;
            if (_rkPasswordReset) {
                const pw = document.getElementById('rk-new-password').value;
                document.getElementById('rk-done-btn').disabled = !(checked && pw && pw.length >= 6);
            } else {
                document.getElementById('rk-done-btn').disabled = !checked;
            }
        }

        async function submitRkPassword() {
            if (_rkPasswordReset) {
                const pw = document.getElementById('rk-new-password').value;
                if (!pw || pw.length < 6) { showToast('Password must be at least 6 characters', 'error'); return; }
                const status = await api('auth_status');
                const res = await api('account_update', { name: status.user.name, email: status.user.email, password: pw }, 'POST');
                if (res.error) { showToast(res.error, 'error'); return; }
                showToast('Password updated');
            }
            closeModal('recovery-modal');
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
                const rawStatus = site.status || 'unknown';
                const status = rawStatus === 'unknown' && site.enabled ? 'scheduled' : rawStatus;
                html += `<tr>
                    <td><span class="status-badge ${status}">${status}</span></td>
                    <td>${escapeHtml(site.name)}</td>
                    <td class="hide-mobile"><a href="${escapeHtml(site.url)}" target="_blank" style="color:var(--text-muted)">${escapeHtml(site.url)}</a></td>
                    <td>${site.interval}s</td>
                    <td>
                        <button class="btn btn-sm btn-outlined" onclick="showChecks(${site.id}, '${escapeHtml(site.name)}')">Logs</button>
                        <button class="btn btn-sm btn-outlined" onclick="editSite(${site.id})">Edit</button>
                        <button class="btn btn-sm btn-outlined btn-outlined-danger" onclick="deleteSite(${site.id}, '${escapeHtml(site.name)}')">Delete</button>
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

        function toggleKeywordField(method) {
            const field = document.getElementById('site-expected-keyword');
            const isHead = method === 'HEAD';
            field.disabled = isHead;
            if (isHead) field.value = '';
        }

        document.getElementById('site-method').addEventListener('change', (e) => {
            toggleKeywordField(e.target.value);
        });

        function showSiteModal(site = null) {
            loadGroupOptions();
            document.getElementById('site-modal-title').textContent = site ? 'Edit Site' : 'Add Site';
            document.getElementById('site-id').value = site ? site.id : '';
            document.getElementById('site-name').value = site ? site.name : '';
            document.getElementById('site-url').value = site ? site.url : '';
            document.getElementById('site-method').value = site ? site.method : 'GET';
            document.getElementById('site-expected-status').value = site ? site.expected_status : 200;
            document.getElementById('site-expected-keyword').value = site ? site.expected_keyword : '';
            toggleKeywordField(document.getElementById('site-method').value);
            document.getElementById('site-timeout').value = site ? site.timeout : 10;
            document.getElementById('site-interval').value = site ? site.interval : 60;
            document.getElementById('site-group').value = site ? (site.group_id || '') : '';
            document.getElementById('site-enabled').checked = site ? !!site.enabled : true;
            document.getElementById('site-visible').checked = site ? !!site.visible : true;
            document.getElementById('site-show-url').checked = site ? !!parseInt(site.show_url) : true;
            document.getElementById('site-notify').checked = site ? !!site.notify : true;
            const whTab = document.getElementById('site-modal-webhooks-tab');
            if (site && site.id) {
                whTab.classList.remove('hidden');
                document.getElementById('site-webhook-form').classList.add('hidden');
                loadSiteWebhooks(site.id);
            } else {
                whTab.classList.add('hidden');
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

        let _checksSiteId = null;

        function getChecksPeriodParams() {
            const v = document.getElementById('checks-period').value;
            if (!v) return {};
            const now = new Date();
            let from;
            if (v === '1h') from = new Date(now - 3600000);
            else if (v === '6h') from = new Date(now - 21600000);
            else if (v === '24h') from = new Date(now - 86400000);
            else if (v === '7d') from = new Date(now - 604800000);
            else if (v === '30d') from = new Date(now - 2592000000);
            return { from: from.toISOString() };
        }

        async function loadChecksData() {
            if (!_checksSiteId) return;
            const params = { site_id: _checksSiteId, ...getChecksPeriodParams() };
            const checks = await api('list_checks', params);
            if (!checks.length) {
                document.getElementById('checks-content').innerHTML = '<div class="empty">No checks recorded yet.</div>';
                return;
            }
            renderChecks(checks);
        }

        function renderChecks(checks) {
            let html = '<table class="checks-table"><thead><tr><th>Time</th><th>Status</th><th>Code</th><th>Response</th><th>Message</th></tr></thead><tbody>';
            for (const c of checks) {
                const t = new Date(c.checked_at);
                const time = t.toLocaleString();
                html += `<tr>
                    <td>${time}</td>
                    <td><span class="status-badge ${c.status}">${c.status}</span></td>
                    <td>${c.status_code || '—'}</td>
                    <td>${c.response_time != null ? c.response_time + 'ms' : '—'}</td>
                    <td><code>${escapeHtml(c.message || 'Success')}</code></td>
                </tr>`;
            }
            html += '</tbody></table>';
            document.getElementById('checks-content').innerHTML = html;
        }

        async function showChecks(siteId, siteName) {
            _checksSiteId = siteId;
            document.getElementById('checks-modal-title').textContent = siteName + ' logs';
            document.getElementById('checks-period').value = '6h';
            document.getElementById('checks-content').innerHTML = '<div class="empty">Loading...</div>';
            document.getElementById('checks-modal').classList.add('active');
            await loadChecksData();
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
                show_url: document.getElementById('site-show-url').checked ? 1 : 0,
                notify: document.getElementById('site-notify').checked ? 1 : 0,
            };
            if (id) data.id = id;
            const res = await api(id ? 'update_site' : 'create_site', data, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            showToast(id ? 'Site updated' : 'Site created');
            closeModal('site-modal');
            loadSites();
        });

        document.getElementById('site-modal-save-btn').addEventListener('click', () => {
            if (document.getElementById('site-tab-site').classList.contains('active')) {
                document.getElementById('site-form').requestSubmit();
            } else {
                closeModal('site-modal');
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const active = document.querySelector('.modal-overlay.active');
                if (active && active.id !== 'recovery-modal') { closeModal(active.id); e.preventDefault(); }
            }
            if ((e.metaKey || e.ctrlKey) && e.key === 's') {
                const active = document.querySelector('.modal-overlay.active');
                if (active) {
                    e.preventDefault();
                    const saveBtn = active.querySelector('[data-modal-save]');
                    if (saveBtn) saveBtn.click();
                }
            }

            const tag = document.activeElement?.tagName;
            const isInput = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
            const modalOpen = document.querySelector('.modal-overlay.active');
            if (isInput || modalOpen) return;

            if (e.key === 's' || e.key === 'S') { showSection('sites'); return; }
            if (e.key === 'g' || e.key === 'G') { showSection('groups'); return; }
            if (e.key === 'a' || e.key === 'A') { showAccountModal(); return; }
            if (e.key === '?') { showHelp(); return; }
            if ((e.metaKey || e.ctrlKey) && e.key === ',') { e.preventDefault(); showSettingsModal(); }
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
                html += `<div class="webhook-item">
                    <div class="webhook-item-info">
                        <span class="webhook-item-type">${escapeHtml(h.type)}</span>
                        <span class="webhook-item-url">${escapeHtml(h.url)}</span>
                        <span class="webhook-item-events">${escapeHtml(h.events)}</span>
                    </div>
                    <div class="webhook-item-actions">
                        <button type="button" class="btn btn-sm" onclick="testSiteWebhook(${h.id}, this)" title="Test">Test</button>
                        <button type="button" class="btn btn-sm btn-danger" onclick="deleteSiteWebhook(${h.id})">Delete</button>
                    </div>
                </div>`;
            }
            container.innerHTML = html;
        }

        function toggleWebhookForm() {
            const form = document.getElementById('site-webhook-form');
            const isOpen = !form.classList.contains('hidden');
            form.classList.toggle('hidden');
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
                        <button class="btn btn-sm btn-outlined" onclick="editGroup(${group.id}, '${escapeHtml(group.name)}', ${group.position ?? 0})">Edit</button>
                        <button class="btn btn-sm btn-outlined btn-outlined-danger" onclick="deleteGroup(${group.id}, '${escapeHtml(group.name)}')">Delete</button>
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
            const res = await api(id ? 'update_group' : 'create_group', data, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            showToast(id ? 'Group updated' : 'Group created');
            closeModal('group-modal');
            loadGroups();
        });

        // ─── ACCOUNT ─────────────────────────────────────
        function switchAccountTab(tab) {
            document.querySelectorAll('#account-modal .modal-tabs button').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('#account-modal .modal-tab').forEach(t => t.classList.remove('active'));
            const btn = document.querySelector(`#account-modal .modal-tabs button[onclick*="${tab}"]`);
            if (btn) btn.classList.add('active');
            document.getElementById(`account-tab-${tab}`).classList.add('active');
        }

        async function loadAccount() {
            const status = await api('auth_status');
            const user = status.user;
            document.getElementById('account-profile-form').innerHTML = `
                <div class="form-group">
                    <label for="account-name">Name</label>
                    <input type="text" id="account-name" value="${escapeHtml(user.name)}">
                </div>
                <div class="form-group">
                    <label for="account-email">Email</label>
                    <input type="email" id="account-email" value="${escapeHtml(user.email)}">
                </div>
            `;
            document.getElementById('account-security-form').innerHTML = `
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
                <hr style="margin:1.25rem 0;border:none;border-top:1px solid var(--border)">
                <h4 style="margin-bottom:0.75rem;font-size:0.875rem;color:var(--text-muted)">Recovery Key</h4>
                <p style="font-size:0.875rem;color:var(--text-muted);margin-bottom:0.75rem">Generate a new recovery key. The old key will stop working immediately.</p>
                <div style="display:flex;gap:0.5rem;align-items:flex-end">
                    <div class="form-group" style="flex:1;margin-bottom:0">
                        <label for="account-rk-password">Current Password</label>
                        <input type="password" id="account-rk-password">
                    </div>
                    <button type="button" class="btn btn-sm" onclick="regenerateRecoveryKey()" style="height:38px;white-space:nowrap">Rotate Key</button>
                </div>
            `;
            switchAccountTab('profile');
            focusFirstInput('account-modal');
        }

        async function regenerateRecoveryKey() {
            const password = document.getElementById('account-rk-password').value;
            if (!password) { showToast('Password is required', 'error'); return; }
            const res = await api('regenerate_recovery_key', { password }, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            document.getElementById('account-rk-password').value = '';
            showRecoveryKeyModal(res.recovery_key, false);
        }

        async function saveAccount() {
            const status = await api('auth_status');
            const user = status.user;
            const nameEl = document.getElementById('account-name');
            const emailEl = document.getElementById('account-email');
            const name = nameEl ? nameEl.value : user.name;
            const email = emailEl ? emailEl.value : user.email;
            if (!name || !email) { showToast('Name and email are required', 'error'); return; }
            const current = document.getElementById('account-current-password').value;
            const newPw = document.getElementById('account-new-password').value;
            const confirmPw = document.getElementById('account-confirm-password').value;
            if (current || newPw || confirmPw) {
                if (!current || !newPw) { showToast('All password fields are required', 'error'); return; }
                if (newPw !== confirmPw) { showToast('Passwords do not match', 'error'); return; }
                if (newPw.length < 6) { showToast('Password must be at least 6 characters', 'error'); return; }
                const res = await api('account_update', { name, email, password: newPw, current_password: current }, 'POST');
                if (res.error) { showToast(res.error, 'error'); return; }
                showToast('Password updated');
            } else {
                const res = await api('account_update', { name, email }, 'POST');
                if (res.error) { showToast(res.error, 'error'); return; }
                showToast('Account updated');
            }
            closeModal('account-modal');
        }

        // ─── SETTINGS ────────────────────────────────────
        function switchSettingsTab(tab) {
            document.querySelectorAll('#settings-modal .modal-tabs button').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('#settings-modal .modal-tab').forEach(t => t.classList.remove('active'));
            const btn = document.querySelector(`#settings-modal .modal-tabs button[onclick*="${tab}"]`);
            if (btn) btn.classList.add('active');
            document.getElementById('settings-tab-' + tab).classList.add('active');
        }

        async function loadSettings() {
            const settings = await api('get_settings');
            if (!APP_STATUS.version) APP_STATUS = await api('auth_status');
            const container = document.getElementById('settings-form');

            document.getElementById('updates-section').innerHTML = `
                <div class="updates-current">Version: ${escapeHtml(APP_STATUS.version || '—')}</div>
                <div id="updates-info"></div>
                <button class="btn btn-sm btn-gray" onclick="checkForUpdates()" id="check-update-btn">Check for updates</button>
            `;

            container.innerHTML = `
                <div class="form-group">
                    <label for="settings-app-name">Status Page Title</label>
                    <input type="text" id="settings-app-name" value="${escapeHtml(settings.app_name || '')}">
                </div>
                <div class="form-group">
                    <label for="settings-retention">Retention (days)</label>
                    <input type="number" id="settings-retention" value="${settings.retention_days || 180}">
                </div>
            `;

            const automationContainer = document.getElementById('settings-automation-form');
            const cronToken = settings.cron_token || '';
            automationContainer.innerHTML = `
                <div class="form-group">
                    <label for="settings-cron-token">Cron Token</label>
                    <div style="display:flex;gap:0.5rem">
                        <input type="text" id="settings-cron-token" value="${escapeHtml(cronToken)}" readonly placeholder="Click Generate to create a token">
                        <button type="button" class="btn btn-sm btn-gray" onclick="generateCronToken()" style="white-space:nowrap">Generate</button>
                    </div>
                    <small style="color:var(--text-muted);margin-top:0.25rem;display:block">When set, <code>run_checks</code> and <code>cleanup_checks</code> endpoints require this token via <code>?token=...</code> query parameter.</small>
                </div>
                <div class="form-group">
                    <label>Cron Example</label>
                    <pre id="cron-example" style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem;overflow-x:auto;margin:0;line-height:1.6">* * * * * curl -sf "https://your-host/?action=run_checks&token=${cronToken || 'YOUR_TOKEN'}"
0 3 * * * curl -sf "https://your-host/?action=cleanup_checks&token=${cronToken || 'YOUR_TOKEN'}"</pre>
                </div>
            `;

            switchSettingsTab('general');
            focusFirstInput('settings-modal');
        }

        async function generateCronToken() {
            const res = await api('generate_cron_token', {}, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            document.getElementById('settings-cron-token').value = res.cron_token;
            const example = document.getElementById('cron-example');
            example.textContent = `* * * * * curl -sf "https://your-host/?action=run_checks&token=${res.cron_token}"\n0 3 * * * curl -sf "https://your-host/?action=cleanup_checks&token=${res.cron_token}"`;
            showToast('Cron token generated');
        }

        async function saveSettings() {
            const res = await api('update_settings', {
                app_name: document.getElementById('settings-app-name').value,
                retention_days: parseInt(document.getElementById('settings-retention').value),
            }, 'POST');
            if (res.error) { showToast(res.error, 'error'); return; }
            showToast('Settings saved');
            closeModal('settings-modal');
        }

        async function checkForUpdates() {
            const btn = document.getElementById('check-update-btn');
            const info = document.getElementById('updates-info');
            btn.disabled = true;
            btn.textContent = 'Checking...';
            info.innerHTML = '';

            const res = await api('check_update', {}, 'POST');
            btn.disabled = false;

            if (res.error) {
                btn.textContent = 'Check for updates';
                info.innerHTML = `<div class="updates-status" style="color:var(--red)">${escapeHtml(res.error)}</div>`;
                return;
            }

            APP_STATUS.version = res.current_version;
            APP_STATUS.update_available = res.update_available;

            const badge = document.getElementById('update-badge');
            if (res.update_available) {
                badge.classList.add('visible');
                btn.textContent = 'Check again';
                info.innerHTML = `
                    <div class="updates-status available">Update available: v${escapeHtml(res.latest_version)}</div>
                    <button class="btn btn-sm" style="margin-top:0.25rem" onclick="applyUpdate()">Apply update</button>
                `;
            } else {
                badge.classList.remove('visible');
                btn.textContent = 'Check again';
                info.innerHTML = `<div class="updates-status uptodate">Up to date</div>`;
            }
        }

        async function applyUpdate() {
            if (!confirm('Apply update? A backup of index.php will be created.')) return;

            const info = document.getElementById('updates-info');
            const btn = document.querySelector('#updates-info .btn');
            if (btn) { btn.disabled = true; btn.textContent = 'Applying...'; }

            const res = await api('apply_update', {}, 'POST');
            if (res.error) {
                showToast(res.error, 'error');
                if (btn) { btn.disabled = false; btn.textContent = 'Apply update'; }
                return;
            }

            showToast(`Updated from v${res.previous_version} to v${res.new_version}`);
            setTimeout(() => location.reload(), 1500);
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
                document.querySelector('#confirm-modal .btn-gray').onclick = () => {
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

        // Show recovery key modal if present in sessionStorage
        const rk = sessionStorage.getItem('rk');
        if (rk) {
            const rkReset = sessionStorage.getItem('rk_reset') === '1';
            sessionStorage.removeItem('rk');
            sessionStorage.removeItem('rk_reset');
            showRecoveryKeyModal(rk, rkReset);
        }

        (async () => {
            APP_STATUS = await api('auth_status');
            const badge = document.getElementById('update-badge');
            if (APP_STATUS.update_available) badge.classList.add('visible');
        })();

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
    $db = getDb();

    // Check for updates: clear flag if local version already matches latest
    $updateAvailable = false;
    $latestVersionRow = $db->query("SELECT value FROM settings WHERE key = 'latest_version'")->fetch();
    if ($latestVersionRow && $latestVersionRow['value']) {
        if (version_compare(APP_VERSION, $latestVersionRow['value'], '>=')) {
            $db->exec("DELETE FROM settings WHERE key = 'update_available'");
        } else {
            $flag = $db->query("SELECT value FROM settings WHERE key = 'update_available'")->fetch();
            $updateAvailable = $flag && $flag['value'] === '1';
        }
    }

    jsonResponse([
        'needs_setup' => needsSetup(),
        'authenticated' => isAuthenticated(),
        'user' => getCurrentUser(),
        'csrf_token' => $_SESSION['csrf_token'] ?? '',
        'version' => APP_VERSION,
        'update_available' => $updateAvailable,
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

    $recoveryKey = rotateRecoveryKey($userId);

    session_regenerate_id(true);
    $_SESSION['user_id'] = $userId;
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));

    jsonResponse(['ok' => true, 'csrf_token' => $_SESSION['csrf_token'], 'recovery_key' => $recoveryKey]);
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
    $stmt = $db->prepare("SELECT id, password_hash, recovery_key_hash FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if (!$user) {
        recordFailedAttempt();
        jsonResponse(['error' => 'Invalid email or password'], 403);
    }

    $response = ['ok' => true];
    $passwordResetRequired = false;

    if (!password_verify($password, $user['password_hash'])) {
        $candidateHash = hash('sha256', str_replace('-', '', strtolower(trim($password))));
        if ($user['recovery_key_hash'] && hash_equals($user['recovery_key_hash'], $candidateHash)) {
            $response['recovery_key'] = rotateRecoveryKey($user['id']);
            $passwordResetRequired = true;
        } else {
            recordFailedAttempt();
            jsonResponse(['error' => 'Invalid email or password'], 403);
        }
    } elseif (!$user['recovery_key_hash']) {
        $response['recovery_key'] = rotateRecoveryKey($user['id']);
    }

    clearAttempts();
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    if ($passwordResetRequired) {
        $_SESSION['password_reset_required'] = true;
        $response['password_reset'] = true;
    }
    $response['csrf_token'] = $_SESSION['csrf_token'];
    jsonResponse($response);
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
        if (!$currentPassword && !empty($_SESSION['password_reset_required'])) {
            // Recovery-key login: allow password change without current password
        } else {
            $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
            $stmt->execute([$user['id']]);
            $row = $stmt->fetch();
            if (!password_verify($currentPassword, $row['password_hash'])) {
                jsonResponse(['error' => 'Current password is incorrect'], 403);
            }
        }
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $db->prepare("UPDATE users SET name = ?, email = ?, password_hash = ? WHERE id = ?")->execute([$name, $email, $hash, $user['id']]);
        unset($_SESSION['password_reset_required']);
    } else {
        $db->prepare("UPDATE users SET name = ?, email = ? WHERE id = ?")->execute([$name, $email, $user['id']]);
    }

    jsonResponse(['ok' => true]);
}

function apiRegenerateRecoveryKey(): void {
    requireAuth();
    $user = getCurrentUser();
    $input = getInput();
    $password = $input['password'] ?? '';

    if (!$password) {
        jsonResponse(['error' => 'Password is required'], 400);
    }

    $db = getDb();
    $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $row = $stmt->fetch();

    if (!password_verify($password, $row['password_hash'])) {
        jsonResponse(['error' => 'Invalid password'], 403);
    }

    jsonResponse(['ok' => true, 'recovery_key' => rotateRecoveryKey($user['id'])]);
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

    $method = $input['method'] ?? 'GET';

    $db = getDb();
    $stmt = $db->prepare("INSERT INTO sites (name, url, method, expected_status, expected_keyword, timeout, interval, group_id, enabled, visible, notify, show_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([
        $name,
        $url,
        $method,
        $input['expected_status'] ?? 200,
        $method === 'HEAD' ? '' : ($input['expected_keyword'] ?? ''),
        $input['timeout'] ?? 10,
        $input['interval'] ?? 60,
        ($input['group_id'] ?? null) ?: null,
        $input['enabled'] ?? 1,
        $input['visible'] ?? 1,
        $input['notify'] ?? 1,
        $input['show_url'] ?? 1,
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

    if (($input['method'] ?? '') === 'HEAD') {
        $input['expected_keyword'] = '';
    }

    $db = getDb();
    $fields = [];
    $params = [];

    foreach (['name', 'url', 'method', 'expected_status', 'expected_keyword', 'timeout', 'interval', 'group_id', 'enabled', 'visible', 'notify', 'show_url'] as $field) {
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
    verifyCronToken();
    $result = runChecks();
    $cleanup = cleanupChecks();
    $result['cleaned'] = $cleanup['deleted'];
    jsonResponse($result);
}

function apiListChecks(): void {
    requireAuth();
    $siteId = (int) ($_GET['site_id'] ?? 0);
    if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);

    $sql = "SELECT * FROM checks WHERE site_id = ?";
    $params = [$siteId];

    if (!empty($_GET['from'])) {
        $sql .= " AND checked_at >= ?";
        $params[] = $_GET['from'];
    }
    if (!empty($_GET['to'])) {
        $sql .= " AND checked_at <= ?";
        $params[] = $_GET['to'];
    }

    $sql .= " ORDER BY checked_at DESC LIMIT 500";

    $db = getDb();
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
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
        SELECT s.id, s.name, s.url, s.group_id, s.visible, s.enabled, s.show_url,
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

        if (!(int) $site['show_url']) {
            unset($site['url']);
        }
        unset($site['show_url']);
    }
    unset($site);

    // Per-group uptime (24h average of grouped sites)
    foreach ($groups as &$group) {
        $groupSiteIds = array_column(array_filter($sites, fn($s) => (int)($s['group_id'] ?? 0) === (int)$group['id']), 'id');
        $group['uptime_24h'] = null;
        $group['status'] = 'unknown';
        if ($groupSiteIds) {
            $ph = implode(',', array_fill(0, count($groupSiteIds), '?'));
            $total = $db->prepare("SELECT COUNT(*) as cnt FROM checks WHERE site_id IN ($ph) AND checked_at > datetime('now', '-24 hours')");
            $total->execute($groupSiteIds);
            $totalCount = (int) $total->fetch()['cnt'];
            if ($totalCount > 0) {
                $up = $db->prepare("SELECT COUNT(*) as cnt FROM checks WHERE site_id IN ($ph) AND status = 'up' AND checked_at > datetime('now', '-24 hours')");
                $up->execute($groupSiteIds);
                $pct = round(((int) $up->fetch()['cnt'] / $totalCount) * 100, 1);
                $group['uptime_24h'] = $pct;
                if ($pct >= 85) $group['status'] = 'operational';
                elseif ($pct >= 20) $group['status'] = 'degraded';
                elseif ($pct >= 1) $group['status'] = 'severely_degraded';
                else $group['status'] = 'down';
            }
        }
    }
    unset($group);

    // Overall uptime across multiple time windows
    $siteIds = array_column($sites, 'id');
    $overall = ['uptime_24h' => null, 'uptime_7d' => null, 'uptime_30d' => null, 'uptime_90d' => null, 'status' => 'unknown'];
    if ($siteIds) {
        $placeholders = implode(',', array_fill(0, count($siteIds), '?'));
        $windows = ['24h' => '-24 hours', '7d' => '-7 days', '30d' => '-30 days', '90d' => '-90 days'];
        foreach ($windows as $key => $interval) {
            $total = $db->prepare("SELECT COUNT(*) as cnt FROM checks WHERE site_id IN ($placeholders) AND checked_at > datetime('now', ?)");
            $total->execute(array_merge($siteIds, [$interval]));
            $totalCount = (int) $total->fetch()['cnt'];
            if ($totalCount > 0) {
                $up = $db->prepare("SELECT COUNT(*) as cnt FROM checks WHERE site_id IN ($placeholders) AND status = 'up' AND checked_at > datetime('now', ?)");
                $up->execute(array_merge($siteIds, [$interval]));
                $overall["uptime_$key"] = round(((int) $up->fetch()['cnt'] / $totalCount) * 100, 3);
            }
        }

        $pct = $overall['uptime_24h'];
        if ($pct === null) {
            $overall['status'] = 'unknown';
        } elseif ($pct >= 85) {
            $overall['status'] = 'operational';
        } elseif ($pct >= 20) {
            $overall['status'] = 'degraded';
        } elseif ($pct >= 1) {
            $overall['status'] = 'severely_degraded';
        } else {
            $overall['status'] = 'down';
        }
    }

    jsonResponse(['groups' => $groups, 'sites' => $sites, 'overall' => $overall]);
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

    $protected = ['cron_token'];
    foreach ($input as $key => $value) {
        if (in_array($key, $protected)) continue;
        $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")->execute([$key, $value]);
    }
    jsonResponse(['ok' => true]);
}

function apiGenerateCronToken(): void {
    requireAuth();
    $token = generateToken(32);
    setSetting('cron_token', $token);
    jsonResponse(['cron_token' => $token]);
}

// ============================================================================
// API: UPDATES
// ============================================================================

function apiCheckUpdate(): void {
    requireAuth();
    $db = getDb();

    // Return cached result if checked within 24h
    $lastCheck = $db->query("SELECT value FROM settings WHERE key = 'last_update_check_at'")->fetch();
    if ($lastCheck && $lastCheck['value']) {
        $lastTime = strtotime($lastCheck['value']);
        if ($lastTime && (time() - $lastTime) < 86400) {
            $latest = $db->query("SELECT value FROM settings WHERE key = 'latest_version'")->fetch();
            $flag = $db->query("SELECT value FROM settings WHERE key = 'update_available'")->fetch();
            jsonResponse([
                'update_available' => $flag && $flag['value'] === '1',
                'latest_version' => $latest ? $latest['value'] : APP_VERSION,
                'current_version' => APP_VERSION,
                'last_checked' => $lastCheck['value'],
            ]);
        }
    }

    // Fetch from GitHub
    $ctx = stream_context_create(['http' => [
        'method' => 'GET',
        'header' => "User-Agent: Uptime/" . APP_VERSION . "\r\n",
        'timeout' => 10,
        'ignore_errors' => true,
    ]]);
    $content = @file_get_contents(GITHUB_RAW_URL, false, $ctx);
    if ($content === false) {
        jsonResponse(['error' => 'Failed to fetch update info'], 502);
    }

    // Parse version
    if (!preg_match("/define\('APP_VERSION',\s*'([^']+)'\)/", $content, $m)) {
        jsonResponse(['error' => 'Invalid remote version format'], 502);
    }
    $latestVersion = $m[1];
    $available = version_compare(APP_VERSION, $latestVersion, '<');

    $now = date('c');
    setSetting('latest_version', $latestVersion);
    setSetting('update_available', $available ? '1' : '0');
    setSetting('last_update_check_at', $now);
    setSetting('latest_content', $content);

    jsonResponse([
        'update_available' => $available,
        'latest_version' => $latestVersion,
        'current_version' => APP_VERSION,
        'last_checked' => $now,
    ]);
}

function apiApplyUpdate(): void {
    requireAuth();
    $db = getDb();

    // Read cached content
    $contentRow = $db->query("SELECT value FROM settings WHERE key = 'latest_content'")->fetch();
    if (!$contentRow || !$contentRow['value']) {
        jsonResponse(['error' => 'No update cached. Run check_update first.'], 400);
    }
    $content = $contentRow['value'];

    // Sanity check
    if (!preg_match("/define\('APP_VERSION',\s*'([^']+)'\)/", $content, $m) || empty($m[1])) {
        jsonResponse(['error' => 'Cached content is invalid'], 400);
    }
    $newVersion = $m[1];
    if ($newVersion === APP_VERSION) {
        jsonResponse(['error' => 'Already up to date'], 400);
    }

    // Backup current file
    $bakPath = __DIR__ . '/index.php.bak';
    if (!copy(__DIR__ . '/index.php', $bakPath)) {
        jsonResponse(['error' => 'Failed to create backup'], 500);
    }

    // Write new content
    $previousVersion = APP_VERSION;
    if (file_put_contents(__DIR__ . '/index.php', $content) === false) {
        // Restore from backup
        @copy($bakPath, __DIR__ . '/index.php');
        jsonResponse(['error' => 'Failed to write update. Restored from backup.'], 500);
    }

    // Clear update state
    $db->exec("DELETE FROM settings WHERE key IN ('update_available', 'latest_content')");

    jsonResponse([
        'ok' => true,
        'previous_version' => $previousVersion,
        'new_version' => $newVersion,
    ]);
}

// ============================================================================
// API: CLEANUP
// ============================================================================

function apiCleanupChecks(): void {
    verifyCronToken();
    $result = cleanupChecks();
    jsonResponse($result);
}
