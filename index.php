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
    if (
      preg_match('/\.(sqlite|sqlite3|db|sql|env|htaccess|htpasswd)$/i', $uri)
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
define('APP_VERSION', '0.2.0');
define('CRAWLER_VERSION', '1.0.0');
define('DB_FILE', getenv('UPTIME_DB_FILE') ?: __DIR__ . '/uptime.sqlite');
define('DEFAULT_RETENTION_DAYS', 180);
define('GITHUB_RAW_URL', 'https://raw.githubusercontent.com/Abtz-Labs/uptime/main/index.php');

// ============================================================================
// DATABASE SETUP
// ============================================================================

function getDb(): PDO
{
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

function initDatabase(): void
{
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
            position INTEGER NOT NULL DEFAULT 0,
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
            events TEXT DEFAULT 'down,up',
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

function migrateDatabase(PDO $db): void
{
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

  // Version 4 → 5: position column on sites
  if ($version < 5) {
    $cols = $db->query("PRAGMA table_info(sites)")->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array('position', $cols)) {
      $db->exec("ALTER TABLE sites ADD COLUMN position INTEGER NOT NULL DEFAULT 0");
      $db->exec("UPDATE sites SET position = id");
    }
  }

  // Version 5 → 6: Telegram fields on webhooks
  if ($version < 6) {
    $cols = $db->query("PRAGMA table_info(webhooks)")->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array('bot_token', $cols)) {
      $db->exec("ALTER TABLE webhooks ADD COLUMN bot_token TEXT");
    }
    if (!in_array('chat_id', $cols)) {
      $db->exec("ALTER TABLE webhooks ADD COLUMN chat_id TEXT");
    }
    if (!in_array('message_template', $cols)) {
      $db->exec("ALTER TABLE webhooks ADD COLUMN message_template TEXT");
    }
  }

  // Version 6 → 7: Incidents and incident updates tables
  if ($version < 7) {
    if (!$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'")->fetch()) {
      $db->exec("
                CREATE TABLE incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ongoing',
                    started_at TEXT NOT NULL DEFAULT (datetime('now')),
                    resolved_at TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            ");
      $db->exec("CREATE INDEX idx_incidents_status ON incidents(status, resolved_at)");
    }
    if (!$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='incident_updates'")->fetch()) {
      $db->exec("
                CREATE TABLE incident_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                )
            ");
      $db->exec("CREATE INDEX idx_incident_updates_incident ON incident_updates(incident_id)");
    }
  }

  // Version 7 → 8: Migrate webhook events from 'recover' to 'up'
  if ($version < 8) {
    $db->exec("UPDATE webhooks SET events = REPLACE(events, 'recover', 'up') WHERE events LIKE '%recover%'");
  }

  $db->exec('PRAGMA user_version = 8');
}

function rotateRecoveryKey(int $userId): string
{
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
if (
  preg_match('/\.(sqlite|sqlite3|db|sql)$/i', $requestPath)
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

function verifyCsrf(): void
{
  $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
  if (!$token || !hash_equals($_SESSION['csrf_token'], $token)) {
    jsonResponse(['error' => 'Invalid CSRF token'], 403);
  }
}

function verifyCronToken(): void
{
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

function jsonResponse(mixed $data, int $status = 200): never
{
  http_response_code($status);
  header('Content-Type: application/json');
  echo json_encode($data);
  exit;
}

function getInput(): array
{
  $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
  if (str_contains($contentType, 'application/json')) {
    return json_decode(file_get_contents('php://input'), true) ?? [];
  }
  return $_POST;
}

function generateToken(int $length = 32): string
{
  return bin2hex(random_bytes($length / 2));
}

function setSetting(string $key, string $value): void
{
  getDb()->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
    ->execute([$key, $value]);
}

function hasUsers(): bool
{
  $db = getDb();
  $stmt = $db->query("SELECT COUNT(*) as cnt FROM users");
  return (int) $stmt->fetch()['cnt'] > 0;
}

function needsSetup(): bool
{
  return !hasUsers();
}

function getCurrentUser(): ?array
{
  $userId = $_SESSION['user_id'] ?? null;
  if (!$userId) return null;
  $db = getDb();
  $stmt = $db->prepare("SELECT id, name, email FROM users WHERE id = ?");
  $stmt->execute([$userId]);
  return $stmt->fetch() ?: null;
}

function isAuthenticated(): bool
{
  return getCurrentUser() !== null;
}

function requireAuth(): void
{
  if (!isAuthenticated()) {
    jsonResponse(['error' => 'Unauthorized'], 401);
  }
}

function getClientIp(): string
{
  return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function checkRateLimit(): void
{
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

function recordFailedAttempt(): void
{
  $db = getDb();
  $db->prepare("INSERT INTO login_attempts (ip) VALUES (?)")->execute([getClientIp()]);
}

function clearAttempts(): void
{
  $db = getDb();
  $db->prepare("DELETE FROM login_attempts WHERE ip = ?")->execute([getClientIp()]);
}

// ============================================================================
// NOTIFICATIONS
// ============================================================================

function sendNotifications(int $siteId, string $event, string $siteName, string $siteUrl, ?string $message = null): void
{
  $db = getDb();
  $stmt = $db->prepare("SELECT * FROM webhooks WHERE enabled = 1 AND site_id = ?");
  $stmt->execute([$siteId]);
  $hooks = $stmt->fetchAll();
  if (!$hooks) return;

  foreach ($hooks as $hook) {
    // Check if this webhook subscribes to this event
    $events = array_map('trim', explode(',', $hook['events']));
    if (!in_array($event, $events)) continue;

    $body = formatWebhookPayload($hook['type'], $event, $siteName, $siteUrl, $message, $hook['bot_token'] ?? null, $hook['chat_id'] ?? null, $hook['message_template'] ?? null);
    $url = $hook['type'] === 'telegram' && !empty($hook['bot_token'])
      ? "https://api.telegram.org/bot{$hook['bot_token']}/sendMessage"
      : $hook['url'];
    sendWebhook($url, $body);
  }

  // Update last_notified_at
  $db->prepare("UPDATE site_status SET last_notified_at = datetime('now') WHERE site_id = ?")->execute([$siteId]);
}

function formatWebhookPayload(string $hookType, string $event, string $siteName, string $siteUrl, ?string $message, ?string $botToken = null, ?string $chatId = null, ?string $messageTemplate = null): string
{
  $genericPayload = json_encode([
    'event' => $event,
    'site' => $siteName,
    'url' => $siteUrl,
    'message' => $message,
    'timestamp' => date('c'),
  ]);

  $escapeMd = fn(string $s) => preg_replace('/([_*\[\]()~`>#+\-=|{}.!\\\\])/', '\\\\$1', $s);

  $replaceTemplate = function (?string $tpl) use ($event, $siteName, $siteUrl, $message, $escapeMd) {
    if (!$tpl) return "$event: $siteName is $message ($siteUrl)";
    $replacements = [
      'event' => $escapeMd($event),
      'site_name' => $escapeMd($siteName),
      'url' => $escapeMd($siteUrl),
      'message' => $escapeMd($message ?? ''),
      'timestamp' => $escapeMd(date('c')),
    ];
    return preg_replace_callback('/\{\{\s*(\w+)\s*\}\}/', function ($m) use ($replacements) {
      $key = $m[1];
      return $replacements[$key] ?? $m[0];
    }, $tpl);
  };

  return match ($hookType) {
    'slack' => json_encode(['text' => $replaceTemplate($messageTemplate)]),
    'telegram' => $chatId
      ? json_encode([
        'chat_id' => $chatId,
        'text' => $replaceTemplate($messageTemplate),
        'parse_mode' => 'MarkdownV2',
      ])
      : $genericPayload,
    default => $genericPayload,
  };
}

function sendWebhook(string $url, string $body): void
{
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

function runChecks(): array
{
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
      $event = $result['status'] === 'down' ? 'down' : 'up';

      // Always notify on recovery (DOWN→UP); apply cooldown only for repeated DOWN alerts
      $shouldNotify = true;
      if ($event === 'down') {
        $notified = $db->prepare("SELECT last_notified_at FROM site_status WHERE site_id = ?");
        $notified->execute([$site['id']]);
        $notifiedRow = $notified->fetch();
        if ($notifiedRow && $notifiedRow['last_notified_at']) {
          $lastNotified = strtotime($notifiedRow['last_notified_at']);
          if ((time() - $lastNotified) < 300) {
            $shouldNotify = false;
          }
        }
      }

      if ($shouldNotify) {
        sendNotifications($site['id'], $event, $site['name'], $site['url'], $result['message']);
      }
    }

    $checked++;
  }

  return ['checked' => $checked];
}

function checkSite(array $site): array
{
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

function cleanupChecks(): array
{
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
    'reorder_sites' => apiReorderSites(),

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

    // Incidents
    'list_incidents' => apiListIncidents(),
    'create_incident' => apiCreateIncident(),
    'update_incident' => apiUpdateIncident(),
    'delete_incident' => apiDeleteIncident(),
    'create_incident_update' => apiCreateIncidentUpdate(),
    'update_incident_update' => apiUpdateIncidentUpdate(),
    'delete_incident_update' => apiDeleteIncidentUpdate(),

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

    // Health
    'health_check' => apiHealthCheck(),

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

function serveStatusPage(): void
{
  $db = getDb();
  $appNameRow = $db->query("SELECT value FROM settings WHERE key = 'app_name'")->fetch();
  $appName = ($appNameRow && $appNameRow['value']) ? $appNameRow['value'] : APP_NAME;
?>
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%23434C5E'/><text x='16' y='22' font-family='sans-serif' font-size='14' font-weight='bold' fill='%23ECEFF4' text-anchor='middle'>UP</text></svg>">
    <title><?= htmlspecialchars($appName) ?> — Status</title>
    <style>
      :root {
        --bg: #2E3440;
        --surface: #3B4252;
        --border: #434C5E;
        --text: #ECEFF4;
        --text-muted: #D8DEE9;
        --green: #4ADE80;
        --red: #BF616A;
        --red-dark: #A05058;
        --amber: #FBBF24;
        --orange: #F97316;
        --gray: #4C566A;
        --blue: #81A1C1;
        --radius: 8px;
      }

      .light {
        --bg: #ECEFF4;
        --surface: #ffffff;
        --border: #D8DEE9;
        --text: #2E3440;
        --text-muted: #4C566A;
        --primary: #5E81AC;
        --primary-hover: #81A1C1;
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg);
        color: var(--text);
        min-height: 100vh;
        padding: 1rem;
        display: flex;
        flex-direction: column;
      }

      .container {
        max-width: 800px;
        margin: 0 auto;
        flex: 1;
        width: 100%;
        display: flex;
        flex-direction: column;
      }

      .header {
        text-align: center;
        padding: 2rem 0;
        position: relative;
      }

      .header h1 {
        font-size: 1.5rem;
        font-weight: 600;
      }

      .header .subtitle {
        color: var(--text-muted);
        font-size: 0.875rem;
        margin-top: 0.5rem;
      }

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

      .theme-toggle:hover {
        opacity: 0.8;
      }

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

      .site:last-child {
        border-bottom: none;
      }

      .status-dot {
        width: 12px;
        height: 12px;
        border-radius: 50%;
        flex-shrink: 0;
      }

      .status-dot.up,
      .status-dot.operational {
        background: var(--green);
      }

      .status-dot.down {
        background: var(--red-dark);
      }

      .status-dot.unknown {
        background: var(--gray);
      }

      .status-dot.scheduled {
        background: var(--blue);
      }

      .status-dot.degraded {
        background: var(--amber);
      }

      .status-dot.severely_degraded {
        background: var(--orange);
      }

      .status-dot.mostly_down {
        background: var(--red);
      }

      .site-info {
        flex: 1;
        min-width: 0;
      }

      .site-name {
        font-weight: 500;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .site-name a {
        color: inherit;
        text-decoration: none;
      }

      .site-name a:hover {
        text-decoration: underline;
      }

      .site-url {
        color: var(--text-muted);
        font-size: 0.75rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .site-meta {
        text-align: right;
        flex-shrink: 0;
      }

      .site-response {
        font-size: 0.875rem;
        font-variant-numeric: tabular-nums;
      }

      .site-time {
        color: var(--text-muted);
        font-size: 0.75rem;
      }

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

      .timeline-bar.up {
        background: var(--green);
      }

      .timeline-bar.degraded {
        background: var(--amber);
      }

      .timeline-bar.down {
        background: var(--red-dark);
      }

      .timeline-bar.mostly_down {
        background: var(--red);
      }

      .timeline-bar.unknown {
        background: var(--border);
      }

      .timeline-bar.scheduled {
        background: var(--blue);
      }

      .timeline-labels {
        display: flex;
        justify-content: space-between;
        font-size: 0.6875rem;
        color: var(--text-muted);
        margin-top: 0.25rem;
      }

      .uptime-pct {
        font-size: 0.75rem;
        color: var(--text-muted);
        text-align: center;
      }

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

      .overall-status-icon.operational {
        background: var(--green);
      }

      .overall-status-icon.degraded {
        background: var(--amber);
      }

      .overall-status-icon.severely_degraded {
        background: var(--orange);
      }

      .overall-status-icon.down {
        background: var(--red-dark);
      }

      .overall-status-icon.mostly_down {
        background: var(--red);
      }

      .overall-status-icon.unknown {
        background: var(--gray);
      }

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
        .overall-uptime {
          grid-template-columns: repeat(4, 1fr);
        }
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

      .incidents-section {
        margin: 1.5rem 0;
      }

      .incidents-header {
        font-size: 0.875rem;
        font-weight: 600;
        color: var(--text);
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.375rem;
      }

      .incident-card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 1rem;
        margin-bottom: 0.75rem;
      }

      .incident-card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.5rem;
      }

      .incident-card-title {
        font-weight: 600;
        font-size: 0.875rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .incident-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        flex-shrink: 0;
      }

      .incident-badge {
        font-size: 0.6875rem;
        font-weight: 600;
        color: var(--text);
        padding: 0.125rem 0.5rem;
        border-radius: 9999px;
        white-space: nowrap;
        text-transform: uppercase;
        letter-spacing: 0.025em;
      }

      .incident-card-meta {
        font-size: 0.75rem;
        color: var(--text-muted);
        margin-top: 0.375rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.5rem;
      }

      .incident-chevron-wrap {
        cursor: pointer;
        padding: 0.125rem;
        border-radius: 4px;
        display: flex;
        align-items: center;
      }

      .incident-chevron-wrap:hover {
        background: var(--border);
      }

      .incident-updates {
        margin-top: 0.75rem;
        padding-top: 0.5rem;
        border-top: 1px solid var(--border);
        display: none;
      }

      .incident-card.expanded .incident-updates {
        display: block;
      }

      .incident-card.expanded .incident-latest-update {
        display: none;
      }

      .incident-latest-update {
        display: flex;
        gap: 0.75rem;
        margin-top: 0.5rem;
        padding-top: 0.5rem;
        border-top: 1px solid var(--border);
        font-size: 0.8125rem;
        line-height: 1.4;
      }

      .incident-chevron {
        transition: transform 0.2s;
        color: var(--text-muted);
        flex-shrink: 0;
      }

      .incident-card.expanded .incident-chevron {
        transform: rotate(180deg);
      }

      .incident-update-row {
        display: flex;
        gap: 0.75rem;
        padding: 0.25rem 0;
        font-size: 0.8125rem;
        line-height: 1.4;
      }

      .incident-update-time {
        color: var(--text-muted);
        font-size: 0.75rem;
        white-space: nowrap;
        min-width: 3.5rem;
      }

      .incidents-history-toggle {
        font-size: 0.875rem;
        font-weight: 500;
        color: var(--text-muted);
        cursor: pointer;
        padding: 0.5rem 0;
      }

      .incidents-history-toggle:hover {
        color: var(--text);
      }

      .incidents-history-content {
        display: none;
      }

      .incidents-section.expanded .incidents-history-content {
        display: block;
      }

      .incidents-section.expanded .history-chevron {
        transform: rotate(90deg);
      }

      .empty {
        text-align: center;
        padding: 3rem;
        color: var(--text-muted);
      }

      .footer {
        text-align: center;
        padding: 2rem 0 0;
        color: var(--text-muted);
        font-size: 0.75rem;
        margin-top: auto;
      }

      .footer a {
        color: var(--text);
      }

      .footer a:hover {
        color: var(--primary);
      }

      .footer p+div {
        margin-top: 1.5rem;
      }

      .footer p+p {
        margin-top: 0.5rem;
      }

      @media (min-width: 768px) {
        body {
          padding: 2rem;
        }

        .header h1 {
          font-size: 2rem;
        }
      }
    </style>
  </head>

  <body>
    <div class="container">
      <div class="header">
        <h1><?= htmlspecialchars($appName) ?></h1>
        <div class="subtitle">System Status</div>
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2" />
            <path d="M12 20v2" />
            <path d="m4.93 4.93 1.41 1.41" />
            <path d="m17.66 17.66 1.41 1.41" />
            <path d="M2 12h2" />
            <path d="M20 12h2" />
            <path d="m6.34 17.66-1.41 1.41" />
            <path d="m19.07 4.93-1.41 1.41" />
          </svg>
        </button>
      </div>
      <div id="status-content">
        <div class="empty">Loading...</div>
      </div>
      <div class="footer">
        <p>
          Last updated: <span id="last-updated">—</span> · Refresh in <span id="countdown">30</span>s
        </p>
        <div>
          <p>Powered by <a href="https://github.com/Abtz-Labs/uptime" target="_blank" rel="noopener noreferrer">Uptime</a> &mdash; <a href="https://github.com/Abtz-Labs/uptime/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">O'SAASy</a> Licensed</p>
          <p>#<?= APP_VERSION ?> &copy; Abtz Labs.</p>
        </div>
      </div>
    </div>
    <script>
      function fmtDate(utcStr) {
        if (!utcStr) return '—';
        const d = new Date(utcStr + 'Z');
        return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
      }

      function fmtTime(utcStr) {
        if (!utcStr) return '';
        const d = new Date(utcStr + 'Z');
        return d.toISOString().slice(11, 16) + ' UTC';
      }

      function toggleIncident(id) {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.toggle('expanded');
        const key = '_expanded';
        const set = JSON.parse(sessionStorage.getItem(key) || '[]');
        if (el.classList.contains('expanded')) {
          if (!set.includes(id)) set.push(id);
        } else {
          const idx = set.indexOf(id);
          if (idx > -1) set.splice(idx, 1);
        }
        sessionStorage.setItem(key, JSON.stringify(set));
      }

      function toggleHistory(el) {
        el.parentElement.classList.toggle('expanded');
        const key = '_history_expanded';
        sessionStorage.setItem(key, el.parentElement.classList.contains('expanded') ? '1' : '');
      }

      function restoreExpandedState() {
        const set = JSON.parse(sessionStorage.getItem('_expanded') || '[]');
        for (const id of set) {
          const el = document.getElementById(id);
          if (el) el.classList.add('expanded');
        }
        if (sessionStorage.getItem('_history_expanded')) {
          const hist = document.querySelector('.incidents-section:has(.incidents-history-toggle)');
          if (hist) hist.classList.add('expanded');
        }
      }

      async function loadStatus() {
        try {
          const res = await fetch('/?action=status_page');
          const data = await res.json();
          renderStatus(data);
          restoreExpandedState();
          document.getElementById('last-updated').textContent = new Date().toISOString().slice(11, 19) + ' UTC';
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
            mostly_down: 'Mostly Down',
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

        // Render active incidents (ongoing/observation) — above sites
        const incidents = data.incidents || [];
        if (incidents.length > 0) {
          html += `<div class="incidents-section">`;
          html += `<div class="incidents-header"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg> Incidents</div>`;
          for (const inc of incidents) {
            html += renderIncidentCard(inc, 'latest');
          }
          html += `</div>`;
        }

        // Render grouped sites
        for (const group of groups) {
          const groupSites = sites.filter(s => s.group_id == group.id);
          if (groupSites.length === 0) continue;

          const gUptime = group.uptime_24h !== null ? group.uptime_24h.toFixed(1) + '% Uptime' : '';
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

        // Render recently resolved — below sites
        const recentResolved = data.recent_resolved || [];
        if (recentResolved.length > 0) {
          html += `<div class="incidents-section">`;
          html += `<div class="incidents-header" style="color:var(--text-muted)"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><polyline points="20 6 9 17 4 12"/></svg> Recently Resolved</div>`;
          for (const inc of recentResolved) {
            html += renderIncidentCard(inc, 'collapsed');
          }
          html += `</div>`;
        }

        // Render incidents history — collapsible block
        const history = data.incidents_history || [];
        if (history.length > 0) {
          html += `<div class="incidents-section">`;
          html += `<div class="incidents-history-toggle" onclick="toggleHistory(this)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;transition:transform 0.2s" class="history-chevron"><path d="m9 18 6-6-6-6"/></svg> Incidents History (${history.length})</div>`;
          html += `<div class="incidents-history-content">`;
          for (const inc of history) {
            html += renderIncidentCard(inc, 'collapsed');
          }
          html += `</div></div>`;
        }

        container.innerHTML = html;
      }

      const _statusLabelsInc = {
        ongoing: 'ON GOING',
        observation: 'OBSERVING',
        resolved: 'RESOLVED'
      };
      const _statusColorsInc = {
        ongoing: '#BF616A',
        observation: '#FBBF24',
        resolved: '#4ADE80'
      };

      function incidentElapsed(startStr, endStr) {
        if (!startStr) return '';
        const start = new Date(startStr + 'Z').getTime();
        const end = endStr ? new Date(endStr + 'Z').getTime() : Date.now();
        const ms = end - start;
        if (ms < 0) return '';
        const s = Math.floor(ms / 1000);
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        if (d > 0) return `${d}d ${h}h`;
        if (h > 0) return `${h}h ${m}m`;
        return `${m}m`;
      }

      function fmtDateRange(startStr, endStr) {
        if (!startStr || !endStr) return '';
        const s = new Date(startStr + 'Z');
        const e = new Date(endStr + 'Z');
        const pad = n => String(n).padStart(2, '0');
        const sDate = s.toISOString().slice(0, 10);
        const sTime = s.toISOString().slice(11, 16);
        const eDate = e.toISOString().slice(0, 10);
        const eTime = e.toISOString().slice(11, 16);
        const startPart = `${sDate} ${sTime}`;

        let endPart;
        if (sDate === eDate) {
          endPart = eTime;
        } else if (sDate.slice(0, 7) === eDate.slice(0, 7)) {
          endPart = `${pad(e.getUTCDate())} ${eTime}`;
        } else if (sDate.slice(0, 4) === eDate.slice(0, 4)) {
          endPart = `${pad(e.getUTCMonth() + 1)}-${pad(e.getUTCDate())} ${eTime}`;
        } else {
          endPart = `${eDate} ${eTime}`;
        }
        return `${startPart} ~ ${endPart} UTC`;
      }

      function renderIncidentCard(inc, mode) {
        const color = _statusColorsInc[inc.status];
        const badge = `<span class="incident-badge" style="background:${color}">${_statusLabelsInc[inc.status]}</span>`;
        const elapsed = incidentElapsed(inc.started_at, inc.resolved_at);
        const elapsedHtml = elapsed ? ` · ${elapsed}` : '';
        let meta = inc.started_at ? `Started ${fmtDate(inc.started_at)}${elapsedHtml}` : '';
        if (inc.status === 'resolved' && inc.resolved_at) {
          meta = `${fmtDateRange(inc.started_at, inc.resolved_at)}${elapsedHtml}`;
        }

        let latestHtml = '';
        let updatesHtml = '';
        if (inc.updates && inc.updates.length > 0) {
          const allUpdates = inc.updates.map(u => {
            const t = u.created_at ? fmtTime(u.created_at) : '';
            return `<div class="incident-update-row"><span class="incident-update-time">${t}</span><span>${escapeHtml(u.description)}</span></div>`;
          }).join('');

          if (mode === 'latest') {
            const last = inc.updates[inc.updates.length - 1];
            const t = last.created_at ? fmtTime(last.created_at) : '';
            latestHtml = `<div class="incident-latest-update"><span class="incident-update-time">${t}</span><span>${escapeHtml(last.description)}</span></div>`;
          }
          updatesHtml = `<div class="incident-updates">${allUpdates}</div>`;
        }

        const uid = 'inc-' + inc.id;
        return `
                <div class="incident-card" id="${uid}">
                    <div class="incident-card-header">
                        <div class="incident-card-title"><span class="incident-dot" style="background:${color}"></span>${escapeHtml(inc.title)}</div>
                        ${badge}
                    </div>
                    <div class="incident-card-meta">
                        <span>${meta}</span>
                        <span class="incident-chevron-wrap" onclick="toggleIncident('${uid}')">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="incident-chevron"><path d="m6 9 6 6 6-6"/></svg>
                        </span>
                    </div>
                    ${latestHtml}
                    ${updatesHtml}
                </div>`;
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

        const nameHtml = site.url ?
          `<a href="${escapeHtml(site.url)}" target="_blank" rel="noopener">${escapeHtml(site.name)}</a>` :
          escapeHtml(site.name);
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
                        ${uptime !== null ? `<div class="uptime-pct">${uptime}%</div>` : ''}
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
          if (countdown <= 0) {
            cb();
            countdown = interval;
          }
        }, 1000);
      }
      startRefreshTimer('countdown', 30, loadStatus);
    </script>
  </body>

  </html>
<?php
}

function serveLoginPage(): void
{
?>
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%23434C5E'/><text x='16' y='22' font-family='sans-serif' font-size='14' font-weight='bold' fill='%23ECEFF4' text-anchor='middle'>UP</text></svg>">
    <title>Login — <?= APP_NAME ?></title>
    <style>
      :root {
        --bg: #2E3440;
        --surface: #3B4252;
        --border: #434C5E;
        --text: #ECEFF4;
        --text-muted: #D8DEE9;
        --primary: #88C0D0;
        --primary-hover: #5E81AC;
        --amber: #FBBF24;
        --orange: #F97316;
        --red: #BF616A;
        --radius: 8px;
      }

      .light {
        --bg: #ECEFF4;
        --surface: #ffffff;
        --border: #D8DEE9;
        --text: #2E3440;
        --text-muted: #4C566A;
        --primary: #5E81AC;
        --primary-hover: #81A1C1;
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

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

      .theme-toggle:hover {
        opacity: 0.8;
      }

      .login-card h1 {
        font-size: 1.5rem;
        text-align: center;
        margin-bottom: 1.5rem;
      }

      .form-group {
        margin-bottom: 1rem;
      }

      .form-group label {
        display: block;
        font-size: 0.875rem;
        margin-bottom: 0.25rem;
      }

      .form-group input {
        width: 100%;
        padding: 0.5rem 0.75rem;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        background: var(--bg);
        color: var(--text);
        font-size: 1rem;
      }

      .form-group input:focus {
        outline: 2px solid var(--primary);
        outline-offset: -1px;
      }

      .btn {
        width: 100%;
        padding: 0.5rem 1rem;
        border: none;
        border-radius: var(--radius);
        background: var(--primary);
        color: var(--bg);
        font-size: 1rem;
        cursor: pointer;
      }

      .btn:hover {
        background: var(--primary-hover);
      }

      .error {
        color: var(--red);
        font-size: 0.875rem;
        margin-top: 0.5rem;
        text-align: center;
        display: none;
      }

      .footer {
        text-align: center;
        padding: 1.5rem 0 0;
        color: var(--text-muted);
        font-size: 0.75rem;
      }

      .footer a {
        color: var(--text-muted);
      }

      .footer a:hover {
        color: var(--primary);
      }

      .auth-wrapper {
        display: flex;
        flex-direction: column;
        align-items: center;
        width: 100%;
        max-width: 400px;
      }
    </style>
  </head>

  <body>
    <div class="auth-wrapper">
      <div class="login-card">
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2" />
            <path d="M12 20v2" />
            <path d="m4.93 4.93 1.41 1.41" />
            <path d="m17.66 17.66 1.41 1.41" />
            <path d="M2 12h2" />
            <path d="M20 12h2" />
            <path d="m6.34 17.66-1.41 1.41" />
            <path d="m19.07 4.93-1.41 1.41" />
          </svg>
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
          headers: {
            'Content-Type': 'application/json'
          },
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

function serveSetupPage(): void
{
?>
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%23434C5E'/><text x='16' y='22' font-family='sans-serif' font-size='14' font-weight='bold' fill='%23ECEFF4' text-anchor='middle'>UP</text></svg>">
    <title>Setup — <?= APP_NAME ?></title>
    <style>
      :root {
        --bg: #2E3440;
        --surface: #3B4252;
        --border: #434C5E;
        --text: #ECEFF4;
        --text-muted: #D8DEE9;
        --primary: #88C0D0;
        --primary-hover: #5E81AC;
        --amber: #FBBF24;
        --orange: #F97316;
        --red: #BF616A;
        --radius: 8px;
      }

      .light {
        --bg: #ECEFF4;
        --surface: #ffffff;
        --border: #D8DEE9;
        --text: #2E3440;
        --text-muted: #4C566A;
        --primary: #5E81AC;
        --primary-hover: #81A1C1;
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

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

      .theme-toggle:hover {
        opacity: 0.8;
      }

      .setup-card h1 {
        font-size: 1.5rem;
        text-align: center;
        margin-bottom: 0.5rem;
      }

      .setup-card .subtitle {
        text-align: center;
        color: var(--text-muted);
        margin-bottom: 1.5rem;
        font-size: 0.875rem;
      }

      .form-group {
        margin-bottom: 1rem;
      }

      .form-group label {
        display: block;
        font-size: 0.875rem;
        margin-bottom: 0.25rem;
      }

      .form-group input {
        width: 100%;
        padding: 0.5rem 0.75rem;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        background: var(--bg);
        color: var(--text);
        font-size: 1rem;
      }

      .form-group input:focus {
        outline: 2px solid var(--primary);
        outline-offset: -1px;
      }

      .btn {
        width: 100%;
        padding: 0.5rem 1rem;
        border: none;
        border-radius: var(--radius);
        background: var(--primary);
        color: var(--bg);
        font-size: 1rem;
        cursor: pointer;
      }

      .btn:hover {
        background: var(--primary-hover);
      }

      .error {
        color: var(--red);
        font-size: 0.875rem;
        margin-top: 0.5rem;
        text-align: center;
        display: none;
      }

      .footer {
        text-align: center;
        padding: 1.5rem 0 0;
        color: var(--text-muted);
        font-size: 0.75rem;
      }

      .footer a {
        color: var(--text-muted);
      }

      .footer a:hover {
        color: var(--primary);
      }

      .auth-wrapper {
        display: flex;
        flex-direction: column;
        align-items: center;
        width: 100%;
        max-width: 400px;
      }
    </style>
  </head>

  <body>
    <div class="auth-wrapper">
      <div class="setup-card">
        <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2" />
            <path d="M12 20v2" />
            <path d="m4.93 4.93 1.41 1.41" />
            <path d="m17.66 17.66 1.41 1.41" />
            <path d="M2 12h2" />
            <path d="M20 12h2" />
            <path d="m6.34 17.66-1.41 1.41" />
            <path d="m19.07 4.93-1.41 1.41" />
          </svg>
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
          headers: {
            'Content-Type': 'application/json'
          },
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

function serveDashboard(): void
{
  header('Cache-Control: no-cache, must-revalidate');
  $user = getCurrentUser();
  $db = getDb();
  $localeRow = $db->query("SELECT value FROM settings WHERE key = 'locale'")->fetch();
  $dashLocale = ($localeRow && $localeRow['value']) ? $localeRow['value'] : '';
?>
  <!DOCTYPE html>
  <html lang="en">

  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%23434C5E'/><text x='16' y='22' font-family='sans-serif' font-size='14' font-weight='bold' fill='%23ECEFF4' text-anchor='middle'>UP</text></svg>">
    <title>Dashboard — <?= APP_NAME ?></title>
    <style>
      :root {
        --bg: #2E3440;
        --surface: #3B4252;
        --border: #434C5E;
        --text: #ECEFF4;
        --text-muted: #D8DEE9;
        --primary: #88C0D0;
        --primary-hover: #5E81AC;
        --green: #4ADE80;
        --red: #BF616A;
        --red-dark: #A05058;
        --amber: #FBBF24;
        --orange: #F97316;
        --gray: #4C566A;
        --blue: #81A1C1;
        --radius: 8px;
      }

      .light {
        --bg: #ECEFF4;
        --surface: #ffffff;
        --border: #D8DEE9;
        --text: #2E3440;
        --text-muted: #4C566A;
        --primary: #5E81AC;
        --primary-hover: #81A1C1;
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

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
        position: sticky;
        top: 0;
        z-index: 1000;
      }

      .topbar h1 {
        font-size: 1.25rem;
        white-space: nowrap;
      }

      .topbar-right {
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

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

      .hamburger:hover {
        opacity: 0.8;
      }

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

      .nav-links button:hover {
        color: var(--text);
      }

      .nav-links button.active {
        color: var(--text);
        font-weight: 500;
      }

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

      .nav-link-btn:hover {
        color: var(--text);
      }

      .user-dropdown {
        position: relative;
        display: none;
      }

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

      .user-trigger:hover {
        background: var(--bg);
      }

      .user-name {
        max-width: 120px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

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
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      }

      .user-menu.open {
        display: block;
      }

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

      .user-menu button:hover {
        background: var(--bg);
      }

      .user-menu a {
        display: block;
        padding: 0.5rem 1rem;
        color: var(--text);
        font-size: 0.875rem;
      }

      .user-menu a:hover {
        background: var(--bg);
      }

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

      .mobile-menu.open {
        display: flex;
      }

      .mobile-menu button,
      .mobile-menu .nav-link-btn {
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

      .mobile-menu button:hover,
      .mobile-menu .nav-link-btn:hover {
        color: var(--text);
        background: var(--bg);
      }

      .mobile-menu hr {
        border: none;
        border-top: 1px solid var(--border);
        margin: 0.25rem 0;
      }

      .content {
        padding: 1rem;
        max-width: 1200px;
        margin: 0 auto;
        flex: 1;
        width: 100%;
      }

      .section {
        display: none;
      }

      .section.active {
        display: block;
      }

      .section-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1rem;
        flex-wrap: wrap;
        gap: 0.5rem;
      }

      .section-header h2 {
        font-size: 1.25rem;
      }

      .btn {
        padding: 0.5rem 1rem;
        border: none;
        border-radius: var(--radius);
        background: var(--primary);
        color: var(--bg);
        cursor: pointer;
        font-size: 0.875rem;
      }

      .btn:hover {
        background: var(--primary-hover);
      }

      .btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }

      .btn:disabled:hover {
        background: var(--primary);
      }

      .btn-danger {
        background: var(--red);
      }

      .btn-danger:hover {
        background: #A3575B;
      }

      .btn-sm {
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
      }

      .btn-outlined {
        background: transparent;
        border: 1px solid var(--border);
        color: var(--text-muted);
      }

      .btn-outlined:hover {
        background: rgba(136, 192, 208, 0.15);
        color: var(--primary);
        border-color: var(--primary);
      }

      .btn-outlined-danger:hover {
        background: rgba(191, 97, 106, 0.15);
        color: var(--red);
        border-color: var(--red);
      }

      .card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 1rem;
        margin-bottom: 1rem;
      }

      table {
        width: 100%;
        border-collapse: collapse;
      }

      th,
      td {
        padding: 0.5rem;
        text-align: left;
        border-bottom: 1px solid var(--border);
      }

      th:last-child,
      td:last-child {
        text-align: right;
      }

      th {
        font-size: 0.75rem;
        color: var(--text-muted);
        text-transform: uppercase;
      }

      .status-badge {
        display: inline-block;
        padding: 0.125rem 0.5rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 500;
        text-transform: uppercase;
      }

      .status-badge.up {
        background: rgba(74, 222, 128, 0.15);
        color: var(--green);
      }

      .status-badge.down {
        background: rgba(160, 80, 88, 0.15);
        color: var(--red-dark);
      }

      .status-badge.mostly_down {
        background: rgba(191, 97, 106, 0.15);
        color: var(--red);
      }

      .status-badge.unknown {
        background: rgba(76, 86, 106, 0.15);
        color: var(--gray);
      }

      .status-badge.scheduled {
        background: rgba(136, 192, 208, 0.15);
        color: var(--blue);
      }

      .status-badge.ongoing {
        background: rgba(191, 97, 106, 0.15);
        color: var(--red);
      }

      .status-badge.observation {
        background: rgba(251, 191, 36, 0.15);
        color: var(--amber);
      }

      .status-badge.resolved {
        background: rgba(74, 222, 128, 0.15);
        color: var(--green);
      }

      .update-badge {
        display: none;
        padding: 0.125rem 0.5rem;
        border-radius: 9999px;
        font-size: 0.7rem;
        font-weight: 500;
        background: rgba(251, 191, 36, 0.15);
        color: var(--amber);
        cursor: pointer;
        white-space: nowrap;
        vertical-align: middle;
        margin-left: 0.5rem;
      }

      .update-badge.visible {
        display: inline-block;
      }

      .updates-section {
        margin-bottom: 1.25rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid var(--border);
      }

      .updates-current {
        font-size: 0.85rem;
        color: var(--text-muted);
        margin-bottom: 0.5rem;
      }

      .updates-status {
        font-size: 0.85rem;
        margin: 0.5rem 0;
      }

      .updates-status.available {
        color: var(--amber);
        font-weight: 500;
      }

      .updates-status.uptodate {
        color: var(--green);
      }

      .modal-overlay {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.5);
        z-index: 100;
        align-items: center;
        justify-content: center;
        padding: 1rem;
      }

      .modal-overlay.active {
        display: flex;
      }

      #confirm-modal {
        z-index: 150;
      }

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

      .modal h3 {
        margin-bottom: 1rem;
      }

      .form-group {
        margin-bottom: 1rem;
      }

      .form-group label {
        display: block;
        font-size: 0.875rem;
        margin-bottom: 0.25rem;
      }

      .form-group input,
      .form-group select,
      .form-group textarea {
        width: 100%;
        padding: 0.5rem 0.75rem;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        background: var(--bg);
        color: var(--text);
        font-size: 1rem;
        font-family: inherit;
      }

      .form-group input:focus,
      .form-group select:focus,
      .form-group textarea:focus {
        outline: 2px solid var(--primary);
        outline-offset: -1px;
      }

      .form-group-hint {
        font-size: 0.75rem;
        color: var(--text-muted);
        margin-top: 0.25rem;
      }

      .checkbox-group {
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      .checkbox-group input[type="checkbox"] {
        width: auto;
        accent-color: var(--primary);
      }

      .checkbox-group label {
        margin-bottom: 0;
        cursor: pointer;
      }

      .drag-handle {
        cursor: grab;
        color: var(--text-muted);
        user-select: none;
      }

      .drag-handle:active {
        cursor: grabbing;
      }

      .btn-gray {
        background: var(--gray);
      }

      .btn-gray:hover {
        background: #3B4252;
      }

      .modal-sm {
        max-width: 360px;
      }

      .modal-md {
        max-width: 440px;
      }

      .rk-content {
        text-align: center;
      }

      .rk-warn {
        color: var(--red);
        font-size: 0.75rem;
        margin-top: 0.75rem;
      }

      .rk-pw-field {
        display: none;
        margin-top: 1rem;
        text-align: left;
      }

      .rk-check {
        display: flex;
        align-items: center;
        gap: 0.375rem;
        justify-content: center;
        margin-top: 1rem;
        font-size: 0.875rem;
        cursor: pointer;
      }

      .form-actions-center {
        justify-content: center;
        border-top: none;
        padding-top: 0;
      }

      .webhook-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.75rem;
      }

      .webhook-form {
        margin-top: 0.75rem;
        padding: 0.75rem;
        background: var(--bg);
        border-radius: var(--radius);
      }

      .webhook-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.375rem 0;
        border-bottom: 1px solid var(--border);
        font-size: 0.875rem;
      }

      .webhook-item-info {
        min-width: 0;
      }

      .webhook-item-type {
        font-weight: 500;
      }

      .webhook-item-url {
        color: var(--text-muted);
        margin-left: 0.5rem;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        display: inline-block;
        max-width: 180px;
        vertical-align: middle;
      }

      .webhook-item-events {
        color: var(--text-muted);
        margin-left: 0.5rem;
      }

      .webhook-item-actions {
        display: flex;
        gap: 0.5rem;
      }

      .help-hint {
        font-size: 0.75rem;
        color: var(--text-muted);
        margin-top: 0.5rem;
      }

      .help-version {
        color: var(--text-muted);
      }

      .site-url-link {
        color: var(--text-muted);
      }

      .confirm-msg {
        margin-bottom: 1.5rem;
        color: var(--text-muted);
      }

      .rk-copy-btn {
        margin-left: 0.5rem;
        padding: 0.25rem 0.5rem;
      }

      .webhook-label {
        font-size: 0.875rem;
        color: var(--text-muted);
      }

      .sortable-ghost {
        opacity: 0.4;
      }

      .dashboard-group {
        border: 1px solid var(--border);
        border-radius: var(--radius);
        margin-bottom: 2rem;
        min-height: 5rem;
        overflow: visible;
      }

      .dashboard-group-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.625rem 0.75rem;
        border-bottom: 1px solid var(--border);
        font-size: 0.875rem;
        margin-bottom: 0.25rem;
        background: var(--surface);
      }

      .dashboard-group-count {
        color: var(--text-muted);
        font-size: 0.75rem;
        margin-left: auto;
      }

      .dashboard-group-actions {
        display: flex;
        gap: 0.375rem;
        margin-left: 0.5rem;
      }

      .dashboard-group-sites {
        padding: 0;
      }

      .dashboard-group-sites tbody {
        background: var(--surface);
      }

      #incidents-list tbody {
        background: var(--surface);
      }

      .dashboard-group-sites table {
        margin: 0;
        width: 100%;
        table-layout: fixed;
      }

      .dashboard-group-sites th:nth-child(1),
      .dashboard-group-sites td:nth-child(1) {
        width: 2.5rem;
      }

      .dashboard-group-sites th:nth-child(2),
      .dashboard-group-sites td:nth-child(2) {
        width: 6rem;
      }

      .dashboard-group-sites th:nth-child(3),
      .dashboard-group-sites td:nth-child(3) {
        width: 4.5rem;
      }

      .dashboard-group-sites th:nth-child(4),
      .dashboard-group-sites td:nth-child(4) {
        width: 25%;
      }

      .dashboard-group-sites th:nth-child(5),
      .dashboard-group-sites td:nth-child(5) {
        width: 30%;
      }

      .dashboard-group-sites td:nth-child(5) a {
        display: block;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .dashboard-group-sites th:nth-child(6),
      .dashboard-group-sites td:nth-child(6) {
        width: 5rem;
      }

      .dashboard-group-sites th:nth-child(7),
      .dashboard-group-sites td:nth-child(7) {
        width: auto;
      }

      .dashboard-group-sites th,
      .dashboard-group-sites td {
        padding: 0.375rem 0.5rem;
      }

      .site-indicators {
        white-space: nowrap;
      }

      .site-indicators svg+svg {
        margin-left: 2px;
      }

      .site-actions-menu {
        position: relative;
        display: inline-block;
      }

      .site-actions-trigger {
        background: none;
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 0.25rem 0.5rem;
        cursor: pointer;
        color: var(--text-muted);
        font-size: 1rem;
        line-height: 1;
      }

      .site-actions-trigger:hover {
        color: var(--text);
        border-color: var(--text-muted);
      }

      .site-actions-dropdown {
        display: none;
        position: absolute;
        right: 0;
        top: 100%;
        margin-top: 0.25rem;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 100;
        min-width: 120px;
      }

      .site-actions-dropdown.open {
        display: block;
      }

      .site-actions-dropdown button {
        display: block;
        width: 100%;
        text-align: left;
        padding: 0.5rem 0.75rem;
        background: none;
        border: none;
        cursor: pointer;
        font-size: 0.8125rem;
        color: var(--text);
      }

      .site-actions-dropdown button:hover {
        background: var(--bg);
      }

      .site-actions-dropdown button.danger {
        color: var(--red);
      }

      .dashboard-ungrouped {
        border: 1px solid var(--border);
        border-radius: var(--radius);
        min-height: 5rem;
        margin-bottom: 2rem;
        overflow: visible;
      }

      .dashboard-ungrouped .dashboard-group-header {
        background: var(--surface);
        color: var(--text-muted);
        font-size: 0.8125rem;
      }

      .form-actions {
        display: flex;
        gap: 0.5rem;
        justify-content: space-between;
        margin-top: 1.5rem;
        padding-top: 1rem;
        border-top: 1px solid var(--border);
      }

      .modal-tabs {
        display: flex;
        gap: 0;
        border-bottom: 1px solid var(--border);
        margin: 0 -1.5rem 1rem -1.5rem;
        padding: 0 1.5rem;
      }

      .modal-tabs button {
        background: none;
        border: none;
        border-bottom: 2px solid transparent;
        color: var(--text-muted);
        padding: 0.75rem 1rem;
        cursor: pointer;
        font-size: 0.875rem;
        font-weight: 500;
      }

      .modal-tabs button:hover {
        color: var(--text);
      }

      .modal-tabs button.active {
        color: var(--text);
        border-bottom-color: var(--primary);
      }

      .modal-tab {
        display: none;
      }

      .modal-tab.active {
        display: block;
      }

      .modal-lg {
        max-width: 640px;
      }

      .modal-xl {
        max-width: 800px;
      }

      .checks-table {
        font-size: 0.8125rem;
      }

      .checks-table td:nth-child(2),
      .checks-table td:nth-child(3),
      .checks-table td:nth-child(4) {
        white-space: nowrap;
      }

      .checks-table code {
        font-size: 0.8125rem;
        background: var(--bg);
        padding: 0.125rem 0.375rem;
        border-radius: var(--radius);
      }

      .empty {
        text-align: center;
        padding: 2rem;
        color: var(--text-muted);
      }

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

      .toast.error {
        border-color: var(--red);
        color: var(--red);
      }

      .toast.success {
        border-color: var(--green);
        color: var(--green);
      }

      .help-content {
        max-height: 60vh;
        overflow-y: auto;
      }

      .help-section {
        margin-bottom: 1.5rem;
      }

      .help-section h4 {
        margin-bottom: 0.5rem;
        font-size: 0.875rem;
        color: var(--text-muted);
      }

      .help-section p {
        font-size: 0.875rem;
        line-height: 1.5;
      }

      .help-table {
        font-size: 0.875rem;
        width: 100%;
        border-collapse: collapse;
      }

      .help-table td {
        padding: 0.375rem 0.5rem;
      }

      .help-table tr:nth-child(odd) {
        background: var(--bg);
      }

      .help-table td:first-child {
        width: 80px;
      }

      .help-table kbd {
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: 3px;
        padding: 0.125rem 0.375rem;
        font-size: 0.75rem;
        font-family: inherit;
      }

      .recovery-key-display {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        background: var(--bg);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 0.75rem 1rem;
        margin-top: 0.5rem;
      }

      .recovery-key-display code {
        font-family: monospace;
        font-size: 1rem;
        letter-spacing: 0.08em;
        user-select: all;
        color: var(--text);
      }

      .hidden {
        display: none !important;
      }

      .hide-mobile {
        display: none;
      }

      table {
        font-size: 0.875rem;
      }

      th,
      td {
        padding: 0.375rem;
      }

      @media (min-width: 641px) {
        .nav-links {
          display: flex !important;
        }

        .user-dropdown {
          display: block !important;
        }

        .hamburger {
          display: none;
        }

        .hide-mobile {
          display: table-cell;
        }
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

      .app-footer a {
        color: var(--text);
      }

      .app-footer a:hover {
        color: var(--primary);
      }

      .app-footer p+p {
        margin-top: 0.25rem;
      }

      .app-footer p+div {
        margin-top: 1.5rem;
      }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.6/Sortable.min.js"></script>
  </head>

  <body>
    <div class="topbar">
      <h1><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px;margin-right:0.375rem">
          <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />
        </svg><?= APP_NAME ?><span class="update-badge" id="update-badge" onclick="showSettingsModal()" title="Update available"></span></h1>
      <div class="topbar-right">
        <nav class="nav-links" id="nav-links">
          <button class="active" data-section="sites" onclick="showSection('sites')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.25rem">
              <rect width="20" height="14" x="2" y="3" rx="2" />
              <line x1="8" x2="16" y1="21" y2="21" />
              <line x1="12" x2="12" y1="17" y2="21" />
            </svg>Websites</button>
          <button data-section="incidents" onclick="showSection('incidents')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.25rem">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
              <path d="M12 9v4" />
              <path d="M12 17h.01" />
            </svg>Incidents</button>
          <a href="/" target="_blank" class="nav-link-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.25rem">
              <path d="M15 3h6v6" />
              <path d="M10 14 21 3" />
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
            </svg>Status Page</a>
        </nav>
        <div class="user-dropdown">
          <button class="user-trigger" onclick="document.getElementById('user-menu').classList.toggle('open')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
            <span class="user-name"><?= htmlspecialchars($user['name']) ?></span>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="m6 9 6 6 6-6" />
            </svg>
          </button>
          <div class="user-menu" id="user-menu">
            <button onclick="showAccountModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
                <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>Account<span style="float:right;font-size:0.6875rem;color:var(--text-muted);opacity:0.6;margin-left:1rem">⌘A</span></button>
            <button onclick="showSettingsModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
                <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
                <circle cx="12" cy="12" r="3" />
              </svg>Settings<span style="float:right;font-size:0.6875rem;color:var(--text-muted);opacity:0.6;margin-left:1rem">⌘,</span></button>
            <hr>
            <button onclick="toggleTheme()" id="theme-toggle-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2" />
                <path d="M12 20v2" />
                <path d="m4.93 4.93 1.41 1.41" />
                <path d="m17.66 17.66 1.41 1.41" />
                <path d="M2 12h2" />
                <path d="M20 12h2" />
                <path d="m6.34 17.66-1.41 1.41" />
                <path d="m19.07 4.93-1.41 1.41" />
              </svg><span id="theme-toggle-label">Theme</span></button>
            <button onclick="showHelp();closeUserMenu()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
                <path d="M3 11h1a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H3a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1z" />
                <path d="M21 11h-1a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1a1 1 0 0 0 1-1v-5a1 1 0 0 0-1-1z" />
                <path d="M4 11V8a8 8 0 0 1 16 0v3" />
                <path d="M18 18a4 4 0 0 1-4 4h-2" />
              </svg>Help</button>
            <a href="https://github.com/Abtz-Labs/uptime/issues" target="_blank" rel="noopener noreferrer" style="display:block;text-decoration:none"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
                <path d="m8 2 1.88 1.88" />
                <path d="M14.12 3.88 16 2" />
                <path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1" />
                <path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6" />
                <path d="M12 20v-9" />
                <path d="M6.53 9C4.6 8.8 3 7.1 3 5" />
                <path d="M6 13H2" />
                <path d="M3 21c0-2.1 1.7-3.9 3.8-4" />
                <path d="M20.97 5c0 2.1-1.6 3.8-3.5 4" />
                <path d="M22 13h-4" />
                <path d="M17.2 17c2.1.1 3.8 1.9 3.8 4" />
              </svg>Report bug<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="float:right;margin-top:2px">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                <polyline points="15 3 21 3 21 9" />
                <line x1="10" y1="14" x2="21" y2="3" />
              </svg></a>
            <hr>
            <button onclick="logout()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" x2="9" y1="12" y2="12" />
              </svg>Logout</button>
          </div>
        </div>
        <button class="hamburger" onclick="document.getElementById('mobile-menu').classList.toggle('open')" aria-label="Menu">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
      </div>
      <nav class="mobile-menu" id="mobile-menu">
        <button class="active" data-section="sites" onclick="showSection('sites')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
            <rect width="20" height="14" x="2" y="3" rx="2" />
            <line x1="8" x2="16" y1="21" y2="21" />
            <line x1="12" x2="12" y1="17" y2="21" />
          </svg>Websites</button>
        <button data-section="incidents" onclick="showSection('incidents')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
            <path d="M12 9v4" />
            <path d="M12 17h.01" />
          </svg>Incidents</button>
        <a href="/" target="_blank" class="nav-link-btn"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
            <path d="M15 3h6v6" />
            <path d="M10 14 21 3" />
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
          </svg>Status Page</a>
        <hr>
        <button onclick="showAccountModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
            <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
            <circle cx="12" cy="7" r="4" />
          </svg>Account</button>
        <button onclick="showSettingsModal()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
            <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
            <circle cx="12" cy="12" r="3" />
          </svg>Settings</button>
        <button onclick="logout()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-right:0.375rem">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" x2="9" y1="12" y2="12" />
          </svg>Logout</button>
      </nav>
    </div>
    <div class="content">
      <!-- Dashboard Section -->
      <div id="sites" class="section active">
        <div class="section-header">
          <h2>Monitored Websites</h2>
          <div style="display:flex;gap:0.5rem">
            <button class="btn btn-outlined" onclick="showGroupModal()">+ Add Group</button>
            <button class="btn" onclick="showSiteModal()">+ Add Website</button>
          </div>
        </div>
        <div id="sites-list">
          <div class="empty">Loading...</div>
        </div>
      </div>

      <!-- Incidents Section -->
      <div id="incidents" class="section">
        <div class="section-header">
          <h2>Incident Reports</h2>
          <button class="btn" onclick="showIncidentModal()">+ New Incident</button>
        </div>
        <div id="incidents-list">
          <div class="empty">Loading...</div>
        </div>
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
          <div id="account-profile-form">
            <div class="empty">Loading...</div>
          </div>
        </div>
        <div class="modal-tab" id="account-tab-security">
          <div id="account-security-form">
            <div class="empty">Loading...</div>
          </div>
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
          <div id="settings-form">
            <div class="empty">Loading...</div>
          </div>
        </div>
        <div class="modal-tab" id="settings-tab-automation">
          <div id="settings-automation-form">
            <div class="empty">Loading...</div>
          </div>
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
        <canvas id="checks-chart" style="width:100%;height:180px;margin-bottom:1rem;display:none"></canvas>
        <div id="checks-content">
          <div class="empty">Loading...</div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-gray" onclick="closeModal('checks-modal')">Close</button>
        </div>
      </div>
    </div>

    <!-- Incident Modal -->
    <div class="modal-overlay" id="incident-modal">
      <div class="modal modal-lg">
        <h3 id="incident-modal-title">New Incident</h3>
        <div class="form-group">
          <label for="incident-title">Title</label>
          <input type="text" id="incident-title" placeholder="Brief description of the incident">
        </div>
        <div class="form-group">
          <label for="incident-status">Status</label>
          <select id="incident-status" onchange="onIncidentStatusChange()">
            <option value="ongoing">On going</option>
            <option value="observation">Observing</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
        <div class="form-group">
          <label for="incident-started-at">Started At</label>
          <input type="datetime-local" id="incident-started-at">
        </div>
        <div class="form-group" id="incident-resolved-at-group" style="display:none">
          <label for="incident-resolved-at">Resolved At</label>
          <input type="datetime-local" id="incident-resolved-at">
        </div>
        <div class="form-group">
          <label>Status Updates</label>
          <div id="incident-updates-list"></div>
          <div style="display:flex;gap:0.5rem;margin-top:0.75rem;align-items:center">
            <span id="incident-update-time-toggle" style="font-size:0.8125rem;color:var(--text-muted);white-space:nowrap;cursor:pointer" onclick="showUpdateTimeInput()">Now <span style="opacity:0.6">✎</span></span>
            <input type="datetime-local" id="incident-update-time-input" style="font-size:0.8125rem;padding:0.375rem 0.5rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);width:auto;display:none">
            <span id="incident-update-time-close" style="cursor:pointer;font-size:0.875rem;color:var(--text-muted);display:none" onclick="hideUpdateTimeInput()">&times;</span>
            <textarea id="incident-update-input" rows="1" placeholder="Describe progress or resolution..." style="flex:1;min-width:180px;resize:vertical"></textarea>
            <button type="button" class="btn" onclick="addIncidentUpdate()">+ Add</button>
          </div>
        </div>
        <div class="form-actions">
          <button type="button" class="btn btn-gray" onclick="closeModal('incident-modal')">Cancel</button>
          <button type="button" class="btn" onclick="saveIncident()" data-modal-save>Save</button>
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
            <h4>Websites & Groups</h4>
            <p>Add websites to monitor by clicking <strong>+ Add Website</strong>. Organize them into groups (e.g., Production, Staging) with <strong>+ Add Group</strong>. Drag the <strong>⠿</strong> handle to reorder. Assign sites to groups via the site edit modal.</p>
          </div>
          <div class="help-section">
            <h4>Status Page</h4>
            <p>The public status page (<strong>/</strong>) shows a read-only view of all visible sites. No login required. Auto-refreshes every 30 seconds.</p>
          </div>
          <div class="help-section">
            <h4>Incidents</h4>
            <p>Report incidents that affect your services. Each incident has a status (<strong>On going</strong>, <strong>Observing</strong>, or <strong>Resolved</strong>) and can include timestamped status updates to communicate progress. Active and recently resolved incidents (within 24h) appear on the public status page.</p>
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
            <p>Website checks are triggered by an external cron job. The cron calls the <code style="font-size:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:3px;padding:0.125rem 0.375rem">run_checks</code> endpoint, which respects each website's configured interval — only websites that are due get checked.</p>
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
              <tr>
                <td><kbd>W</kbd></td>
                <td>Websites</td>
              </tr>
              <tr>
                <td><kbd>I</kbd></td>
                <td>Incidents</td>
              </tr>
              <tr>
                <td><kbd>⌘</kbd> <kbd>A</kbd></td>
                <td>Account</td>
              </tr>
              <tr>
                <td><kbd>⌘</kbd> <kbd>,</kbd></td>
                <td>App Settings</td>
              </tr>
              <tr>
                <td><kbd>⌘</kbd> <kbd>S</kbd></td>
                <td>Save (in any form)</td>
              </tr>
              <tr>
                <td><kbd>Esc</kbd></td>
                <td>Close modal</td>
              </tr>
              <tr>
                <td><kbd>?</kbd></td>
                <td>Show this help</td>
              </tr>
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
              <svg id="rk-copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" />
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
              </svg>
              <svg id="rk-check-icon" class="hidden" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
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

    <!-- Website Modal -->
    <div class="modal-overlay" id="site-modal">
      <div class="modal">
        <h3 id="site-modal-title">Add Website</h3>
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
              <small style="color:var(--text-muted);margin-top:0.25rem;display:block">Case-insensitive plain text searched in the response body. Website is marked down if the text is not found. Does not support regex. Disabled for HEAD method (no body returned).</small>
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
              <select id="site-group">
                <option value="">None</option>
              </select>
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
            <input type="hidden" id="site-webhook-edit-id">
            <div class="form-group">
              <label for="site-webhook-type">Type</label>
              <select id="site-webhook-type" onchange="togglePresetFields()">
                <option value="generic">Generic JSON</option>
                <option value="slack">Slack</option>
                <option value="telegram">Telegram</option>
              </select>
            </div>
            <div class="form-group" id="site-webhook-url-group">
              <label for="site-webhook-url">URL</label>
              <input type="url" id="site-webhook-url">
              <div class="form-group-hint" id="slack-hint" style="display:none">Create a webhook at <a href="https://api.slack.com/apps" target="_blank" rel="noopener">https://api.slack.com/apps</a></div>
            </div>
            <div id="telegram-fields" class="hidden">
              <div class="form-group">
                <label for="site-webhook-bot-token">Bot Token</label>
                <input type="text" id="site-webhook-bot-token" placeholder="123456:ABC-DEF...">
                <div class="form-group-hint">Get a token from <a href="https://t.me/BotFather" target="_blank" rel="noopener">https://t.me/BotFather</a></div>
              </div>
              <div class="form-group">
                <label for="site-webhook-chat-id">Chat ID</label>
                <input type="text" id="site-webhook-chat-id" placeholder="-1001234567890">
              </div>
              <div class="form-group">
                <label for="site-webhook-message-template">Message Template <span style="opacity:0.5">(optional)</span></label>
                <textarea id="site-webhook-message-template" rows="3" placeholder="{{event}}: {{site_name}} is {{message}}"></textarea>
                <div class="form-group-hint">Supports {{event}}, {{site_name}}, {{url}}, {{message}}, {{timestamp}}</div>
              </div>
            </div>
            <div id="slack-template" class="hidden">
              <div class="form-group">
                <label for="site-webhook-slack-template">Message Template <span style="opacity:0.5">(optional)</span></label>
                <textarea id="site-webhook-slack-template" rows="3" placeholder="*{{event}}*: {{site_name}} is {{message}}"></textarea>
                <div class="form-group-hint">Supports {{event}}, {{site_name}}, {{url}}, {{message}}, {{timestamp}}</div>
              </div>
            </div>
            <div class="form-group">
              <label>Events</label>
              <div class="checkbox-group">
                <input type="checkbox" id="site-webhook-event-down" checked>
                <label for="site-webhook-event-down">Down</label>
              </div>
              <div class="checkbox-group">
                <input type="checkbox" id="site-webhook-event-up" checked>
                <label for="site-webhook-event-up">Up</label>
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
      let APP_LOCALE = '<?= htmlspecialchars($dashLocale) ?>' || undefined;
      let APP_STATUS = {};

      function fmtDate(utcStr) {
        if (!utcStr) return '—';
        const d = new Date(utcStr + 'Z');
        if (APP_LOCALE === 'UTC') return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
        return d.toLocaleString(APP_LOCALE || undefined, {
          timeZone: APP_LOCALE === 'UTC' ? 'UTC' : undefined
        });
      }

      function fmtTime(utcStr) {
        if (!utcStr) return '';
        const d = new Date(utcStr + 'Z');
        if (APP_LOCALE === 'UTC') return d.toISOString().slice(11, 16) + ' UTC';
        return d.toLocaleTimeString(APP_LOCALE || undefined, {
          hour: '2-digit',
          minute: '2-digit',
          hour12: false,
          timeZone: APP_LOCALE === 'UTC' ? 'UTC' : undefined
        });
      }

      function fmtDateBare(utcStr) {
        if (!utcStr) return '—';
        const d = new Date(utcStr + 'Z');
        if (APP_LOCALE === 'UTC') return d.toISOString().slice(0, 16).replace('T', ' ');
        return d.toLocaleString(APP_LOCALE || undefined, {
          timeZone: APP_LOCALE === 'UTC' ? 'UTC' : undefined
        });
      }

      function fmtInterval(seconds) {
        if (seconds >= 3600) return (seconds / 3600) + ' hour';
        if (seconds >= 60) return (seconds / 60) + ' min';
        return seconds + 's';
      }

      function fmtResolvedRelative(startStr, endStr) {
        if (!startStr || !endStr) return '—';
        const s = new Date(startStr + 'Z');
        const e = new Date(endStr + 'Z');
        if (APP_LOCALE === 'UTC') {
          const sDate = s.toISOString().slice(0, 10);
          const eDate = e.toISOString().slice(0, 10);
          const eTime = e.toISOString().slice(11, 16);
          const pad = n => String(n).padStart(2, '0');
          if (sDate === eDate) return eTime;
          if (sDate.slice(0, 7) === eDate.slice(0, 7)) return `${pad(e.getUTCDate())} ${eTime}`;
          if (sDate.slice(0, 4) === eDate.slice(0, 4)) return `${pad(e.getUTCMonth() + 1)}-${pad(e.getUTCDate())} ${eTime}`;
          return `${eDate} ${eTime}`;
        }
        return e.toLocaleString(APP_LOCALE || undefined);
      }

      async function api(action, data = {}, method = 'GET') {
        const opts = {
          method,
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSRF
          },
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
          if (b.dataset.section === id) b.classList.add('active');
        });
        closeUserMenu();
        closeMobileMenu();
        history.replaceState(null, '', '#' + id);
        if (id === 'sites') loadDashboard();
        if (id === 'incidents') loadIncidents();
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
          if (!pw || pw.length < 6) {
            showToast('Password must be at least 6 characters', 'error');
            return;
          }
          const status = await api('auth_status');
          const res = await api('account_update', {
            name: status.user.name,
            email: status.user.email,
            password: pw
          }, 'POST');
          if (res.error) {
            showToast(res.error, 'error');
            return;
          }
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

      function toggleSiteActions(btn) {
        const dropdown = btn.nextElementSibling;
        const wasOpen = dropdown.classList.contains('open');
        document.querySelectorAll('.site-actions-dropdown.open').forEach(d => d.classList.remove('open'));
        if (!wasOpen) dropdown.classList.add('open');
      }

      // Close menus when clicking outside
      document.addEventListener('click', (e) => {
        if (!e.target.closest('.user-dropdown')) closeUserMenu();
        if (!e.target.closest('.hamburger') && !e.target.closest('.mobile-menu')) closeMobileMenu();
        if (e.target.closest('.site-actions-dropdown')) {
          e.target.closest('.site-actions-dropdown').classList.remove('open');
        } else if (!e.target.closest('.site-actions-menu')) {
          document.querySelectorAll('.site-actions-dropdown.open').forEach(d => d.classList.remove('open'));
        }
      });

      async function logout() {
        await api('auth_logout', {}, 'POST');
        window.location.href = '/dash/login';
      }

      // ─── DASHBOARD ─────────────────────────────────────
      async function loadDashboard() {
        const [rawSites, rawGroups] = await Promise.all([api('list_sites'), api('list_groups')]);
        const sites = Array.isArray(rawSites) ? rawSites : [];
        const groups = Array.isArray(rawGroups) ? rawGroups : [];
        const container = document.getElementById('sites-list');

        if (!sites.length && !groups.length) {
          container.innerHTML = '<div class="empty">No websites yet. Add one to start monitoring.</div>';
          return;
        }

        const groupsMap = {};
        for (const g of groups) groupsMap[g.id] = {
          ...g,
          sites: []
        };
        const ungrouped = [];
        for (const site of sites) {
          if (site.group_id && groupsMap[site.group_id]) groupsMap[site.group_id].sites.push(site);
          else ungrouped.push(site);
        }

        function siteRow(site) {
          const rawStatus = site.status || 'unknown';
          const status = rawStatus === 'unknown' && site.enabled ? 'scheduled' : rawStatus;
          const icons = [{
              on: site.enabled,
              title: 'Enabled',
              paths: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>'
            },
            {
              on: site.visible,
              title: 'Visible',
              paths: '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>'
            },
            {
              on: site.show_url,
              title: 'Show URL',
              paths: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'
            },
            {
              on: site.notify && site.webhook_count > 0,
              title: 'Notifications',
              paths: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>'
            }
          ].map(i => `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="${i.on ? 'var(--green)' : 'var(--text-muted)'}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="opacity:${i.on ? 1 : 0.35};vertical-align:-1px" title="${i.title}">${i.paths}</svg>`).join('');
          const siteName = escapeHtml(site.name);
          return `<tr data-id="${site.id}">
                    <td><span class="drag-handle" title="Drag to reorder">⠿</span></td>
                    <td><span class="status-badge ${status}">${status}</span></td>
                    <td class="hide-mobile site-indicators">${icons}</td>
                    <td>${siteName}</td>
                    <td class="hide-mobile"><a href="${escapeHtml(site.url)}" target="_blank" style="color:var(--text-muted)">${escapeHtml(site.url)}</a></td>
                    <td class="hide-mobile">${fmtInterval(site.interval)}</td>
                    <td>${site.response_time != null ? site.response_time + 'ms' : '—'}</td>
                    <td>
                        <div class="site-actions-menu">
                            <button class="site-actions-trigger" onclick="toggleSiteActions(this)" title="Actions">⋯</button>
                            <div class="site-actions-dropdown">
                                <button onclick="showChecks(${site.id}, '${siteName}')">Logs</button>
                                <button onclick="editSite(${site.id})">Edit</button>
                                <button class="danger" onclick="deleteSite(${site.id}, '${siteName}')">Delete</button>
                            </div>
                        </div>
                    </td>
                </tr>`;
        }

        let html = '';
        const siteTableHead = '<table class="dashboard-sites"><thead><tr><th></th><th>Status</th><th class="hide-mobile"></th><th>Name</th><th class="hide-mobile">URL</th><th class="hide-mobile">Interval</th><th>Response</th><th>Actions</th></tr></thead><tbody>';

        for (const group of groups) {
          const gSites = groupsMap[group.id].sites;
          html += `<div class="dashboard-group" data-group-id="${group.id}">
                    <div class="dashboard-group-header">
                        <span class="drag-handle" title="Drag to reorder">⠿</span>
                        <strong>${escapeHtml(group.name)}</strong>
                        <span class="dashboard-group-count">${gSites.length} site${gSites.length !== 1 ? 's' : ''}</span>
                        <span class="dashboard-group-actions">
                            <button class="btn btn-sm btn-outlined" onclick="editGroup(${group.id}, '${escapeHtml(group.name)}')">Edit</button>
                            <button class="btn btn-sm btn-outlined btn-outlined-danger" onclick="deleteGroup(${group.id}, '${escapeHtml(group.name)}')">Delete</button>
                        </span>
                    </div>`;
          if (gSites.length) {
            html += `<div class="dashboard-group-sites">${siteTableHead}`;
            for (const site of gSites) html += siteRow(site);
            html += '</tbody></table></div>';
          }
          html += '</div>';
        }

        if (ungrouped.length) {
          html += `<div class="dashboard-ungrouped">
                    <div class="dashboard-group-header">Ungrouped</div>
                    <div class="dashboard-group-sites">${siteTableHead}`;
          for (const site of ungrouped) html += siteRow(site);
          html += '</tbody></table></div>';
        }

        container.innerHTML = html;

        // Group-level Sortable
        Sortable.create(container, {
          handle: '.dashboard-group-header .drag-handle',
          animation: 150,
          ghostClass: 'sortable-ghost',
          draggable: '.dashboard-group',
          onEnd: async function() {
            const ids = [...container.querySelectorAll('.dashboard-group')]
              .map(el => parseInt(el.dataset.groupId));
            await api('reorder_groups', {
              ids
            }, 'POST');
          }
        });

        // Site-level Sortable (one per group + ungrouped)
        container.querySelectorAll('.dashboard-group-sites tbody').forEach(tbody => {
          Sortable.create(tbody, {
            handle: '.drag-handle',
            animation: 150,
            ghostClass: 'sortable-ghost',
            onEnd: async function() {
              const ids = [...tbody.querySelectorAll('tr')]
                .map(tr => parseInt(tr.dataset.id));
              await api('reorder_sites', {
                ids
              }, 'POST');
            }
          });
        });
      }

      async function loadGroupOptions() {
        const raw = await api('list_groups');
        const groups = Array.isArray(raw) ? raw : [];
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

      async function showSiteModal(site = null) {
        await loadGroupOptions();
        document.getElementById('site-modal-title').textContent = site ? 'Edit Website' : 'Add Website';
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
        const raw = await api('list_sites');
        const sites = Array.isArray(raw) ? raw : [];
        const site = sites.find(s => s.id == id);
        if (site) showSiteModal(site);
      }

      async function deleteSite(id, name) {
        if (!await showConfirm('Delete Website', `Delete website "${name}"?`)) return;
        await api('delete_site', {
          id
        }, 'POST');
        loadDashboard();
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
        return {
          from: from.toISOString()
        };
      }

      async function loadChecksData() {
        if (!_checksSiteId) return;
        const params = {
          site_id: _checksSiteId,
          ...getChecksPeriodParams()
        };
        const res = await api('list_checks', params);
        const chart = res.chart || [];
        const events = res.events || [];
        if (!chart.length && !events.length) {
          document.getElementById('checks-chart').style.display = 'none';
          document.getElementById('checks-content').innerHTML = '<div class="empty">No checks recorded yet.</div>';
          return;
        }
        renderChart(chart);
        renderChecks(events);
      }

      function renderChart(checks) {
        const canvas = document.getElementById('checks-chart');
        if (!checks.length) {
          canvas.style.display = 'none';
          return;
        }
        canvas.style.display = 'block';
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        const ctx = canvas.getContext('2d');
        ctx.scale(dpr, dpr);
        const W = rect.width,
          H = rect.height;
        const pad = {
          top: 10,
          right: 10,
          bottom: 30,
          left: 50
        };
        const plotW = W - pad.left - pad.right;
        const plotH = H - pad.top - pad.bottom;

        const isLight = document.documentElement.classList.contains('light');
        const gridColor = isLight ? 'rgba(46,52,64,0.08)' : 'rgba(236,239,244,0.06)';
        const labelColor = isLight ? 'rgba(46,52,64,0.45)' : 'rgba(236,239,244,0.4)';

        const times = checks.map(c => new Date(c.checked_at + 'Z').getTime());
        const values = checks.map(c => c.response_time || 0);
        const maxVal = Math.max(...values, 100);
        const minTime = times[0],
          maxTime = times[times.length - 1];
        const timeRange = maxTime - minTime || 1;

        ctx.clearRect(0, 0, W, H);

        // Grid lines
        ctx.strokeStyle = gridColor;
        ctx.lineWidth = 1;
        const yTicks = 5;
        for (let i = 0; i <= yTicks; i++) {
          const y = pad.top + plotH - (i / yTicks) * plotH;
          ctx.beginPath();
          ctx.moveTo(pad.left, y);
          ctx.lineTo(W - pad.right, y);
          ctx.stroke();
          ctx.fillStyle = labelColor;
          ctx.font = '10px sans-serif';
          ctx.textAlign = 'right';
          ctx.fillText(Math.round(maxVal * i / yTicks) + '', pad.left - 6, y + 3);
        }

        // X-axis labels
        ctx.fillStyle = labelColor;
        ctx.textAlign = 'center';
        const xTicks = Math.min(8, checks.length);
        for (let i = 0; i < xTicks; i++) {
          const t = minTime + (i / (xTicks - 1 || 1)) * timeRange;
          const x = pad.left + (i / (xTicks - 1 || 1)) * plotW;
          const d = new Date(t);
          ctx.fillText(d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0'), x, H - 8);
        }

        // Y-axis label
        ctx.save();
        ctx.translate(12, pad.top + plotH / 2);
        ctx.rotate(-Math.PI / 2);
        ctx.fillStyle = labelColor;
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Resp. Time (ms)', 0, 0);
        ctx.restore();

        // Line path
        ctx.beginPath();
        for (let i = 0; i < checks.length; i++) {
          const x = pad.left + ((times[i] - minTime) / timeRange) * plotW;
          const y = pad.top + plotH - (values[i] / maxVal) * plotH;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.strokeStyle = '#4ADE80';
        ctx.lineWidth = 1.5;
        ctx.lineJoin = 'round';
        ctx.stroke();

        // Fill area under line
        const lastX = pad.left + plotW;
        ctx.lineTo(lastX, pad.top + plotH);
        ctx.lineTo(pad.left, pad.top + plotH);
        ctx.closePath();
        ctx.fillStyle = 'rgba(74,222,128,0.1)';
        ctx.fill();
      }

      function renderChecks(checks) {
        let html = '<table class="checks-table"><thead><tr><th>Since</th><th>Status</th><th>Code</th><th>Response</th><th>Message</th></tr></thead><tbody>';
        for (const c of checks) {
          const time = fmtDate(c.checked_at);
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
        document.getElementById('checks-chart').style.display = 'none';
        document.getElementById('checks-content').innerHTML = '<div class="empty">Loading...</div>';
        document.getElementById('checks-modal').classList.add('active');
        await loadChecksData();
      }

      let _lastChecksChart = [];
      const _origRenderChart = renderChart;
      renderChart = function(checks) {
        _lastChecksChart = checks;
        _origRenderChart(checks);
      };
      window.addEventListener('resize', () => {
        if (_lastChecksChart.length) _origRenderChart(_lastChecksChart);
      });

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
        if (res.error) {
          showToast(res.error, 'error');
          return;
        }
        showToast(id ? 'Website updated' : 'Website created');
        closeModal('site-modal');
        loadDashboard();
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
          if (active && active.id !== 'recovery-modal') {
            closeModal(active.id);
            e.preventDefault();
          }
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

        if (e.key === 'w' || e.key === 'W') {
          showSection('sites');
          return;
        }
        if (e.key === 'i' || e.key === 'I') {
          showSection('incidents');
          return;
        }
        if ((e.metaKey || e.ctrlKey) && (e.key === 'a' || e.key === 'A')) {
          e.preventDefault();
          showAccountModal();
          return;
        }
        if (e.key === '?') {
          showHelp();
          return;
        }
        if ((e.metaKey || e.ctrlKey) && e.key === ',') {
          e.preventDefault();
          showSettingsModal();
        }
      });

      // ─── SITE WEBHOOKS (embedded in site modal) ──────
      async function loadSiteWebhooks(siteId) {
        const webhooks = await api('list_webhooks', {
          site_id: siteId
        }, 'POST');
        const container = document.getElementById('site-webhooks-list');
        if (!webhooks.length) {
          container.innerHTML = '<div class="empty" style="font-size:0.875rem">No webhooks yet.</div>';
          return;
        }
        let html = '';
        for (const h of webhooks) {
          const displayUrl = h.type === 'telegram' ? `Chat: ${escapeHtml(h.chat_id || '')}` : escapeHtml(h.url);
          html += `<div class="webhook-item">
                    <div class="webhook-item-info">
                        <span class="webhook-item-type">${escapeHtml(h.type)}</span>
                        <span class="webhook-item-url">${displayUrl}</span>
                        <span class="webhook-item-events">${escapeHtml(h.events)}</span>
                    </div>
                    <div class="webhook-item-actions">
                        <button type="button" class="btn btn-sm" onclick="testSiteWebhook(${h.id}, this)" title="Test">Test</button>
                        <button type="button" class="btn btn-sm" onclick="editSiteWebhook(${h.id})" title="Edit">Edit</button>
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
          document.getElementById('site-webhook-edit-id').value = '';
          document.getElementById('site-webhook-url').value = '';
          document.getElementById('site-webhook-type').value = 'generic';
          document.getElementById('site-webhook-bot-token').value = '';
          document.getElementById('site-webhook-chat-id').value = '';
          document.getElementById('site-webhook-message-template').value = '';
          document.getElementById('site-webhook-slack-template').value = '';
          document.getElementById('site-webhook-event-down').checked = true;
          document.getElementById('site-webhook-event-up').checked = true;
          togglePresetFields();
        }
      }

      function togglePresetFields() {
        const type = document.getElementById('site-webhook-type').value;
        const telegramFields = document.getElementById('telegram-fields');
        const slackTemplate = document.getElementById('slack-template');
        const urlGroup = document.getElementById('site-webhook-url-group');
        const urlInput = document.getElementById('site-webhook-url');
        const slackHint = document.getElementById('slack-hint');

        telegramFields.classList.toggle('hidden', type !== 'telegram');
        slackTemplate.classList.toggle('hidden', type !== 'slack');
        slackHint.style.display = type === 'slack' ? '' : 'none';
        urlGroup.classList.toggle('hidden', type === 'telegram');

        if (type === 'slack') {
          urlInput.placeholder = 'https://hooks.slack.com/services/T00000000/B00000000/XXXX';
        } else if (type === 'generic') {
          urlInput.placeholder = 'https://example.com/webhook';
        }
      }

      async function editSiteWebhook(id) {
        const siteId = document.getElementById('site-id').value;
        const webhooks = await api('list_webhooks', {
          site_id: siteId
        }, 'POST');
        const hook = webhooks.find(w => w.id === id);
        if (!hook) return;
        const form = document.getElementById('site-webhook-form');
        if (form.classList.contains('hidden')) form.classList.remove('hidden');
        document.getElementById('site-webhook-edit-id').value = hook.id;
        document.getElementById('site-webhook-type').value = hook.type;
        if (hook.type === 'telegram') {
          document.getElementById('site-webhook-bot-token').value = hook.bot_token || '';
          document.getElementById('site-webhook-chat-id').value = hook.chat_id || '';
          document.getElementById('site-webhook-message-template').value = hook.message_template || '';
        } else {
          document.getElementById('site-webhook-url').value = hook.url || '';
          if (hook.type === 'slack') {
            document.getElementById('site-webhook-slack-template').value = hook.message_template || '';
          }
        }
        const events = (hook.events || '').split(',');
        document.getElementById('site-webhook-event-down').checked = events.includes('down');
        document.getElementById('site-webhook-event-up').checked = events.includes('up');
        togglePresetFields();
      }

      async function saveSiteWebhook() {
        const siteId = document.getElementById('site-id').value;
        if (!siteId) return;
        const editId = document.getElementById('site-webhook-edit-id').value;
        const events = [];
        if (document.getElementById('site-webhook-event-down').checked) events.push('down');
        if (document.getElementById('site-webhook-event-up').checked) events.push('up');
        const type = document.getElementById('site-webhook-type').value;
        const data = {
          site_id: parseInt(siteId),
          type: type,
          events: events.join(','),
        };
        if (type === 'telegram') {
          data.bot_token = document.getElementById('site-webhook-bot-token').value;
          data.chat_id = document.getElementById('site-webhook-chat-id').value;
          data.message_template = document.getElementById('site-webhook-message-template').value;
        } else {
          data.url = document.getElementById('site-webhook-url').value;
          if (type === 'slack') {
            data.message_template = document.getElementById('site-webhook-slack-template').value;
          }
        }
        if (editId) {
          data.id = parseInt(editId);
          await api('update_webhook', data, 'POST');
        } else {
          await api('create_webhook', data, 'POST');
        }
        toggleWebhookForm();
        loadSiteWebhooks(siteId);
        loadDashboard();
      }

      async function deleteSiteWebhook(id) {
        if (!await showConfirm('Delete Webhook', 'Delete this webhook?')) return;
        const siteId = document.getElementById('site-id').value;
        await api('delete_webhook', {
          id
        }, 'POST');
        loadSiteWebhooks(siteId);
        loadDashboard();
      }

      async function testSiteWebhook(id, btn) {
        btn.disabled = true;
        btn.textContent = 'Sending...';
        try {
          const res = await api('test_webhook', {
            id
          }, 'POST');
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
        setTimeout(() => {
          btn.textContent = 'Test';
          btn.disabled = false;
        }, 2000);
      }

      function showGroupModal(group = null) {
        document.getElementById('group-modal-title').textContent = group ? 'Edit Group' : 'Add Group';
        document.getElementById('group-id').value = group ? group.id : '';
        document.getElementById('group-name').value = group ? group.name : '';
        document.getElementById('group-modal').classList.add('active');
        focusFirstInput('group-modal');
      }

      function editGroup(id, name) {
        showGroupModal({
          id,
          name
        });
      }

      async function deleteGroup(id, name) {
        if (!await showConfirm('Delete Group', `Delete group "${name}"? Sites in this group will become ungrouped.`)) return;
        await api('delete_group', {
          id
        }, 'POST');
        loadDashboard();
      }

      document.getElementById('group-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const id = document.getElementById('group-id').value;
        const data = {
          name: document.getElementById('group-name').value,
        };
        if (id) data.id = id;
        const res = await api(id ? 'update_group' : 'create_group', data, 'POST');
        if (res.error) {
          showToast(res.error, 'error');
          return;
        }
        showToast(id ? 'Group updated' : 'Group created');
        closeModal('group-modal');
        loadDashboard();
      });

      // ─── INCIDENTS ───────────────────────────────────
      let _editIncidentId = null;
      let _incidentUpdates = [];
      let _elapsedTimer = null;

      function formatElapsed(ms) {
        if (ms < 0) ms = 0;
        const s = Math.floor(ms / 1000);
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        if (d > 0) return `${d}d ${h}h ${m}m`;
        if (h > 0) return `${h}h ${m}m`;
        return `${m}m`;
      }

      function updateElapsedTimers() {
        document.querySelectorAll('[data-elapsed-start]').forEach(el => {
          const start = parseInt(el.dataset.elapsedStart);
          const end = el.dataset.elapsedEnd ? parseInt(el.dataset.elapsedEnd) : Date.now();
          el.textContent = formatElapsed(end - start);
        });
      }

      async function loadIncidents() {
        const data = await api('list_incidents');
        const list = document.getElementById('incidents-list');
        const incidents = data.incidents || [];
        if (incidents.length === 0) {
          list.innerHTML = '<div class="empty">No incidents reported</div>';
          if (_elapsedTimer) {
            clearInterval(_elapsedTimer);
            _elapsedTimer = null;
          }
          return;
        }
        const statusLabels = {
          ongoing: 'On going',
          observation: 'Observing',
          resolved: 'Resolved'
        };
        const statusClasses = {
          ongoing: 'ongoing',
          observation: 'observation',
          resolved: 'resolved'
        };
        const tzLabel = APP_LOCALE === 'UTC' ? ' (UTC)' : '';
        let html = `<table><thead><tr><th>Status</th><th>Title</th><th class="hide-mobile">Started${tzLabel}</th><th class="hide-mobile">Resolved</th><th>Elapsed</th><th>Actions</th></tr></thead><tbody>`;
        for (const i of incidents) {
          const started = fmtDateBare(i.started_at);
          const resolved = i.resolved_at ? fmtResolvedRelative(i.started_at, i.resolved_at) : '—';
          const startMs = i.started_at ? new Date(i.started_at + 'Z').getTime() : 0;
          const endMs = i.resolved_at ? new Date(i.resolved_at + 'Z').getTime() : '';
          const elapsed = startMs ? formatElapsed((endMs || Date.now()) - startMs) : '—';
          html += `<tr>
                    <td><span class="status-badge ${statusClasses[i.status]}">${statusLabels[i.status]}</span></td>
                    <td>${escapeHtml(i.title)}</td>
                    <td class="hide-mobile">${started}</td>
                    <td class="hide-mobile">${resolved}</td>
                    <td><span data-elapsed-start="${startMs}"${endMs ? ` data-elapsed-end="${endMs}"` : ''}>${elapsed}</span></td>
                    <td>
                        <div class="site-actions-menu">
                            <button class="site-actions-trigger" onclick="toggleSiteActions(this)" title="Actions">⋯</button>
                            <div class="site-actions-dropdown">
                                <button onclick="editIncident(${i.id})">Update</button>
                                <button class="danger" onclick="deleteIncident(${i.id}, '${escapeHtml(i.title).replace(/'/g, "\\'")}')">Delete</button>
                            </div>
                        </div>
                    </td>
                </tr>`;
        }
        html += '</tbody></table>';
        list.innerHTML = html;

        if (_elapsedTimer) clearInterval(_elapsedTimer);
        _elapsedTimer = setInterval(updateElapsedTimers, 60000);
      }

      function showIncidentModal(incident = null) {
        _editIncidentId = incident ? incident.id : null;
        document.getElementById('incident-modal-title').textContent = incident ? 'Edit Incident' : 'New Incident';
        document.getElementById('incident-title').value = incident ? incident.title : '';
        document.getElementById('incident-status').value = incident ? incident.status : 'ongoing';

        const now = new Date();
        const localIso = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        if (incident && incident.started_at) {
          document.getElementById('incident-started-at').value = incident.started_at.replace(' ', 'T').slice(0, 16);
        } else {
          document.getElementById('incident-started-at').value = localIso;
        }
        if (incident && incident.resolved_at) {
          document.getElementById('incident-resolved-at').value = incident.resolved_at.replace(' ', 'T').slice(0, 16);
        } else {
          document.getElementById('incident-resolved-at').value = '';
        }

        _incidentUpdates = incident && incident.updates ? incident.updates.map(u => ({
          id: u.id,
          description: u.description,
          created_at: u.created_at
        })) : [];
        renderIncidentUpdates();
        onIncidentStatusChange();
        document.getElementById('incident-modal').classList.add('active');
        focusFirstInput('incident-modal');
      }

      function onIncidentStatusChange() {
        const status = document.getElementById('incident-status').value;
        const group = document.getElementById('incident-resolved-at-group');
        group.style.display = status === 'resolved' ? '' : 'none';
        if (status === 'resolved' && !document.getElementById('incident-resolved-at').value) {
          const now = new Date();
          document.getElementById('incident-resolved-at').value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        }
      }

      function renderIncidentUpdates() {
        const container = document.getElementById('incident-updates-list');
        if (_incidentUpdates.length === 0) {
          container.innerHTML = '<div style="font-size:0.8125rem;color:var(--text-muted);padding:0.5rem 0">No updates yet</div>';
          return;
        }
        container.innerHTML = _incidentUpdates.map((u, i) => {
          const time = u.created_at ? fmtTime(u.created_at) : 'now';
          return `<div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.375rem 0;border-bottom:1px solid var(--border)" id="incident-update-row-${i}">
                    <span style="font-size:0.75rem;color:var(--text-muted);white-space:nowrap;margin-top:2px" id="incident-update-time-${i}">${time}</span>
                    <span style="flex:1;font-size:0.8125rem" id="incident-update-text-${i}">${escapeHtml(u.description)}</span>
                    <button type="button" class="btn btn-sm btn-outlined" onclick="editIncidentUpdateInline(${i})" style="padding:0.125rem 0.375rem;font-size:0.75rem">✎</button>
                    <button type="button" class="btn btn-sm btn-outlined btn-outlined-danger" onclick="removeIncidentUpdate(${i})" style="padding:0.125rem 0.375rem;font-size:0.75rem">&times;</button>
                </div>`;
        }).join('');
      }

      function editIncidentUpdateInline(index) {
        const u = _incidentUpdates[index];
        const row = document.getElementById(`incident-update-row-${index}`);
        if (!row) return;
        const timeVal = u.created_at ? u.created_at.replace(' ', 'T').slice(0, 16) : '';
        row.innerHTML = `
                <input type="datetime-local" value="${timeVal}" style="font-size:0.75rem;padding:0.25rem 0.375rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text);width:auto" id="incident-update-edit-time-${index}">
                <input type="text" value="${escapeHtml(u.description)}" style="flex:1;font-size:0.8125rem;padding:0.25rem 0.375rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg);color:var(--text)" id="incident-update-edit-desc-${index}" onkeydown="if(event.key==='Enter'){saveIncidentUpdateInline(${index})}">
                <button type="button" class="btn btn-sm" onclick="saveIncidentUpdateInline(${index})" style="padding:0.125rem 0.5rem;font-size:0.75rem">Save</button>
                <button type="button" class="btn btn-sm btn-outlined" onclick="renderIncidentUpdates()" style="padding:0.125rem 0.375rem;font-size:0.75rem">Cancel</button>
            `;
        row.querySelector(`#incident-update-edit-desc-${index}`).focus();
      }

      async function saveIncidentUpdateInline(index) {
        const desc = document.getElementById(`incident-update-edit-desc-${index}`).value.trim();
        const timeRaw = document.getElementById(`incident-update-edit-time-${index}`).value;
        if (!desc) return;
        const createdAt = timeRaw ? timeRaw.replace('T', ' ') + ':00' : null;
        _incidentUpdates[index].description = desc;
        if (createdAt) _incidentUpdates[index].created_at = createdAt;
        if (_incidentUpdates[index].id) {
          const payload = {
            id: _incidentUpdates[index].id,
            description: desc
          };
          if (createdAt) payload.created_at = createdAt;
          await api('update_incident_update', payload, 'POST');
        }
        renderIncidentUpdates();
      }

      function showUpdateTimeInput() {
        const now = new Date();
        const local = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        document.getElementById('incident-update-time-input').value = local;
        document.getElementById('incident-update-time-input').style.display = '';
        document.getElementById('incident-update-time-close').style.display = '';
        document.getElementById('incident-update-time-toggle').style.display = 'none';
      }

      function hideUpdateTimeInput() {
        document.getElementById('incident-update-time-input').style.display = 'none';
        document.getElementById('incident-update-time-input').value = '';
        document.getElementById('incident-update-time-close').style.display = 'none';
        document.getElementById('incident-update-time-toggle').style.display = '';
      }

      async function addIncidentUpdate() {
        const input = document.getElementById('incident-update-input');
        const timeInput = document.getElementById('incident-update-time-input');
        const desc = input.value.trim();
        if (!desc) return;

        const timeRaw = timeInput.value;
        const createdAt = timeRaw ? timeRaw.replace('T', ' ') + ':00' : null;

        if (_editIncidentId) {
          const payload = {
            incident_id: _editIncidentId,
            description: desc
          };
          if (createdAt) payload.created_at = createdAt;
          const res = await api('create_incident_update', payload, 'POST');
          if (res.error) {
            showToast(res.error, 'error');
            return;
          }
          _incidentUpdates.push({
            id: res.id,
            description: desc,
            created_at: createdAt || new Date().toISOString().replace('T', ' ').slice(0, 19)
          });
        } else {
          _incidentUpdates.push({
            id: null,
            description: desc,
            created_at: createdAt
          });
        }
        input.value = '';
        hideUpdateTimeInput();
        renderIncidentUpdates();
      }

      async function removeIncidentUpdate(index) {
        const u = _incidentUpdates[index];
        if (u.id) {
          await api('delete_incident_update', {
            id: u.id
          }, 'POST');
        }
        _incidentUpdates.splice(index, 1);
        renderIncidentUpdates();
      }

      async function editIncident(id) {
        const data = await api('list_incidents');
        const incident = (data.incidents || []).find(i => i.id === id);
        if (!incident) return;
        showIncidentModal(incident);
      }

      async function deleteIncident(id, title) {
        if (!await showConfirm('Delete Incident', `Delete incident "${title}"? All status updates will also be removed.`)) return;
        await api('delete_incident', {
          id
        }, 'POST');
        showToast('Incident deleted');
        loadIncidents();
      }

      async function saveIncident() {
        const title = document.getElementById('incident-title').value.trim();
        const status = document.getElementById('incident-status').value;
        const startedAt = document.getElementById('incident-started-at').value.replace('T', ' ') + ':00';
        const resolvedAtRaw = document.getElementById('incident-resolved-at').value;
        const resolvedAt = status === 'resolved' && resolvedAtRaw ? resolvedAtRaw.replace('T', ' ') + ':00' : null;

        if (!title) {
          showToast('Title is required', 'error');
          return;
        }
        if (status === 'resolved' && !resolvedAt) {
          showToast('Resolved At is required', 'error');
          return;
        }

        const payload = {
          title,
          status,
          started_at: startedAt
        };
        if (resolvedAt) payload.resolved_at = resolvedAt;

        if (_editIncidentId) {
          payload.id = _editIncidentId;
          const res = await api('update_incident', payload, 'POST');
          if (res.error) {
            showToast(res.error, 'error');
            return;
          }
          showToast('Incident updated');
        } else {
          const res = await api('create_incident', payload, 'POST');
          if (res.error) {
            showToast(res.error, 'error');
            return;
          }
          const newId = res.id;
          for (const u of _incidentUpdates) {
            if (!u.id) {
              await api('create_incident_update', {
                incident_id: newId,
                description: u.description
              }, 'POST');
            }
          }
          showToast('Incident created');
        }
        closeModal('incident-modal');
        loadIncidents();
      }

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
        if (!password) {
          showToast('Password is required', 'error');
          return;
        }
        const res = await api('regenerate_recovery_key', {
          password
        }, 'POST');
        if (res.error) {
          showToast(res.error, 'error');
          return;
        }
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
        if (!name || !email) {
          showToast('Name and email are required', 'error');
          return;
        }
        const current = document.getElementById('account-current-password').value;
        const newPw = document.getElementById('account-new-password').value;
        const confirmPw = document.getElementById('account-confirm-password').value;
        if (current || newPw || confirmPw) {
          if (!current || !newPw) {
            showToast('All password fields are required', 'error');
            return;
          }
          if (newPw !== confirmPw) {
            showToast('Passwords do not match', 'error');
            return;
          }
          if (newPw.length < 6) {
            showToast('Password must be at least 6 characters', 'error');
            return;
          }
          const res = await api('account_update', {
            name,
            email,
            password: newPw,
            current_password: current
          }, 'POST');
          if (res.error) {
            showToast(res.error, 'error');
            return;
          }
          showToast('Password updated');
        } else {
          const res = await api('account_update', {
            name,
            email
          }, 'POST');
          if (res.error) {
            showToast(res.error, 'error');
            return;
          }
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

        const localeOptions = [{
            value: '',
            label: 'Browser default'
          },
          {
            value: 'UTC',
            label: 'UTC (2026-08-27 14:30 UTC)'
          },
          {
            value: 'ja-JP',
            label: 'Japanese (2026/08/27 14:30)'
          },
          {
            value: 'en-US',
            label: 'English US (8/27/2026, 2:30 PM)'
          },
          {
            value: 'en-GB',
            label: 'English UK (27/08/2026, 14:30)'
          },
          {
            value: 'de-DE',
            label: 'German (27.08.2026, 14:30)'
          },
          {
            value: 'fr-FR',
            label: 'French (27/08/2026 14:30)'
          },
          {
            value: 'pt-BR',
            label: 'Portuguese BR (27/08/2026 14:30)'
          },
          {
            value: 'ko-KR',
            label: 'Korean (2026. 8. 27. 14:30)'
          },
          {
            value: 'zh-CN',
            label: 'Chinese (2026/8/27 14:30)'
          },
        ];
        const currentLocale = settings.locale || '';
        const localeSelect = localeOptions.map(o => `<option value="${o.value}"${o.value === currentLocale ? ' selected' : ''}>${o.label}</option>`).join('');

        container.innerHTML = `
                <div class="form-group">
                    <label for="settings-app-name">Status Page Title</label>
                    <input type="text" id="settings-app-name" value="${escapeHtml(settings.app_name || '')}">
                </div>
                <div class="form-group">
                    <label for="settings-locale">Date Format</label>
                    <select id="settings-locale">${localeSelect}</select>
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
        if (res.error) {
          showToast(res.error, 'error');
          return;
        }
        document.getElementById('settings-cron-token').value = res.cron_token;
        const example = document.getElementById('cron-example');
        example.textContent = `* * * * * curl -sf "https://your-host/?action=run_checks&token=${res.cron_token}"\n0 3 * * * curl -sf "https://your-host/?action=cleanup_checks&token=${res.cron_token}"`;
        showToast('Cron token generated');
      }

      async function saveSettings() {
        const locale = document.getElementById('settings-locale').value;
        const res = await api('update_settings', {
          app_name: document.getElementById('settings-app-name').value,
          locale: locale,
          retention_days: parseInt(document.getElementById('settings-retention').value),
        }, 'POST');
        if (res.error) {
          showToast(res.error, 'error');
          return;
        }
        APP_LOCALE = locale || undefined;
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
        if (btn) {
          btn.disabled = true;
          btn.textContent = 'Applying...';
        }

        const res = await api('apply_update', {}, 'POST');
        if (res.error) {
          showToast(res.error, 'error');
          if (btn) {
            btn.disabled = false;
            btn.textContent = 'Apply update';
          }
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
      const validSections = ['sites'];
      const initialSection = location.hash.replace('#', '');
      if (validSections.includes(initialSection)) {
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        document.getElementById(initialSection).classList.add('active');
        document.querySelectorAll('.nav-links button, .mobile-menu button').forEach(b => {
          b.classList.remove('active');
          if (b.dataset.section === initialSection) b.classList.add('active');
        });
      }
      loadDashboard();

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
          if (countdown <= 0) {
            cb();
            countdown = interval;
          }
        }, 1000);
      }
      const _initSection = location.hash.replace('#', '') || 'sites';
      if (['sites', 'incidents'].includes(_initSection)) {
        showSection(_initSection);
      } else {
        loadDashboard();
      }
      startRefreshTimer('sites-refresh', 30, () => {
        const active = document.querySelector('.section.active');
        if (active && active.id === 'sites') loadDashboard();
      });
    </script>
  </body>

  </html>
<?php
}

// ============================================================================
// API: AUTH
// ============================================================================

function apiAuthStatus(): void
{
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

function apiAuthSetup(): void
{
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

function apiAuthLogin(): void
{
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

function apiAuthLogout(): void
{
  session_destroy();
  jsonResponse(['ok' => true]);
}

// ============================================================================
// API: ACCOUNT
// ============================================================================

function apiAccountUpdate(): void
{
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

function apiRegenerateRecoveryKey(): void
{
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

function apiListSites(): void
{
  requireAuth();
  $db = getDb();
  $sites = $db->query("
        SELECT s.*, ss.status, ss.last_check, ss.last_up, ss.last_down,
               (SELECT COUNT(*) FROM webhooks w WHERE w.site_id = s.id) AS webhook_count,
               (SELECT response_time FROM checks WHERE site_id = s.id ORDER BY checked_at DESC LIMIT 1) AS response_time
        FROM sites s
        LEFT JOIN site_status ss ON s.id = ss.site_id
        ORDER BY s.position, s.name
    ")->fetchAll();
  jsonResponse($sites);
}

function apiCreateSite(): void
{
  requireAuth();
  $input = getInput();
  $name = trim($input['name'] ?? '');
  $url = trim($input['url'] ?? '');

  if (!$name || !$url) jsonResponse(['error' => 'Name and URL are required'], 400);
  if (!filter_var($url, FILTER_VALIDATE_URL)) jsonResponse(['error' => 'Invalid URL'], 400);

  $method = $input['method'] ?? 'GET';

  $db = getDb();
  $maxPos = $db->query("SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM sites")->fetch()['next_pos'];
  $stmt = $db->prepare("INSERT INTO sites (name, url, method, expected_status, expected_keyword, timeout, interval, group_id, enabled, visible, notify, show_url, position) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
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
    $maxPos,
  ]);
  $siteId = (int) $db->lastInsertId();

  // Initialize site_status
  $db->prepare("INSERT INTO site_status (site_id) VALUES (?)")->execute([$siteId]);

  jsonResponse(['id' => $siteId]);
}

function apiUpdateSite(): void
{
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

function apiDeleteSite(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $db->prepare("DELETE FROM sites WHERE id = ?")->execute([$id]);
  jsonResponse(['ok' => true]);
}

function apiReorderSites(): void
{
  requireAuth();
  $input = getInput();
  $ids = $input['ids'] ?? [];
  if (!is_array($ids) || count($ids) === 0) jsonResponse(['error' => 'Missing ids'], 400);

  $db = getDb();
  $db->exec('BEGIN');
  $stmt = $db->prepare("UPDATE sites SET position = ? WHERE id = ?");
  foreach ($ids as $position => $id) {
    $stmt->execute([(int) $position, (int) $id]);
  }
  $db->exec('COMMIT');
  jsonResponse(['ok' => true]);
}

// ============================================================================
// API: CHECKS
// ============================================================================

function apiRunChecks(): void
{
  verifyCronToken();
  $result = runChecks();
  $cleanup = cleanupChecks();
  $result['cleaned'] = $cleanup['deleted'];
  jsonResponse($result);
}

function apiListChecks(): void
{
  requireAuth();
  $siteId = (int) ($_GET['site_id'] ?? 0);
  if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);

  $where = "WHERE site_id = ?";
  $params = [$siteId];

  if (!empty($_GET['from'])) {
    $where .= " AND checked_at >= ?";
    $params[] = preg_replace('/\.\d+Z$/', '', str_replace('T', ' ', $_GET['from']));
  }
  if (!empty($_GET['to'])) {
    $where .= " AND checked_at <= ?";
    $params[] = preg_replace('/\.\d+Z$/', '', str_replace('T', ' ', $_GET['to']));
  }

  $db = getDb();

  // All checks for response time chart
  $chartSql = "SELECT checked_at, status, response_time, status_code, message FROM checks $where ORDER BY checked_at ASC LIMIT 500";
  $stmt = $db->prepare($chartSql);
  $stmt->execute($params);
  $allChecks = $stmt->fetchAll();

  // Status transition events for the table
  $eventsSql = "SELECT checked_at, status, status_code, response_time, message FROM (
        SELECT checked_at, status, status_code, response_time, message,
               LAG(status) OVER (ORDER BY checked_at) AS prev_status
        FROM checks $where ORDER BY checked_at ASC LIMIT 500
    ) WHERE prev_status IS NULL OR status != prev_status ORDER BY checked_at DESC";
  $stmt = $db->prepare($eventsSql);
  $stmt->execute($params);
  $events = $stmt->fetchAll();

  jsonResponse(['chart' => $allChecks, 'events' => $events]);
}

// ============================================================================
// API: GROUPS
// ============================================================================

function apiListGroups(): void
{
  requireAuth();
  $db = getDb();
  $groups = $db->query("SELECT * FROM groups ORDER BY position, name")->fetchAll();
  jsonResponse($groups);
}

function apiCreateGroup(): void
{
  requireAuth();
  $input = getInput();
  $name = trim($input['name'] ?? '');
  if (!$name) jsonResponse(['error' => 'Name is required'], 400);

  $db = getDb();
  $maxPos = $db->query("SELECT COALESCE(MAX(position), -1) + 1 as next_pos FROM groups")->fetch()['next_pos'];
  $db->prepare("INSERT INTO groups (name, position) VALUES (?, ?)")->execute([$name, $maxPos]);
  jsonResponse(['id' => (int) $db->lastInsertId()]);
}

function apiUpdateGroup(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $fields = [];
  $params = [];

  if (isset($input['name'])) {
    $fields[] = 'name = ?';
    $params[] = trim($input['name']);
  }
  if (isset($input['position'])) {
    $fields[] = 'position = ?';
    $params[] = (int) $input['position'];
  }

  if (!$fields) jsonResponse(['error' => 'No fields to update'], 400);

  $params[] = $id;
  $db->prepare("UPDATE groups SET " . implode(', ', $fields) . " WHERE id = ?")->execute($params);
  jsonResponse(['ok' => true]);
}

function apiDeleteGroup(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $db->prepare("DELETE FROM groups WHERE id = ?")->execute([$id]);
  jsonResponse(['ok' => true]);
}

function apiReorderGroups(): void
{
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

function apiListWebhooks(): void
{
  requireAuth();
  $input = getInput();
  $siteId = (int) ($input['site_id'] ?? 0);
  if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);

  $db = getDb();
  $stmt = $db->prepare("SELECT * FROM webhooks WHERE site_id = ? ORDER BY created_at DESC");
  $stmt->execute([$siteId]);
  jsonResponse($stmt->fetchAll());
}

function apiCreateWebhook(): void
{
  requireAuth();
  $input = getInput();
  $url = trim($input['url'] ?? '');
  $type = $input['type'] ?? 'generic';
  $siteId = (int) ($input['site_id'] ?? 0);
  $botToken = trim($input['bot_token'] ?? '');
  $chatId = trim($input['chat_id'] ?? '');
  $messageTemplate = $input['message_template'] ?? null;

  if (!$siteId) jsonResponse(['error' => 'Missing site_id'], 400);
  if (!in_array($type, ['slack', 'telegram', 'generic'])) jsonResponse(['error' => 'Invalid type'], 400);

  if ($type === 'telegram') {
    if (!$botToken) jsonResponse(['error' => 'Bot token is required for Telegram'], 400);
    if (!$chatId) jsonResponse(['error' => 'Chat ID is required for Telegram'], 400);
    $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
  } else {
    if (!$url) jsonResponse(['error' => 'URL is required'], 400);
    if (!filter_var($url, FILTER_VALIDATE_URL)) jsonResponse(['error' => 'Invalid URL'], 400);
  }

  $db = getDb();
  // Verify site exists
  $check = $db->prepare("SELECT id FROM sites WHERE id = ?");
  $check->execute([$siteId]);
  if (!$check->fetch()) jsonResponse(['error' => 'Site not found'], 404);

  $db->prepare("INSERT INTO webhooks (site_id, url, type, events, bot_token, chat_id, message_template) VALUES (?, ?, ?, ?, ?, ?, ?)")->execute([$siteId, $url, $type, $input['events'] ?? 'down,up', $botToken ?: null, $chatId ?: null, $messageTemplate]);
  jsonResponse(['id' => (int) $db->lastInsertId()]);
}

function apiUpdateWebhook(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $fields = [];
  $params = [];

  if (isset($input['url'])) {
    $fields[] = 'url = ?';
    $params[] = trim($input['url']);
  }
  if (isset($input['type'])) {
    $fields[] = 'type = ?';
    $params[] = $input['type'];
  }
  if (isset($input['events'])) {
    $fields[] = 'events = ?';
    $params[] = $input['events'];
  }
  if (isset($input['enabled'])) {
    $fields[] = 'enabled = ?';
    $params[] = (int) $input['enabled'];
  }
  if (array_key_exists('bot_token', $input)) {
    $fields[] = 'bot_token = ?';
    $params[] = $input['bot_token'] ?: null;
  }
  if (array_key_exists('chat_id', $input)) {
    $fields[] = 'chat_id = ?';
    $params[] = $input['chat_id'] ?: null;
  }
  if (array_key_exists('message_template', $input)) {
    $fields[] = 'message_template = ?';
    $params[] = $input['message_template'] ?: null;
  }

  if (!$fields) jsonResponse(['error' => 'No fields to update'], 400);

  $params[] = $id;
  $db->prepare("UPDATE webhooks SET " . implode(', ', $fields) . " WHERE id = ?")->execute($params);
  jsonResponse(['ok' => true]);
}

function apiDeleteWebhook(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $db->prepare("DELETE FROM webhooks WHERE id = ?")->execute([$id]);
  jsonResponse(['ok' => true]);
}

function apiTestWebhook(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $hook = $db->prepare("SELECT * FROM webhooks WHERE id = ?");
  $hook->execute([$id]);
  $webhook = $hook->fetch();
  if (!$webhook) jsonResponse(['error' => 'Webhook not found'], 404);

  $body = formatWebhookPayload($webhook['type'], 'test', 'Test Website', 'https://example.com', 'This is a test notification', $webhook['bot_token'] ?? null, $webhook['chat_id'] ?? null, $webhook['message_template'] ?? null);
  $url = $webhook['type'] === 'telegram' && !empty($webhook['bot_token'])
    ? "https://api.telegram.org/bot{$webhook['bot_token']}/sendMessage"
    : $webhook['url'];
  sendWebhook($url, $body);
  jsonResponse(['ok' => true]);
}

// ============================================================================
// API: INCIDENTS
// ============================================================================

function apiListIncidents(): void
{
  requireAuth();
  $db = getDb();
  $incidents = $db->query("
        SELECT * FROM incidents
        ORDER BY
            CASE status WHEN 'ongoing' THEN 0 WHEN 'observation' THEN 1 ELSE 2 END,
            updated_at DESC
    ")->fetchAll();

  foreach ($incidents as &$incident) {
    $stmt = $db->prepare("SELECT * FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
    $stmt->execute([$incident['id']]);
    $incident['updates'] = $stmt->fetchAll();
  }
  unset($incident);

  jsonResponse(['incidents' => $incidents]);
}

function apiCreateIncident(): void
{
  requireAuth();
  $input = getInput();
  $title = trim($input['title'] ?? '');
  $status = $input['status'] ?? '';
  $startedAt = $input['started_at'] ?? date('Y-m-d H:i:s');
  $resolvedAt = $input['resolved_at'] ?? null;

  if (!$title) jsonResponse(['error' => 'Title is required'], 400);
  if (!in_array($status, ['ongoing', 'observation', 'resolved'])) {
    jsonResponse(['error' => 'Invalid status'], 400);
  }
  if ($status === 'resolved' && !$resolvedAt) {
    jsonResponse(['error' => 'resolved_at is required when status is resolved'], 400);
  }

  $db = getDb();
  $stmt = $db->prepare("INSERT INTO incidents (title, status, started_at, resolved_at) VALUES (?, ?, ?, ?)");
  $stmt->execute([$title, $status, $startedAt, $resolvedAt]);
  jsonResponse(['id' => (int) $db->lastInsertId()]);
}

function apiUpdateIncident(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $existing = $db->prepare("SELECT id FROM incidents WHERE id = ?");
  $existing->execute([$id]);
  if (!$existing->fetch()) jsonResponse(['error' => 'Not found'], 404);

  $title = trim($input['title'] ?? '');
  $status = $input['status'] ?? '';
  $startedAt = $input['started_at'] ?? null;
  $resolvedAt = $input['resolved_at'] ?? null;

  if (!$title) jsonResponse(['error' => 'Title is required'], 400);
  if (!in_array($status, ['ongoing', 'observation', 'resolved'])) {
    jsonResponse(['error' => 'Invalid status'], 400);
  }
  if ($status === 'resolved' && !$resolvedAt) {
    jsonResponse(['error' => 'resolved_at is required when status is resolved'], 400);
  }

  $stmt = $db->prepare("UPDATE incidents SET title = ?, status = ?, started_at = COALESCE(?, started_at), resolved_at = ?, updated_at = datetime('now') WHERE id = ?");
  $stmt->execute([$title, $status, $startedAt, $resolvedAt, $id]);
  jsonResponse(['ok' => true]);
}

function apiDeleteIncident(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $existing = $db->prepare("SELECT id FROM incidents WHERE id = ?");
  $existing->execute([$id]);
  if (!$existing->fetch()) jsonResponse(['error' => 'Not found'], 404);

  $db->prepare("DELETE FROM incidents WHERE id = ?")->execute([$id]);
  jsonResponse(['ok' => true]);
}

function apiCreateIncidentUpdate(): void
{
  requireAuth();
  $input = getInput();
  $incidentId = (int) ($input['incident_id'] ?? 0);
  $description = trim($input['description'] ?? '');

  if (!$description) jsonResponse(['error' => 'Description is required'], 400);

  $db = getDb();
  $existing = $db->prepare("SELECT id FROM incidents WHERE id = ?");
  $existing->execute([$incidentId]);
  if (!$existing->fetch()) jsonResponse(['error' => 'Incident not found'], 404);

  $createdAt = $input['created_at'] ?? null;
  if ($createdAt) {
    $stmt = $db->prepare("INSERT INTO incident_updates (incident_id, description, created_at) VALUES (?, ?, ?)");
    $stmt->execute([$incidentId, $description, $createdAt]);
  } else {
    $stmt = $db->prepare("INSERT INTO incident_updates (incident_id, description) VALUES (?, ?)");
    $stmt->execute([$incidentId, $description]);
  }

  $db->prepare("UPDATE incidents SET updated_at = datetime('now') WHERE id = ?")->execute([$incidentId]);

  jsonResponse(['id' => (int) $db->lastInsertId()]);
}

function apiUpdateIncidentUpdate(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  $description = trim($input['description'] ?? '');

  if (!$description) jsonResponse(['error' => 'Description is required'], 400);

  $db = getDb();
  $existing = $db->prepare("SELECT id, incident_id FROM incident_updates WHERE id = ?");
  $existing->execute([$id]);
  $row = $existing->fetch();
  if (!$row) jsonResponse(['error' => 'Not found'], 404);

  $createdAt = $input['created_at'] ?? null;
  if ($createdAt) {
    $db->prepare("UPDATE incident_updates SET description = ?, created_at = ? WHERE id = ?")->execute([$description, $createdAt, $id]);
  } else {
    $db->prepare("UPDATE incident_updates SET description = ? WHERE id = ?")->execute([$description, $id]);
  }
  $db->prepare("UPDATE incidents SET updated_at = datetime('now') WHERE id = ?")->execute([$row['incident_id']]);

  jsonResponse(['ok' => true]);
}

function apiDeleteIncidentUpdate(): void
{
  requireAuth();
  $input = getInput();
  $id = (int) ($input['id'] ?? 0);
  if (!$id) jsonResponse(['error' => 'Missing id'], 400);

  $db = getDb();
  $existing = $db->prepare("SELECT id, incident_id FROM incident_updates WHERE id = ?");
  $existing->execute([$id]);
  $row = $existing->fetch();
  if (!$row) jsonResponse(['error' => 'Not found'], 404);

  $db->prepare("DELETE FROM incident_updates WHERE id = ?")->execute([$id]);
  $db->prepare("UPDATE incidents SET updated_at = datetime('now') WHERE id = ?")->execute([$row['incident_id']]);

  jsonResponse(['ok' => true]);
}

// ============================================================================
// API: STATUS PAGE
// ============================================================================

function apiStatusPage(): void
{
  $db = getDb();

  $groups = $db->query("SELECT * FROM groups ORDER BY position, name")->fetchAll();

  $sites = $db->query("
        SELECT s.id, s.name, s.url, s.group_id, s.visible, s.enabled, s.show_url,
               ss.status, ss.last_check, ss.last_up, ss.last_down,
               (SELECT response_time FROM checks WHERE site_id = s.id ORDER BY checked_at DESC LIMIT 1) as response_time
        FROM sites s
        LEFT JOIN site_status ss ON s.id = ss.site_id
        WHERE s.visible = 1
        ORDER BY s.position, s.name
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
        if ($pct >= 96) $group['status'] = 'operational';
        elseif ($pct >= 80) $group['status'] = 'degraded';
        elseif ($pct >= 50) $group['status'] = 'severely_degraded';
        elseif ($pct >= 10) $group['status'] = 'mostly_down';
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
    } elseif ($pct >= 96) {
      $overall['status'] = 'operational';
    } elseif ($pct >= 80) {
      $overall['status'] = 'degraded';
    } elseif ($pct >= 50) {
      $overall['status'] = 'severely_degraded';
    } elseif ($pct >= 10) {
      $overall['status'] = 'mostly_down';
    } else {
      $overall['status'] = 'down';
    }
  }

  // Active incidents (ongoing + observation)
  $activeIncidents = $db->query("
        SELECT * FROM incidents
        WHERE status IN ('ongoing', 'observation')
        ORDER BY CASE status WHEN 'ongoing' THEN 0 ELSE 1 END, started_at DESC
    ")->fetchAll();

  // Recently resolved (within 24h)
  $recentResolved = $db->query("
        SELECT * FROM incidents
        WHERE status = 'resolved' AND resolved_at > datetime('now', '-24 hours')
        ORDER BY resolved_at DESC
    ")->fetchAll();

  // History (resolved > 24h, last 90 days, capped at 20)
  $history = $db->query("
        SELECT * FROM incidents
        WHERE status = 'resolved'
          AND resolved_at <= datetime('now', '-24 hours')
          AND resolved_at > datetime('now', '-90 days')
        ORDER BY resolved_at DESC
        LIMIT 20
    ")->fetchAll();

  $addUpdates = function (&$list) use ($db) {
    foreach ($list as &$incident) {
      $stmt = $db->prepare("SELECT id, description, created_at FROM incident_updates WHERE incident_id = ? ORDER BY created_at ASC");
      $stmt->execute([$incident['id']]);
      $incident['updates'] = $stmt->fetchAll();
    }
    unset($incident);
  };
  $addUpdates($activeIncidents);
  $addUpdates($recentResolved);
  $addUpdates($history);

  jsonResponse([
    'groups' => $groups,
    'sites' => $sites,
    'overall' => $overall,
    'incidents' => array_values($activeIncidents),
    'recent_resolved' => array_values($recentResolved),
    'incidents_history' => array_values($history),
  ]);
}

// ============================================================================
// API: SETTINGS
// ============================================================================

function apiGetSettings(): void
{
  requireAuth();
  $db = getDb();
  $rows = $db->query("SELECT key, value FROM settings")->fetchAll();
  $settings = [];
  foreach ($rows as $row) {
    $settings[$row['key']] = $row['value'];
  }
  jsonResponse($settings);
}

function apiUpdateSettings(): void
{
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

function apiGenerateCronToken(): void
{
  requireAuth();
  $token = generateToken(32);
  setSetting('cron_token', $token);
  jsonResponse(['cron_token' => $token]);
}

// ============================================================================
// API: UPDATES
// ============================================================================

function apiCheckUpdate(): void
{
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

function apiApplyUpdate(): void
{
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

function apiCleanupChecks(): void
{
  verifyCronToken();
  $result = cleanupChecks();
  jsonResponse($result);
}

function apiHealthCheck(): void
{
  $db = getDb();
  try {
    $db->query('SELECT 1');
  } catch (\Exception $e) {
    jsonResponse(['status' => 'unhealthy', 'error' => 'Database unreachable'], 503);
  }
  jsonResponse(['status' => 'healthy']);
}
