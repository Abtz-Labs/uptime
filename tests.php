<?php
/**
 * Uptime Tool API Test Suite
 * Run: php tests.php
 * Spins up its own test server using test.sqlite (never touches uptime.sqlite).
 */
error_reporting(E_ALL & ~E_DEPRECATED);

$TEST_PORT = 8090;
$TEST_DB = __DIR__ . '/test.sqlite';
$BASE = "http://localhost:$TEST_PORT";
$passed = 0;
$failed = 0;
$cookieFile = tempnam(sys_get_temp_dir(), 'uptime_test_');

// Clean previous test DB
@unlink($TEST_DB);

// Start a dedicated test server
$serverCmd = sprintf(
    'UPTIME_DB_FILE=%s UPTIME_STRICT_CRON=1 php -S localhost:%d -t %s %s/index.php',
    escapeshellarg($TEST_DB),
    $TEST_PORT,
    escapeshellarg(__DIR__),
    escapeshellarg(__DIR__)
);
$serverProc = proc_open($serverCmd, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
if (!$serverProc) {
    echo "Failed to start test server.\n";
    exit(1);
}
// Wait for server to be ready
$ready = false;
for ($i = 0; $i < 50; $i++) {
    $sock = @fsockopen('localhost', $TEST_PORT, $errno, $errstr, 0.1);
    if ($sock) { fclose($sock); $ready = true; break; }
    usleep(100_000);
}
if (!$ready) {
    echo "Test server failed to start on port $TEST_PORT.\n";
    proc_terminate($serverProc);
    exit(1);
}

function req(string $action, array $data = [], string $method = 'GET', string $csrf = '', string $cookie = ''): array {
    global $BASE, $cookieFile;
    $url = "$BASE/?action=$action";
    $ch = curl_init();

    if ($method === 'GET' && $data) {
        $url .= '&' . http_build_query($data);
    }

    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_COOKIEFILE => $cookie ?: $cookieFile,
        CURLOPT_COOKIEJAR => $cookie ?: $cookieFile,
    ]);

    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        $headers = ['Content-Type: application/json'];
        if ($csrf) $headers[] = "X-CSRF-Token: $csrf";
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $body = substr($response, $headerSize);
    curl_close($ch);

    return ['status' => $httpCode, 'body' => json_decode($body, true) ?? [], 'raw' => $body];
}

function assert_eq($expected, $actual, string $msg): void {
    global $passed, $failed;
    if ($expected === $actual) {
        $passed++;
        echo "  ✓ $msg\n";
    } else {
        $failed++;
        echo "  ✗ $msg\n    Expected: " . json_encode($expected) . "\n    Got:      " . json_encode($actual) . "\n";
    }
}

function assert_true($val, string $msg): void {
    assert_eq(true, (bool)$val, $msg);
}

function section(string $name): void {
    echo "\n\033[1m[$name]\033[0m\n";
}

echo "Uptime Tool Test Suite\n";
echo str_repeat('=', 40) . "\n";

// ─── SETUP ───────────────────────────────────────────────
section('Setup / First User');

$r = req('auth_status');
assert_eq(200, $r['status'], 'auth_status returns 200');
assert_true($r['body']['needs_setup'], 'needs_setup is true with no users');
assert_eq(false, $r['body']['authenticated'], 'not authenticated initially');

$r = req('auth_setup', ['name' => 'Admin', 'email' => 'admin@test.com', 'password' => 'admin123'], 'POST');
assert_eq(200, $r['status'], 'setup succeeds');
assert_true(!empty($r['body']['csrf_token']), 'returns CSRF token');
assert_true(!empty($r['body']['recovery_key']), 'setup returns recovery key');
$recoveryKey = $r['body']['recovery_key'];
$adminCsrf = $r['body']['csrf_token'];

$r = req('auth_status');
assert_eq(true, $r['body']['authenticated'], 'authenticated after setup');
assert_eq(false, $r['body']['needs_setup'], 'needs_setup is false after setup');

$r = req('auth_setup', ['name' => 'Dup', 'email' => 'dup@test.com', 'password' => '123456'], 'POST');
assert_eq(400, $r['status'], 'cannot run setup again');

// ─── LOGIN ───────────────────────────────────────────────
section('Login');

$r = req('auth_logout', [], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'logout succeeds');

// New session after logout
@unlink($cookieFile);
$cookieFile = tempnam(sys_get_temp_dir(), 'uptime_test_');

$r = req('auth_status');
assert_eq(false, $r['body']['authenticated'], 'not authenticated after logout');

$r = req('auth_login', ['email' => 'admin@test.com', 'password' => 'wrong'], 'POST');
assert_eq(403, $r['status'], 'wrong password returns 403');

$r = req('auth_login', ['email' => 'admin@test.com', 'password' => 'admin123'], 'POST');
assert_eq(200, $r['status'], 'correct login succeeds');
$adminCsrf = $r['body']['csrf_token'];

// ─── RECOVERY KEY ────────────────────────────────────────
section('Recovery Key');

// Logout and try recovery key login
$r = req('auth_logout', [], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'logout before recovery test');
@unlink($cookieFile);
$cookieFile = tempnam(sys_get_temp_dir(), 'uptime_test_');

// Old key is still valid before first key-based login
$r = req('auth_login', ['email' => 'admin@test.com', 'password' => $recoveryKey], 'POST');
assert_eq(200, $r['status'], 'login with original recovery key succeeds');
assert_true(!empty($r['body']['recovery_key']), 'returns rotated recovery key');
assert_eq(true, $r['body']['password_reset'] ?? false, 'password reset required after recovery login');
$rotatedKey = $r['body']['recovery_key'];
$adminCsrf = $r['body']['csrf_token'];

// Old key is now invalid
@unlink($cookieFile);
$cookieFile = tempnam(sys_get_temp_dir(), 'uptime_test_');
$r = req('auth_login', ['email' => 'admin@test.com', 'password' => $recoveryKey], 'POST');
assert_eq(403, $r['status'], 'old recovery key is rejected after rotation');

// Login again with rotated key to reset session
$r = req('auth_login', ['email' => 'admin@test.com', 'password' => $rotatedKey], 'POST');
assert_eq(200, $r['status'], 'login with rotated recovery key succeeds');
$adminCsrf = $r['body']['csrf_token'];

// Password change without current password during reset
$r = req('account_update', ['name' => 'Admin', 'email' => 'admin@test.com', 'password' => 'admin123'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'password change succeeds without current password during reset');

// Normal login still works
@unlink($cookieFile);
$cookieFile = tempnam(sys_get_temp_dir(), 'uptime_test_');
$r = req('auth_login', ['email' => 'admin@test.com', 'password' => 'admin123'], 'POST');
assert_eq(200, $r['status'], 'normal login works after reset');
assert_true(empty($r['body']['recovery_key']), 'no recovery key returned on normal login');
$adminCsrf = $r['body']['csrf_token'];

// Password change without current password (not in reset) is rejected
$r = req('account_update', ['name' => 'Admin', 'email' => 'admin@test.com', 'password' => 'something'], 'POST', $adminCsrf);
assert_eq(403, $r['status'], 'password change without current password rejected when not in reset');

// Regenerate recovery key requires password
$r = req('regenerate_recovery_key', ['password' => 'wrong'], 'POST', $adminCsrf);
assert_eq(403, $r['status'], 'regenerate recovery key rejects wrong password');

$r = req('regenerate_recovery_key', ['password' => 'admin123'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'regenerate recovery key succeeds');
assert_true(!empty($r['body']['recovery_key']), 'regenerate returns new recovery key');
$newKey = $r['body']['recovery_key'];

// New key works for login, old rotated key does not
@unlink($cookieFile);
$cookieFile = tempnam(sys_get_temp_dir(), 'uptime_test_');
$r = req('auth_login', ['email' => 'admin@test.com', 'password' => $newKey], 'POST');
assert_eq(200, $r['status'], 'newly regenerated key works for login');
$adminCsrf = $r['body']['csrf_token'];

// ─── GROUPS ──────────────────────────────────────────────
section('Groups');

$r = req('list_groups');
assert_eq(200, $r['status'], 'list_groups returns 200');
assert_eq(0, count($r['body']), 'no groups initially');

$r = req('create_group', ['name' => 'Production'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create group succeeds');
$groupId = $r['body']['id'];

$r = req('create_group', ['name' => 'Staging'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create second group');
$groupId2 = $r['body']['id'];

$r = req('list_groups');
assert_eq(2, count($r['body']), 'two groups after create');

$r = req('update_group', ['id' => $groupId, 'name' => 'Production Env'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update group name');

$r = req('update_group', ['id' => $groupId, 'position' => 5], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update group position');

$r = req('list_groups');
$prod = array_values(array_filter($r['body'], fn($g) => $g['id'] == $groupId))[0] ?? null;
assert_eq('Production Env', $prod['name'] ?? '', 'group name updated');
assert_eq(5, $prod['position'] ?? -1, 'group position updated');

$r = req('reorder_groups', ['ids' => [$groupId2, $groupId]], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'reorder_groups succeeds');

$r = req('list_groups');
$prod = array_values(array_filter($r['body'], fn($g) => $g['id'] == $groupId))[0] ?? null;
$staging = array_values(array_filter($r['body'], fn($g) => $g['id'] == $groupId2))[0] ?? null;
assert_eq(1, $prod['position'] ?? -1, 'reorder: production moved to position 1');
assert_eq(0, $staging['position'] ?? -1, 'reorder: staging moved to position 0');

$r = req('reorder_groups', ['ids' => []], 'POST', $adminCsrf);
assert_eq(400, $r['status'], 'reorder_groups rejects empty ids');

// ─── SITES ───────────────────────────────────────────────
section('Sites');

$r = req('list_sites');
assert_eq(200, $r['status'], 'list_sites returns 200');
assert_eq(0, count($r['body']), 'no sites initially');

$r = req('create_site', [
    'name' => 'Example',
    'url' => 'https://example.com',
    'interval' => 60,
    'group_id' => $groupId,
], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create site succeeds');
$siteId = $r['body']['id'];

$r = req('create_site', [
    'name' => 'Google',
    'url' => 'https://google.com',
    'interval' => 30,
    'group_id' => $groupId,
], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create second site');
$siteId2 = $r['body']['id'];

$r = req('list_sites');
assert_eq(2, count($r['body']), 'two sites after create');

$r = req('update_site', ['id' => $siteId, 'name' => 'Example Updated', 'enabled' => 0], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update site');

$r = req('list_sites');
$site = array_values(array_filter($r['body'], fn($s) => $s['id'] == $siteId))[0] ?? null;
assert_eq('Example Updated', $site['name'] ?? '', 'site name updated');
assert_eq(0, (int)($site['enabled'] ?? 1), 'site disabled');

// Re-enable for check tests
$r = req('update_site', ['id' => $siteId, 'enabled' => 1], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 're-enable site');

$r = req('delete_site', ['id' => $siteId2], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'delete site');

$r = req('list_sites');
assert_eq(1, count($r['body']), 'one site after delete');

// ─── CHECKS ──────────────────────────────────────────────
section('Checks');

// Run checks (cron endpoint)
$r = req('run_checks');
assert_eq(200, $r['status'], 'run_checks returns 200');
assert_true(array_key_exists('checked', $r['body']), 'run_checks reports checked count');

// List checks for the site
$r = req('list_checks', ['site_id' => $siteId]);
assert_eq(200, $r['status'], 'list_checks returns 200');
assert_true(count($r['body']) >= 1, 'at least one check after run_checks');
$check = $r['body'][0];
assert_eq('up', $check['status'], 'healthy site (example.com) is reported as up');
assert_eq(200, $check['status_code'], 'check status_code is 200');
assert_true(!empty($check['checked_at']), 'check has checked_at');

// Site status updated
$r = req('list_sites');
$site = array_values(array_filter($r['body'], fn($s) => $s['id'] == $siteId))[0] ?? null;
assert_true(!empty($site['status']), 'site has status field');
assert_eq('up', $site['status'], 'site status is up in list_sites');

// ─── WEBHOOKS (per-site) ─────────────────────────────────
section('Webhooks');

$r = req('list_webhooks', ['site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'list_webhooks returns 200');
assert_eq(0, count($r['body']), 'no webhooks initially');

$r = req('create_webhook', ['url' => 'https://hooks.slack.com/test', 'type' => 'slack', 'site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create webhook succeeds');
$webhookId = $r['body']['id'];

$r = req('create_webhook', ['url' => 'not-a-url', 'type' => 'generic', 'site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(400, $r['status'], 'invalid URL rejected');

$r = req('create_webhook', ['url' => 'https://example.com', 'type' => 'invalid', 'site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(400, $r['status'], 'invalid type rejected');

$r = req('create_webhook', ['url' => 'https://example.com', 'type' => 'generic'], 'POST', $adminCsrf);
assert_eq(400, $r['status'], 'missing site_id rejected');

$r = req('list_webhooks', ['site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(1, count($r['body']), 'one webhook for this site');
assert_eq('slack', $r['body'][0]['type'], 'webhook type is slack');
assert_eq($siteId, (int)$r['body'][0]['site_id'], 'webhook belongs to correct site');

$r = req('delete_webhook', ['id' => $webhookId], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'delete webhook succeeds');

$r = req('list_webhooks', ['site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(0, count($r['body']), 'no webhooks after delete');

// Cascade delete: create webhook → delete site → webhooks gone
$r = req('create_webhook', ['url' => 'https://hooks.slack.com/cascade', 'type' => 'slack', 'site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create webhook for cascade test');
$cascadeWebhookId = $r['body']['id'];

$r = req('list_webhooks', ['site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(1, count($r['body']), 'one webhook before site delete');

// Create a throwaway site to delete (preserve $siteId for later tests)
$r = req('create_site', ['name' => 'Cascade Test', 'url' => 'https://cascade.test'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create cascade test site');
$cascadeSiteId = $r['body']['id'];
$r = req('create_webhook', ['url' => 'https://hooks.slack.com/cascade2', 'type' => 'generic', 'site_id' => $cascadeSiteId], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create webhook on cascade site');

$r = req('delete_site', ['id' => $cascadeSiteId], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'delete cascade site');

$r = req('list_webhooks', ['site_id' => $cascadeSiteId], 'POST', $adminCsrf);
assert_eq(0, count($r['body']), 'webhooks cascade-deleted with site');

// Original webhook still intact
$r = req('list_webhooks', ['site_id' => $siteId], 'POST', $adminCsrf);
assert_eq(1, count($r['body']), 'other site webhooks unaffected');

// ─── STATUS PAGE ────────────────────────────────────────
section('Status Page');

// Public status page data (no auth required)
$r = req('status_page');
assert_eq(200, $r['status'], 'status_page returns 200');
assert_true(isset($r['body']['groups']), 'status_page has groups');
assert_true(isset($r['body']['sites']), 'status_page has sites');

// Hidden sites should not appear in status page
$r = req('update_site', ['id' => $siteId, 'visible' => 0], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'hide site from status page');

$r = req('status_page');
$visibleSites = array_filter($r['body']['sites'] ?? [], fn($s) => $s['id'] == $siteId);
assert_eq(0, count($visibleSites), 'hidden site not in status page');

// Re-show
$r = req('update_site', ['id' => $siteId, 'visible' => 1], 'POST', $adminCsrf);

$r = req('status_page');
$visibleSites = array_filter($r['body']['sites'] ?? [], fn($s) => $s['id'] == $siteId);
assert_eq(1, count($visibleSites), 'visible site in status page');

// Enabled field present in status page response
$statusSite = array_values($visibleSites)[0];
assert_true(array_key_exists('enabled', $statusSite), 'status_page site includes enabled field');
assert_eq(1, (int) $statusSite['enabled'], 'visible site is enabled');

// ─── CLEANUP ─────────────────────────────────────────────
section('Cleanup');

$r = req('cleanup_checks');
assert_eq(200, $r['status'], 'cleanup_checks returns 200');
assert_true(isset($r['body']['deleted']), 'cleanup_reports deleted count');

// ─── SETTINGS ────────────────────────────────────────────
section('Settings');

$r = req('get_settings');
assert_eq(200, $r['status'], 'get_settings returns 200');
assert_true(is_array($r['body']), 'settings returns an array');

$r = req('update_settings', ['app_name' => 'My Uptime'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update_settings succeeds');

$r = req('get_settings');
assert_eq('My Uptime', $r['body']['app_name'] ?? '', 'app_name updated');

// ─── SECURITY: HEADERS ──────────────────────────────────
section('Security Headers');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_NOBODY => true,
]);
$headResponse = curl_exec($ch);
curl_close($ch);

assert_true(stripos($headResponse, 'X-Frame-Options: DENY') !== false, 'X-Frame-Options header present');
assert_true(stripos($headResponse, 'X-Content-Type-Options: nosniff') !== false, 'X-Content-Type-Options header present');
assert_true(stripos($headResponse, 'Referrer-Policy: strict-origin-when-cross-origin') !== false, 'Referrer-Policy header present');
assert_true(stripos($headResponse, 'X-Powered-By') === false, 'X-Powered-By header removed');

// ─── SECURITY: SENSITIVE FILE ACCESS ────────────────────
section('Sensitive File Blocking');

$sensitiveFiles = ['uptime.sqlite', 'test.sqlite', 'data.db', '.env', '.git/config'];
foreach ($sensitiveFiles as $f) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => "$BASE/$f",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    assert_eq(403, $code, "access to $f blocked");
}

// ─── SECURITY: CSRF ─────────────────────────────────────
section('CSRF Protection');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/?action=create_site",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => json_encode(['name' => 'Test', 'url' => 'https://test.com']),
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_COOKIEFILE => $cookieFile,
    CURLOPT_COOKIEJAR => $cookieFile,
]);
$resp = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
assert_eq(403, $httpCode, 'POST without CSRF token rejected');

$r = req('create_site', ['name' => 'CSRF Valid', 'url' => 'https://csrf.com'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'POST with valid CSRF token accepted');

// Cleanup CSRF test site
if (isset($r['body']['id'])) {
    req('delete_site', ['id' => $r['body']['id']], 'POST', $adminCsrf);
}

// ─── CRON TOKEN ─────────────────────────────────────────
section('Cron Token');

// Without token set, run_checks works freely
$r = req('run_checks');
assert_eq(200, $r['status'], 'run_checks works without token when none is set');

$r = req('cleanup_checks');
assert_eq(200, $r['status'], 'cleanup_checks works without token when none is set');

// Generate a cron token
$r = req('generate_cron_token', [], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'generate_cron_token succeeds');
assert_true(!empty($r['body']['cron_token']), 'returns a cron token');
$cronToken = $r['body']['cron_token'];

// Without token, run_checks is now rejected
$r = req('run_checks');
assert_eq(401, $r['status'], 'run_checks rejected without token after token is set');

// With wrong token, still rejected
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/?action=run_checks&token=wrong_token",
    CURLOPT_RETURNTRANSFER => true,
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
assert_eq(401, $code, 'run_checks rejected with wrong token');

// With correct token, run_checks works
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/?action=run_checks&token=$cronToken",
    CURLOPT_RETURNTRANSFER => true,
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
assert_eq(200, $code, 'run_checks works with correct token');

// cleanup_checks also requires token
$r = req('cleanup_checks');
assert_eq(401, $r['status'], 'cleanup_checks rejected without token after token is set');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/?action=cleanup_checks&token=$cronToken",
    CURLOPT_RETURNTRANSFER => true,
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
assert_eq(200, $code, 'cleanup_checks works with correct token');

// Regenerating token invalidates old one
$r = req('generate_cron_token', [], 'POST', $adminCsrf);
$newCronToken = $r['body']['cron_token'];
assert_true($newCronToken !== $cronToken, 'new token differs from old');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/?action=run_checks&token=$cronToken",
    CURLOPT_RETURNTRANSFER => true,
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
assert_eq(401, $code, 'old token rejected after regeneration');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/?action=run_checks&token=$newCronToken",
    CURLOPT_RETURNTRANSFER => true,
]);
$body = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
assert_eq(200, $code, 'new token works after regeneration');

// ─── RESULTS ─────────────────────────────────────────────
echo "\n" . str_repeat('=', 40) . "\n";
echo "Results: \033[32m$passed passed\033[0m, " . ($failed ? "\033[31m$failed failed\033[0m" : "0 failed") . "\n";

// Cleanup
proc_terminate($serverProc);
proc_close($serverProc);
@unlink($cookieFile);
@unlink($TEST_DB);

exit($failed > 0 ? 1 : 0);
