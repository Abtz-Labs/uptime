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

function colorGreen(string $s): string { return "\033[32m" . $s . "\033[0m"; }
function colorRed(string $s): string { return "\033[31m" . $s . "\033[0m"; }
function colorBold(string $s): string { return "\033[1m" . $s . "\033[0m"; }

function assert_eq($expected, $actual, string $msg): void {
    global $passed, $failed;
    if ($expected === $actual) {
        $passed++;
        echo '  ' . colorGreen('PASS') . " $msg\n";
    } else {
        $failed++;
        echo '  ' . colorRed('FAIL') . " $msg\n";
        echo '    ' . colorRed('expected: ' . var_export($expected, true)) . "\n";
        echo '    ' . colorRed('actual:   ' . var_export($actual, true)) . "\n";
    }
}

function assert_true($val, string $msg): void {
    assert_eq(true, (bool)$val, $msg);
}

function section(string $name): void {
    echo "\n" . colorBold("=== $name ===") . "\n";
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

// Overall uptime in status page response
$r = req('status_page');
assert_true(array_key_exists('overall', $r['body']), 'status_page includes overall');
$overall = $r['body']['overall'];
assert_true(array_key_exists('uptime_24h', $overall), 'overall has uptime_24h');
assert_true(array_key_exists('uptime_7d', $overall), 'overall has uptime_7d');
assert_true(array_key_exists('uptime_30d', $overall), 'overall has uptime_30d');
assert_true(array_key_exists('uptime_90d', $overall), 'overall has uptime_90d');
assert_true(array_key_exists('status', $overall), 'overall has status');
assert_true(in_array($overall['status'], ['operational', 'degraded', 'severely_degraded', 'down', 'unknown']), 'overall status is valid');
assert_true(is_numeric($overall['uptime_24h']) || $overall['uptime_24h'] === null, 'uptime_24h is numeric or null');

// Group uptime in status page response
$r = req('status_page');
$groups = $r['body']['groups'] ?? [];
$groupWithSites = array_values(array_filter($groups, fn($g) => $g['id'] == $groupId));
if (count($groupWithSites) > 0) {
    $group = $groupWithSites[0];
    assert_true(array_key_exists('uptime_24h', $group), 'group includes uptime_24h');
    assert_true(array_key_exists('status', $group), 'group includes status');
    assert_true(in_array($group['status'], ['operational', 'degraded', 'severely_degraded', 'down', 'unknown']), 'group status is valid');
    assert_true(is_numeric($group['uptime_24h']) || $group['uptime_24h'] === null, 'group uptime_24h is numeric or null');
}

// ─── STATUS THRESHOLDS ──────────────────────────────────
section('Status Thresholds');

// Connect directly to test DB to insert synthetic check data
$testDb = new PDO('sqlite:' . $TEST_DB, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

// Create a dedicated group and sites for threshold tests
$r = req('create_group', ['name' => 'Threshold Group'], 'POST', $adminCsrf);
$thresholdGroupId = $r['body']['id'];

// Helper: create a site and insert checks with a given up ratio
function createSiteWithUptime(string $name, int $groupId, float $upRatio, string $csrf): int {
    global $testDb, $adminCsrf;
    $r = req('create_site', ['name' => $name, 'url' => "https://$name.test", 'group_id' => $groupId], 'POST', $csrf);
    $id = $r['body']['id'];

    // Insert 100 checks in the last 24 hours
    $upCount = (int) round($upRatio * 100);
    $now = time();
    for ($i = 0; $i < 100; $i++) {
        $status = $i < $upCount ? 'up' : 'down';
        $checkedAt = date('Y-m-d H:i:s', $now - ($i * 60)); // every minute going back
        $testDb->prepare("INSERT INTO checks (site_id, status, status_code, response_time, checked_at) VALUES (?, ?, ?, ?, ?)")
            ->execute([$id, $status, $status === 'up' ? 200 : 503, 100, $checkedAt]);
    }
    return $id;
}

// Test: 100% up → operational (≥85%)
$opSiteId = createSiteWithUptime('operational-site', $thresholdGroupId, 1.0, $adminCsrf);
$r = req('status_page');
$overall = $r['body']['overall'];
assert_eq('operational', $overall['status'], 'overall status is operational at 100% uptime');

// Verify group status too
$groups = $r['body']['groups'];
$tg = array_values(array_filter($groups, fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('operational', $tg['status'], 'group status is operational at 100% uptime');

// Clean up and test: 50% up → degraded (20-84%)
req('delete_site', ['id' => $opSiteId], 'POST', $adminCsrf);
$degSiteId = createSiteWithUptime('degraded-site', $thresholdGroupId, 0.5, $adminCsrf);
$r = req('status_page');
$tg = array_values(array_filter($r['body']['groups'], fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('degraded', $tg['status'], 'group status is degraded at 50% uptime');

// Also check overall (this is now the only visible site besides $siteId which has real checks)
// We test overall by making this the only site (hide the other)
req('update_site', ['id' => $siteId, 'visible' => 0], 'POST', $adminCsrf);
$r = req('status_page');
assert_eq('degraded', $r['body']['overall']['status'], 'overall status is degraded at 50% uptime');

// Clean up and test: 10% up → severely_degraded (1-19%)
req('delete_site', ['id' => $degSiteId], 'POST', $adminCsrf);
$sevSiteId = createSiteWithUptime('severe-site', $thresholdGroupId, 0.10, $adminCsrf);
$r = req('status_page');
$tg = array_values(array_filter($r['body']['groups'], fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('severely_degraded', $tg['status'], 'group status is severely_degraded at 10% uptime');
assert_eq('severely_degraded', $r['body']['overall']['status'], 'overall status is severely_degraded at 10% uptime');

// Clean up and test: 0% up → down
req('delete_site', ['id' => $sevSiteId], 'POST', $adminCsrf);
$downSiteId = createSiteWithUptime('down-site', $thresholdGroupId, 0.0, $adminCsrf);
$r = req('status_page');
$tg = array_values(array_filter($r['body']['groups'], fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('down', $tg['status'], 'group status is down at 0% uptime');
assert_eq('down', $r['body']['overall']['status'], 'overall status is down at 0% uptime');

// Test boundary: exactly 85% → operational
req('delete_site', ['id' => $downSiteId], 'POST', $adminCsrf);
$boundarySiteId = createSiteWithUptime('boundary-site', $thresholdGroupId, 0.85, $adminCsrf);
$r = req('status_page');
$tg = array_values(array_filter($r['body']['groups'], fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('operational', $tg['status'], 'group status is operational at exactly 85% uptime');

// Test boundary: exactly 20% → degraded
req('delete_site', ['id' => $boundarySiteId], 'POST', $adminCsrf);
$boundary2SiteId = createSiteWithUptime('boundary2-site', $thresholdGroupId, 0.20, $adminCsrf);
$r = req('status_page');
$tg = array_values(array_filter($r['body']['groups'], fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('degraded', $tg['status'], 'group status is degraded at exactly 20% uptime');

// Test boundary: exactly 1% → severely_degraded
req('delete_site', ['id' => $boundary2SiteId], 'POST', $adminCsrf);
$boundary3SiteId = createSiteWithUptime('boundary3-site', $thresholdGroupId, 0.01, $adminCsrf);
$r = req('status_page');
$tg = array_values(array_filter($r['body']['groups'], fn($g) => $g['id'] == $thresholdGroupId))[0] ?? [];
assert_eq('severely_degraded', $tg['status'], 'group status is severely_degraded at exactly 1% uptime');

// Clean up threshold tests
req('delete_site', ['id' => $boundary3SiteId], 'POST', $adminCsrf);
req('delete_group', ['id' => $thresholdGroupId], 'POST', $adminCsrf);
req('update_site', ['id' => $siteId, 'visible' => 1], 'POST', $adminCsrf);

// ─── SHOW URL PER-SITE ─────────────────────────────────
section('Show URL Per-Site');

// show_url per-site — ON by default
$r = req('status_page');
$statusSite = $r['body']['sites'][0] ?? [];
assert_true(!empty($statusSite['url']), 'site URL included by default (show_url=1)');

// Disable show_url on this site
$r = req('update_site', ['id' => $siteId, 'show_url' => 0], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update site show_url to 0');

$r = req('status_page');
$statusSite = array_values(array_filter($r['body']['sites'], fn($s) => $s['id'] == $siteId))[0] ?? [];
assert_true(!array_key_exists('url', $statusSite), 'site URL omitted when show_url is off');

// Re-enable show_url
$r = req('update_site', ['id' => $siteId, 'show_url' => 1], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'restore site show_url to 1');

$r = req('status_page');
$statusSite = array_values(array_filter($r['body']['sites'], fn($s) => $s['id'] == $siteId))[0] ?? [];
assert_true(!empty($statusSite['url']), 'site URL included after re-enabling show_url');

// New sites default to show_url=1
$r = req('create_site', ['name' => 'ShowUrl Test', 'url' => 'https://showurl.test'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create site for show_url default test');
$showUrlTestId = $r['body']['id'];
$r = req('list_sites');
$showUrlSite = array_values(array_filter($r['body'], fn($s) => $s['id'] == $showUrlTestId))[0] ?? [];
assert_eq(1, (int)($showUrlSite['show_url'] ?? 0), 'new site defaults to show_url=1');
$r = req('delete_site', ['id' => $showUrlTestId], 'POST', $adminCsrf);

// ─── EXPECTED KEYWORD ────────────────────────────────────
section('Expected Keyword');

// Keyword is stored when method is GET
$r = req('create_site', [
    'name' => 'Keyword Test',
    'url' => 'https://example.com',
    'method' => 'GET',
    'expected_keyword' => 'Example Domain',
    'interval' => 1,
], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create site with keyword');
$kwSiteId = $r['body']['id'];

$r = req('list_sites');
$kwSite = array_values(array_filter($r['body'], fn($s) => $s['id'] == $kwSiteId))[0] ?? [];
assert_eq('Example Domain', $kwSite['expected_keyword'] ?? '', 'keyword stored on create');

// Keyword is cleared when method is HEAD (create)
$r = req('create_site', [
    'name' => 'HEAD Keyword Test',
    'url' => 'https://example.com',
    'method' => 'HEAD',
    'expected_keyword' => 'ShouldBeCleared',
    'interval' => 1,
], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create HEAD site with keyword');
$headKwSiteId = $r['body']['id'];

$r = req('list_sites');
$headKwSite = array_values(array_filter($r['body'], fn($s) => $s['id'] == $headKwSiteId))[0] ?? [];
assert_eq('', $headKwSite['expected_keyword'] ?? 'NOT_EMPTY', 'keyword cleared on create when method is HEAD');

// Keyword is cleared when method is updated to HEAD
$r = req('update_site', ['id' => $kwSiteId, 'method' => 'HEAD'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update method to HEAD');

$r = req('list_sites');
$kwSite = array_values(array_filter($r['body'], fn($s) => $s['id'] == $kwSiteId))[0] ?? [];
assert_eq('', $kwSite['expected_keyword'] ?? 'NOT_EMPTY', 'keyword cleared on update when method changed to HEAD');

// Restore to GET with a keyword for the matching tests
// Page contains "Example Domain" — using "example domain" (lowercase) to test case-insensitivity
$r = req('update_site', ['id' => $kwSiteId, 'method' => 'GET', 'expected_keyword' => 'example domain'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'restore site to GET with keyword');

sleep(2);
$r = req('run_checks');
assert_eq(200, $r['status'], 'run_checks for keyword test');

$r = req('list_checks', ['site_id' => $kwSiteId]);
$lastCheck = $r['body'][0] ?? [];
assert_eq('up', $lastCheck['status'] ?? '', 'case-insensitive keyword match marks site up');

// Keyword NOT found marks site down
$r = req('update_site', ['id' => $kwSiteId, 'expected_keyword' => 'xyznonexistent999'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'update keyword to non-matching string');

sleep(2);
$r = req('run_checks');
assert_eq(200, $r['status'], 'run_checks for missing keyword');

$r = req('list_checks', ['site_id' => $kwSiteId]);
$lastCheck = $r['body'][0] ?? [];
assert_eq('down', $lastCheck['status'] ?? '', 'missing keyword marks site down');
assert_true(str_contains($lastCheck['message'] ?? '', 'not found'), 'message indicates keyword not found');

// Cleanup test sites
$r = req('delete_site', ['id' => $kwSiteId], 'POST', $adminCsrf);
$r = req('delete_site', ['id' => $headKwSiteId], 'POST', $adminCsrf);

// ─── SITE REORDERING ────────────────────────────────────
section('Site Reordering');

// Create sites and verify they get auto-assigned positions
$r = req('create_site', ['name' => 'Alpha Site', 'url' => 'https://alpha.test'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create alpha site');
$alphaSiteId = $r['body']['id'];

$r = req('create_site', ['name' => 'Beta Site', 'url' => 'https://beta.test'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create beta site');
$betaSiteId = $r['body']['id'];

$r = req('create_site', ['name' => 'Gamma Site', 'url' => 'https://gamma.test'], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'create gamma site');
$gammaSiteId = $r['body']['id'];

// Verify initial order (by position, then name)
$r = req('list_sites');
$siteIds = array_map(fn($s) => (int) $s['id'], $r['body']);
$alphaIdx = array_search($alphaSiteId, $siteIds);
$betaIdx = array_search($betaSiteId, $siteIds);
$gammaIdx = array_search($gammaSiteId, $siteIds);
assert_true($alphaIdx < $betaIdx && $betaIdx < $gammaIdx, 'sites are ordered by creation position');

// Reorder: Gamma, Alpha, Beta
$r = req('reorder_sites', ['ids' => [$gammaSiteId, $alphaSiteId, $betaSiteId]], 'POST', $adminCsrf);
assert_eq(200, $r['status'], 'reorder_sites succeeds');

$r = req('list_sites');
$siteIds = array_map(fn($s) => (int) $s['id'], $r['body']);
$alphaIdx = array_search($alphaSiteId, $siteIds);
$betaIdx = array_search($betaSiteId, $siteIds);
$gammaIdx = array_search($gammaSiteId, $siteIds);
assert_true($gammaIdx < $alphaIdx && $alphaIdx < $betaIdx, 'sites reordered: gamma < alpha < beta');

// Reorder rejects empty ids
$r = req('reorder_sites', ['ids' => []], 'POST', $adminCsrf);
assert_eq(400, $r['status'], 'reorder_sites rejects empty ids');

// Status page respects site order
$r = req('update_site', ['id' => $alphaSiteId, 'visible' => 1], 'POST', $adminCsrf);
$r = req('update_site', ['id' => $betaSiteId, 'visible' => 1], 'POST', $adminCsrf);
$r = req('update_site', ['id' => $gammaSiteId, 'visible' => 1], 'POST', $adminCsrf);

$r = req('status_page');
$statusSiteIds = array_map(fn($s) => (int) $s['id'], $r['body']['sites']);
$alphaIdx = array_search($alphaSiteId, $statusSiteIds);
$betaIdx = array_search($betaSiteId, $statusSiteIds);
$gammaIdx = array_search($gammaSiteId, $statusSiteIds);
assert_true($gammaIdx < $alphaIdx && $alphaIdx < $betaIdx, 'status page respects site reorder');

// New site after reorder lands at the end, not position 0
$r = req('create_site', ['name' => 'Delta Site', 'url' => 'https://delta.test'], 'POST', $adminCsrf);
$deltaSiteId = $r['body']['id'];

$r = req('list_sites');
$siteIds = array_map(fn($s) => (int) $s['id'], $r['body']);
$betaIdx = array_search($betaSiteId, $siteIds);
$deltaIdx = array_search($deltaSiteId, $siteIds);
assert_true($deltaIdx > $betaIdx, 'new site after reorder appends to end');

// Deleting a site does not break order of remaining sites
$r = req('delete_site', ['id' => $alphaSiteId], 'POST', $adminCsrf);

$r = req('list_sites');
$siteIds = array_map(fn($s) => (int) $s['id'], $r['body']);
$gammaIdx = array_search($gammaSiteId, $siteIds);
$betaIdx = array_search($betaSiteId, $siteIds);
$deltaIdx = array_search($deltaSiteId, $siteIds);
assert_true($gammaIdx < $betaIdx && $betaIdx < $deltaIdx, 'order preserved after deleting a middle site');

// Cleanup
$r = req('delete_site', ['id' => $betaSiteId], 'POST', $adminCsrf);
$r = req('delete_site', ['id' => $gammaSiteId], 'POST', $adminCsrf);
$r = req('delete_site', ['id' => $deltaSiteId], 'POST', $adminCsrf);

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

// app_name only affects the status page title, not the dashboard
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_COOKIEFILE => $cookieFile,
]);
$html = curl_exec($ch);
curl_close($ch);
assert_true(str_contains($html, '<title>My Uptime'), 'status page uses custom app_name in title');
assert_true(str_contains($html, '>My Uptime<'), 'status page uses custom app_name in heading');

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "$BASE/dash",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_COOKIEFILE => $cookieFile,
    CURLOPT_COOKIEJAR => $cookieFile,
    CURLOPT_FOLLOWLOCATION => true,
]);
$html = curl_exec($ch);
curl_close($ch);
assert_true(str_contains($html, '<title>Dashboard — Uptime</title>'), 'dashboard title always says Uptime');
assert_true(!str_contains($html, 'My Uptime'), 'dashboard does not use custom app_name');

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
$total = $passed + $failed;
echo "\n" . colorBold(str_repeat('=', 64)) . "\n";
if ($failed === 0) {
    echo colorGreen('ALL TESTS PASSED') . "\n";
} else {
    echo colorRed('TESTS FAILED') . "\n";
}
echo colorBold("Pass: {$passed}  Fail: {$failed}  Total: {$total}") . "\n";

// Cleanup
proc_terminate($serverProc);
proc_close($serverProc);
@unlink($cookieFile);
@unlink($TEST_DB);

exit($failed > 0 ? 1 : 0);
