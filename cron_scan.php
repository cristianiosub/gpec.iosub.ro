<?php
// ── Activat inainte de orice require — altfel erorile din fisierele incluse sunt ascunse ──
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');

// Handler global pentru erori fatale neasteptate
set_error_handler(function(int $errno, string $errstr, string $errfile, int $errline): bool {
    if (!(error_reporting() & $errno)) return false;
    echo "[ERROR {$errno}] {$errstr} in {$errfile}:{$errline}\n";
    return false; // continua handling standard
});

/**
 * GPeC Cron Scanner — ruleaza automat din cPanel cron jobs
 * Apel: /usr/local/bin/php /path/to/gpec-tool/cron_scan.php
 * Sau via HTTP: cron_scan.php?key=SECRET_KEY[&scan_id=SPECIFIC_ID]
 */

if (PHP_SAPI !== 'cli') {
    require_once __DIR__ . '/config.php';
    $adminPass   = getSetting('admin_password', 'gpec2024');
    $expectedKey = substr(md5($adminPass), 0, 16);
    if (($_GET['key'] ?? '') !== $expectedKey) {
        http_response_code(403); echo 'Forbidden'; exit;
    }
} else {
    require_once __DIR__ . '/config.php';
}
set_time_limit(300);
ignore_user_abort(true);
define('GPEC_FAST_MODE', true); // delays minime (50-150ms in loc de 400-1200ms)

$log = function(string $msg): void {
    $ts = date('Y-m-d H:i:s');
    echo "[{$ts}] {$msg}\n";
    if (PHP_SAPI !== 'cli') flush();
};

$queueEnabled = getSetting('queue_enabled', '1') === '1';
if (!$queueEnabled) { $log('Coada dezactivata. Iesire.'); exit; }

$db = getDB();

// ── Auto-recuperare scanari blocate (running > 10 min, 0 rezultate) ────────
try {
    $db->exec("
        UPDATE scans s SET s.status='queued', s.started_at=NULL
        WHERE s.status='running'
          AND s.started_at < DATE_SUB(NOW(), INTERVAL 10 MINUTE)
          AND (SELECT COUNT(*) FROM results r WHERE r.scan_id=s.id) = 0
    ");
} catch (Throwable) {}

// ── Claim scan ──────────────────────────────────────────────────────────────
$specificId = trim($_GET['scan_id'] ?? $argv[1] ?? '');

if ($specificId) {
    $upd = $db->prepare("UPDATE scans SET status='running', started_at=? WHERE id=? AND status='queued' LIMIT 1");
    $upd->execute([date('Y-m-d H:i:s'), $specificId]);
    if ($upd->rowCount() === 0) {
        $log("Scan {$specificId} nu e disponibil (nu exista, nu e queued, sau deja preluat).");
        exit;
    }
    $row = $db->prepare('SELECT id, domain FROM scans WHERE id=?');
    $row->execute([$specificId]);
    $next = $row->fetch();
} else {
    $db->beginTransaction();
    try {
        $pick = $db->query("SELECT id, domain FROM scans WHERE status='queued' ORDER BY created_at ASC LIMIT 1 FOR UPDATE");
        $next = $pick->fetch();
        if (!$next) { $db->commit(); $log('Coada goala.'); exit; }
        $db->prepare("UPDATE scans SET status='running', started_at=? WHERE id=?")->execute([date('Y-m-d H:i:s'), $next['id']]);
        $db->commit();
    } catch (Throwable $e) {
        $db->rollBack();
        $log('Eroare claim: ' . $e->getMessage());
        exit;
    }
}

$scanId = $next['id'];
$domain = $next['domain'];
$log("START: {$domain} (ID: {$scanId})");

// ── Shutdown safety — daca procesul moare, marcheaza ca eroare ─────────────
register_shutdown_function(function() use ($db, $scanId, $log) {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        $log("FATAL PHP: " . $err['message'] . ' @ ' . $err['file'] . ':' . $err['line']);
    }
    $chk = $db->prepare("SELECT status FROM scans WHERE id=?");
    $chk->execute([$scanId]);
    $row = $chk->fetch();
    if ($row && $row['status'] === 'running') {
        $db->prepare("UPDATE scans SET status='error', finished_at=? WHERE id=?")->execute([date('Y-m-d H:i:s'), $scanId]);
        $log("Scan {$scanId} ramas 'running' la shutdown — marcat 'error'.");
    }
});

// ── Harta checks ───────────────────────────────────────────────────────────
$checkMap = [
    'dedicated_server'  => ['DedicatedServer',  '#1'],
    'malware'           => ['Malware',           '#2'],
    'spam_reputation'   => ['SpamReputation',    '#3'],
    'https_full'        => ['HttpsFull',         '#4'],
    'ssl_config'        => ['SslConfig',         '#5'],
    'critical_ports'    => ['CriticalPorts',     '#6'],
    'cms_updates'       => ['CmsUpdates',        '#7'],
    'email_security'    => ['EmailSecurity',     '#8'],
    'directory_listing' => ['DirectoryListing',  '#9'],
    'brute_force'       => ['BruteForce',        '#10'],
];

// ── FAZA 1: Batch paralel via curl_multi → api.php ─────────────────────────
$adminPass = getSetting('admin_password', 'gpec2024');
$cronKey   = substr(md5($adminPass), 0, 16);

if (PHP_SAPI === 'cli') {
    $baseHost = rtrim(getSetting('site_url', 'http://localhost'), '/');
    $apiUrl   = $baseHost . '/api.php';
} else {
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $apiUrl = $scheme . '://' . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['PHP_SELF']), '/') . '/api.php';
}

$log("FAZA 1: curl_multi → {$apiUrl}");

$mh      = curl_multi_init();
$handles = [];

foreach (array_keys($checkMap) as $check) {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $apiUrl . '?cron_key=' . urlencode($cronKey),
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query(['action' => 'run_check', 'scan_id' => $scanId, 'check' => $check]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 90,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);
    $handles[$check] = $ch;
    curl_multi_add_handle($mh, $ch);
}

$active = null;
do {
    $status = curl_multi_exec($mh, $active);
    if ($active) curl_multi_select($mh, 0.5);
} while ($active && $status === CURLM_OK);

// Inregistreaza ce a reusit si ce nu prin curl
$curlOk  = [];
$curlFail = [];
foreach ($handles as $check => $ch) {
    $curlErr  = curl_errno($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $body     = curl_multi_getcontent($ch);
    curl_multi_remove_handle($mh, $ch);
    curl_close($ch);

    if ($curlErr !== 0 || $httpCode !== 200) {
        $curlFail[$check] = "HTTP {$httpCode} / curl_err {$curlErr}";
        $log("  CURL FAIL {$check}: HTTP={$httpCode} curlErr={$curlErr}");
    } else {
        $decoded = json_decode($body, true);
        if (!($decoded['success'] ?? false)) {
            $curlFail[$check] = $decoded['error'] ?? 'raspuns invalid JSON';
            $log("  API FAIL {$check}: " . ($decoded['error'] ?? substr($body, 0, 100)));
        } else {
            $curlOk[$check] = true;
            $log("  OK {$check}: " . ($decoded['result']['status'] ?? '?'));
        }
    }
}
curl_multi_close($mh);

// ── FAZA 2: Verifica ce lipseste efectiv din DB (sursa de adevar) ──────────
// (un check putea esua dupa salvare — DB e mai fiabil decat raspunsul curl)
$savedStmt = $db->prepare('SELECT gpec_id FROM results WHERE scan_id=?');
$savedStmt->execute([$scanId]);
$savedGpecIds = $savedStmt->fetchAll(PDO::FETCH_COLUMN);

$gpecToCheck = array_column($checkMap, 0, 0); // pentru lookup rapid
$missing = [];
foreach ($checkMap as $checkKey => [$className, $gpecId]) {
    if (!in_array($gpecId, $savedGpecIds, true)) {
        $missing[$checkKey] = [$className, $gpecId];
    }
}

// ── FAZA 3: Retry via HTTP (curl) pentru checks lipsa ────────────────────
// IMPORTANT: Retry merge tot prin api.php (HTTP), NU direct in PHP.
// Astfel, daca un check face PHP fatal error, el moare in procesul HTTP separat,
// nu in procesul cron — scanul continua normal cu celelalte checks.
if ($missing) {
    $log("FAZA 2: Retry HTTP pentru " . count($missing) . " checks lipsa: " . implode(', ', array_keys($missing)));

    foreach ($missing as $checkKey => [$className, $gpecId]) {
        $lastError = null;
        $success   = false;

        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $log("  Retry {$gpecId} ({$checkKey}) via HTTP — incercarea {$attempt}/3");

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $apiUrl . '?cron_key=' . urlencode($cronKey),
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => http_build_query(['action' => 'run_check', 'scan_id' => $scanId, 'check' => $checkKey]),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 150, // timeout mai lung pentru retry
                CURLOPT_CONNECTTIMEOUT => 15,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ]);
            $body    = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlErr  = curl_errno($ch);
            $curlErrMsg = curl_error($ch);
            curl_close($ch);

            if ($curlErr !== 0 || $httpCode !== 200) {
                $lastError = "HTTP {$httpCode} / curl_err {$curlErr}: {$curlErrMsg}";
                $log("  Retry {$attempt} fail: {$lastError}");
                if ($attempt < 3) sleep(3);
                continue;
            }

            $decoded = json_decode($body, true);
            if (!($decoded['success'] ?? false)) {
                $lastError = $decoded['error'] ?? 'raspuns invalid';
                $log("  Retry {$attempt} API fail: {$lastError}");
                if ($attempt < 3) sleep(3);
                continue;
            }

            $log("  OK {$gpecId} dupa {$attempt} incercari: " . ($decoded['result']['status'] ?? '?'));
            $success = true;
            break;
        }

        if (!$success) {
            $log("  FAIL definitiv {$gpecId} dupa 3 incercari — salvez fail si continuu.");
            saveFailResult($db, $scanId, $gpecId, $checkKey,
                "Verificarea a esuat dupa 3 incercari: " . ($lastError ?? 'eroare necunoscuta'));
        }
    }
}

// ── FAZA 3: Calcul scor si finalizare ─────────────────────────────────────
$res = $db->prepare('SELECT status FROM results WHERE scan_id=?');
$res->execute([$scanId]);
$rows = $res->fetchAll(PDO::FETCH_COLUMN);

$scoreMap = ['pass' => 10, 'warning' => 5, 'fail' => 0, 'saas' => 5, 'error' => 0];
$sum      = array_sum(array_map(fn($s) => $scoreMap[$s] ?? 0, $rows));
$total    = count($rows);
$score    = $total > 0 ? (int)round(($sum / ($total * 10)) * 100) : 0;

// Daca tot lipsesc checks (situatie extrema), marcheaza ca eroare dar nu bloca
$finalStatus = $total > 0 ? 'done' : 'error';

// Reseteaza created_at la data reala (Run Now il seta 2000-01-01 pentru prioritate in coada)
$now = date('Y-m-d H:i:s');
$db->prepare("UPDATE scans SET status=?, score=?, finished_at=?, created_at=IF(created_at < '2001-01-01', ?, created_at) WHERE id=?")
   ->execute([$finalStatus, $score, $now, $now, $scanId]);

$log("FINAL: {$domain} — {$finalStatus}, scor {$score}%, {$total}/10 rezultate");
$log('---');

// ── Helper: salveaza un rezultat fail fara sa arunci exceptie ──────────────
function saveFailResult(PDO $db, string $scanId, string $gpecId, string $checkKey, string $reason): void {
    try {
        $db->prepare('DELETE FROM results WHERE scan_id=? AND gpec_id=?')->execute([$scanId, $gpecId]);
        $db->prepare(
            'INSERT INTO results (scan_id,gpec_id,check_name,status,stars_suggested,summary,details,comment_ro,raw_data)
             VALUES (?,?,?,?,?,?,?,?,?)'
        )->execute([
            $scanId, $gpecId, $checkKey, 'fail', 1,
            $reason,
            json_encode([$reason]),
            "Verificarea {$gpecId} nu s-a putut realiza. Verificare manuala recomandata.",
            json_encode(['recommendation_ro' => 'Va rugam sa verificati manual acest criteriu sau sa reincercati scanarea.']),
        ]);
    } catch (Throwable) {}
}
