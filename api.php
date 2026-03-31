<?php
// Captureaza orice output (warnings/notices/errors) inainte de orice altceva
ob_start();

/**
 * GPeC Security Health Check — API
 * Toate endpoint-urile: ?action=...
 */

// Suprima afisarea erorilor PHP in output (le logam, nu le afisam)
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

set_time_limit(180);
ignore_user_abort(true);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// Verifica autentificarea (sesiune normala SAU cron key intern)
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/config.php';

$_gpecCronKey     = substr(md5(getSetting('admin_password', 'gpec2024')), 0, 16);
$_gpecProvidedKey = $_GET['cron_key'] ?? $_POST['cron_key'] ?? '';
$_gpecIsInternal  = ($_gpecProvidedKey !== '' && hash_equals($_gpecCronKey, $_gpecProvidedKey));

if (!$_gpecIsInternal && !isLoggedIn()) {
    ob_end_clean();
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Neautentificat — reincarca pagina.']);
    exit;
}

// Modul rapid pentru apeluri interne (cron) — elimina delayurile politicoase
if ($_gpecIsInternal && !defined('GPEC_FAST_MODE')) {
    define('GPEC_FAST_MODE', true);
}

try {
    getDB(); // test conexiune DB la start
} catch (Throwable $e) {
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Eroare configurare BD: ' . $e->getMessage()]);
    exit;
}

require_once __DIR__ . '/checks/BaseCheck.php';

$action = $_REQUEST['action'] ?? '';

// Wrapper global pentru orice eroare neasteptata
set_exception_handler(function(Throwable $e) {
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    exit;
});

// ----------------------------------------------------------------
// action=create_scan  POST domain=...
// ----------------------------------------------------------------
if ($action === 'create_scan') {
    $domain = trim($_POST['domain'] ?? '');
    $domain = preg_replace('#^https?://#', '', $domain);
    $domain = preg_replace('#/.*$#', '', $domain);
    $domain = strtolower($domain);

    if (!$domain || !str_contains($domain, '.')) {
        jsonErr('Domeniu invalid');
    }

    $id = bin2hex(random_bytes(8)); // 16 char hex ID
    getDB()->prepare('INSERT INTO scans (id, domain, status, created_at) VALUES (?,?,?,?)')
        ->execute([$id, $domain, 'pending', date('Y-m-d H:i:s')]);

    jsonOk(['id' => $id, 'domain' => $domain]);
}

// ----------------------------------------------------------------
// action=run_check  POST scan_id=... check=...
// ----------------------------------------------------------------
if ($action === 'run_check') {
    $scanId = trim($_POST['scan_id'] ?? '');
    $check  = trim($_POST['check']   ?? '');

    if (!$scanId || !$check) jsonErr('scan_id si check sunt obligatorii');

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

    if (!isset($checkMap[$check])) jsonErr('Check necunoscut: ' . $check);

    [$className, $gpecId] = $checkMap[$check];

    // Verifica ca scan-ul exista
    $scan = getDB()->prepare('SELECT * FROM scans WHERE id=?');
    $scan->execute([$scanId]);
    $scanRow = $scan->fetch();
    if (!$scanRow) jsonErr('Scan negasit');

    $domain = $scanRow['domain'];

    // Citeste hints salvate + merge cu hint-ul one-time din request (pentru recheck manual)
    $savedHints = json_decode($scanRow['hints'] ?? '{}', true) ?: [];

    // Hint one-time din POST: hint_{check_name}_{key}=value (ex: hint_brute_force_login_url=https://...)
    // SAU format generic: hints[login_url]=...
    $postHints = [];
    foreach ($_POST as $k => $v) {
        if (str_starts_with($k, 'hint_' . $check . '_')) {
            $hintKey = substr($k, strlen('hint_' . $check . '_'));
            $postHints[$hintKey] = trim($v);
        }
    }
    // Format alternativ: hints[login_url]=...
    if (!empty($_POST['hints']) && is_array($_POST['hints'])) {
        foreach ($_POST['hints'] as $k => $v) {
            $postHints[trim($k)] = trim($v);
        }
    }

    // Hints finale = din DB + override din POST (POST are prioritate)
    $checkHints = array_merge(
        $savedHints[$check] ?? [],
        $savedHints,           // hints globale per scan (ex: login_url)
        $postHints
    );
    // Filtrare: sterge valorile goale
    $checkHints = array_filter($checkHints, function($v) { return $v !== ''; });

    // Daca s-au furnizat hints noi, salveaza-le in DB (persista pentru scanari viitoare)
    if ($postHints) {
        $updatedHints = array_merge($savedHints, [$check => array_merge($savedHints[$check] ?? [], $postHints)]);
        // Merge si la nivel global pentru chei comune (ex: login_url folosit de mai multi checkers)
        foreach ($postHints as $k => $v) {
            $updatedHints[$k] = $v;
        }
        getDB()->prepare('UPDATE scans SET hints=? WHERE id=?')
               ->execute([json_encode($updatedHints, JSON_UNESCAPED_UNICODE), $scanId]);
    }

    // Incarca clasa
    $file = __DIR__ . "/checks/{$className}.php";
    if (!file_exists($file)) jsonErr("Fisier clasa lipsa: {$className}.php");
    require_once $file;

    // Ruleaza check-ul (cu hints)
    try {
        $instance = new $className($domain, $checkHints);
        $result   = $instance->run();
        $result['check_name'] = $check; // salveaza intotdeauna machine name (ex: 'brute_force')
    } catch (Throwable $e) {
        $result = [
            'gpec_id'         => $gpecId,
            'check_name'      => $check,
            'status'          => 'fail',
            'stars_suggested' => 1,
            'summary'         => 'Eroare la verificare: ' . $e->getMessage(),
            'details'         => ['Eroare: ' . $e->getMessage()],
            'comment_ro'      => "Verificarea {$gpecId} nu s-a putut realiza. Verificare manuala recomandata.",
            'raw_data'        => [],
        ];
    }

    // Salveaza rezultat
    $db = getDB();

    // Sterge rezultat vechi daca exista (re-run)
    $db->prepare('DELETE FROM results WHERE scan_id=? AND gpec_id=?')
       ->execute([$scanId, $result['gpec_id']]);

    $db->prepare(
        'INSERT INTO results (scan_id, gpec_id, check_name, status, stars_suggested, summary, details, comment_ro, raw_data)
         VALUES (?,?,?,?,?,?,?,?,?)'
    )->execute([
        $scanId,
        $result['gpec_id'],
        $result['check_name'],
        $result['status'],
        $result['stars_suggested'],
        $result['summary'],
        json_encode($result['details'], JSON_UNESCAPED_UNICODE),
        $result['comment_ro'],
        json_encode($result['raw_data'],  JSON_UNESCAPED_UNICODE),
    ]);

    // Verifica daca toate 10 check-urile sunt gata → actualizeaza scor
    $cnt = getDB()->prepare('SELECT COUNT(*) FROM results WHERE scan_id=?');
    $cnt->execute([$scanId]);
    if ((int)$cnt->fetchColumn() >= 10) {
        recalcScore($scanId);
    } else {
        $db->prepare("UPDATE scans SET status='running' WHERE id=?")->execute([$scanId]);
    }

    jsonOk(['result' => $result]);
}

// ----------------------------------------------------------------
// action=scan_status  GET scan_id=...
// ----------------------------------------------------------------
if ($action === 'scan_status') {
    $scanId = trim($_GET['scan_id'] ?? '');
    if (!$scanId) jsonErr('scan_id lipsa');

    $s = getDB()->prepare('SELECT * FROM scans WHERE id=?');
    $s->execute([$scanId]);
    $scan = $s->fetch();
    if (!$scan) jsonErr('Scan negasit', 404);

    $r = getDB()->prepare('SELECT * FROM results WHERE scan_id=? ORDER BY id');
    $r->execute([$scanId]);
    $results = $r->fetchAll();

    foreach ($results as &$row) {
        $row['details']  = json_decode($row['details'],  true) ?? [];
        $row['raw_data'] = json_decode($row['raw_data'], true) ?? [];
    }

    jsonOk(['scan' => $scan, 'results' => $results]);
}

// ----------------------------------------------------------------
// action=history  GET
// ----------------------------------------------------------------
if ($action === 'history') {
    $s = getDB()->query(
        'SELECT id, domain, status, score, created_at FROM scans ORDER BY created_at DESC LIMIT 30'
    );
    jsonOk(['scans' => $s->fetchAll()]);
}

// ----------------------------------------------------------------
// action=delete_scan  POST scan_id=...
// ----------------------------------------------------------------
if ($action === 'delete_scan') {
    $scanId = trim($_POST['scan_id'] ?? '');
    if ($scanId) {
        getDB()->prepare('DELETE FROM scans WHERE id=?')->execute([$scanId]);
    }
    jsonOk(['deleted' => true]);
}

// ----------------------------------------------------------------
// action=quick_check  POST domain=... check=... [hints[login_url]=...]
// Ruleaza un singur check fara a salva in DB (pentru admin panel + index single check)
// ----------------------------------------------------------------
if ($action === 'quick_check') {
    $domain = trim($_POST['domain'] ?? '');
    $domain = strtolower(preg_replace('#^https?://#', '', preg_replace('#/.*$#', '', $domain)));
    $check  = trim($_POST['check'] ?? '');

    if (!$domain || !str_contains($domain, '.')) jsonErr('Domeniu invalid');

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
    if (!isset($checkMap[$check])) jsonErr('Check necunoscut');

    [$className, $gpecId] = $checkMap[$check];
    $file = __DIR__ . "/checks/{$className}.php";
    if (!file_exists($file)) jsonErr("Fisier clasa lipsa: {$className}.php");
    require_once $file;

    // Hints din POST: hints[login_url]=... SAU hint_brute_force_login_url=...
    $hints = [];
    if (!empty($_POST['hints']) && is_array($_POST['hints'])) {
        foreach ($_POST['hints'] as $k => $v) {
            if (trim($v) !== '') $hints[trim($k)] = trim($v);
        }
    }
    foreach ($_POST as $k => $v) {
        if (str_starts_with($k, 'hint_' . $check . '_') && trim($v) !== '') {
            $hints[substr($k, strlen('hint_' . $check . '_'))] = trim($v);
        }
    }

    try {
        $result = (new $className($domain, $hints))->run();
    } catch (Throwable $e) {
        $result = [
            'gpec_id' => $gpecId, 'check_name' => $check, 'status' => 'fail',
            'stars_suggested' => 1, 'summary' => 'Eroare: ' . $e->getMessage(),
            'details' => [$e->getMessage()], 'comment_ro' => '', 'raw_data' => [],
        ];
    }
    jsonOk(['result' => $result]);
}

// ----------------------------------------------------------------
// action=save_hints  POST scan_id=... hints[login_url]=...
// Salveaza hints pentru un scan fara a re-rula verificarile
// ----------------------------------------------------------------
if ($action === 'save_hints') {
    $scanId = trim($_POST['scan_id'] ?? '');
    if (!$scanId) jsonErr('scan_id lipsa');

    $s = getDB()->prepare('SELECT hints FROM scans WHERE id=?');
    $s->execute([$scanId]);
    $row = $s->fetch();
    if (!$row) jsonErr('Scan negasit', 404);

    $existing = json_decode($row['hints'] ?? '{}', true) ?: [];
    $new = [];
    if (!empty($_POST['hints']) && is_array($_POST['hints'])) {
        foreach ($_POST['hints'] as $k => $v) {
            $new[trim($k)] = trim($v); // permite stergerea cu string gol
        }
    }
    $merged = array_merge($existing, $new);
    getDB()->prepare('UPDATE scans SET hints=? WHERE id=?')
           ->execute([json_encode($merged, JSON_UNESCAPED_UNICODE), $scanId]);

    jsonOk(['hints' => $merged]);
}

jsonErr('Actiune necunoscuta: ' . $action);

// ----------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------

function recalcScore(string $scanId): void {
    $db  = getDB();
    $res = $db->prepare('SELECT status FROM results WHERE scan_id=?');
    $res->execute([$scanId]);
    $rows = $res->fetchAll(PDO::FETCH_COLUMN);

    $map  = ['pass' => 10, 'warning' => 5, 'fail' => 0];
    $sum  = array_sum(array_map(fn($s) => $map[$s] ?? 0, $rows));
    $max  = 10 * 10;
    $score = (int)round(($sum / $max) * 100);

    $db->prepare("UPDATE scans SET status='done', score=? WHERE id=?")
       ->execute([$score, $scanId]);
}

function jsonOk(array $data): never {
    while (ob_get_level() > 0) ob_end_clean();
    echo json_encode(['success' => true, ...$data], JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonErr(string $msg, int $code = 400): never {
    while (ob_get_level() > 0) ob_end_clean();
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}
