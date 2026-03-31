<?php
/**
 * Pagina de diagnosticare setup — sterge-o dupa ce confirmi ca totul merge
 * Acceseaza: https://gpec.iosub.ro/check_setup.php
 */
require_once __DIR__ . '/config.php';

$ok = true;
$results = [];

// Test BD
try {
    $db = getDB();
    $results[] = ['✅ Conexiune MySQL', 'OK — conectat la ' . DB_NAME];
} catch (Exception $e) {
    $ok = false;
    $results[] = ['❌ Conexiune MySQL', 'EROARE: ' . $e->getMessage()];
}

// Test tabele
if ($ok) {
    try {
        $cnt = $db->query('SELECT COUNT(*) FROM scans')->fetchColumn();
        $results[] = ['✅ Tabel scans', "OK — {$cnt} scanări înregistrate"];
    } catch (Exception $e) {
        $ok = false;
        $results[] = ['❌ Tabel scans', 'LIPSA — importă install.sql în phpMyAdmin: ' . $e->getMessage()];
    }
    try {
        $cnt = $db->query('SELECT COUNT(*) FROM results')->fetchColumn();
        $results[] = ['✅ Tabel results', "OK — {$cnt} rezultate"];
    } catch (Exception $e) {
        $ok = false;
        $results[] = ['❌ Tabel results', 'LIPSA — importă install.sql în phpMyAdmin'];
    }
}

// Test curl
$results[] = function_exists('curl_init')
    ? ['✅ cURL', 'disponibil']
    : ['⚠️ cURL', 'LIPSA — verificări HTTP nu vor funcționa'];

// Test DNS
$results[] = function_exists('dns_get_record')
    ? ['✅ dns_get_record', 'disponibil']
    : ['⚠️ dns_get_record', 'LIPSA — verificări DNS nu vor funcționa'];

// Test stream_socket_client
$fp = @stream_socket_client('tcp://8.8.8.8:53', $e, $s, 2);
if ($fp) { fclose($fp); $results[] = ['✅ stream_socket_client', 'funcțional — port scanning activ']; }
else $results[] = ['⚠️ stream_socket_client', 'blocat pe acest server — port scanning va folosi cURL ca fallback'];

// Test openssl
$results[] = extension_loaded('openssl')
    ? ['✅ OpenSSL', 'disponibil — verificare SSL activă']
    : ['⚠️ OpenSSL', 'LIPSA — verificările SSL vor fi limitate'];

// PHP version
$results[] = ['ℹ️ PHP', PHP_VERSION . ' — ' . (version_compare(PHP_VERSION, '8.0') >= 0 ? '✅ OK' : '⚠️ Recomandat PHP 8+')];
?>
<!DOCTYPE html><html lang="ro"><head><meta charset="UTF-8"><title>GPeC Setup Check</title>
<style>
body { font-family: monospace; background: #1C2340; color: #E0E0E0; padding: 30px; }
h2 { color: #F5B800; margin-bottom: 20px; }
table { border-collapse: collapse; width: 100%; max-width: 700px; }
td { padding: 8px 14px; border-bottom: 1px solid #2a3150; font-size: 14px; }
td:first-child { width: 240px; }
.ok { color: #4CAF50; } .err { color: #EF5350; } .warn { color: #F5B800; }
.note { margin-top: 20px; color: #90A4AE; font-size: 13px; }
</style></head><body>
<h2>🔐 GPeC Security Health Check — Diagnosticare Setup</h2>
<table>
<?php foreach ($results as $r): ?>
<tr><td><?= $r[0] ?></td><td><?= htmlspecialchars($r[1]) ?></td></tr>
<?php endforeach; ?>
</table>
<p class="note">⚠️ Șterge acest fișier după confirmare: <strong>check_setup.php</strong></p>
<?php if ($ok): ?>
<p style="color:#4CAF50;margin-top:20px;font-size:15px;font-weight:bold">✅ Setup complet — toolul este funcțional.</p>
<?php else: ?>
<p style="color:#EF5350;margin-top:20px;font-size:15px;font-weight:bold">❌ Probleme detectate — urmează instrucțiunile de mai sus.</p>
<?php endif; ?>
</body></html>
