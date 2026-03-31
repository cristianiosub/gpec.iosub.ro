<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/config.php';
requireLogin();

$user = currentUser();
$db   = getDB();
$msg  = '';

// ── Actiuni POST ───────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Salvare setari API
    if (isset($_POST['_save_settings'])) {
        $keys = ['google_safe_browsing_key','virustotal_key','queue_interval_minutes','queue_enabled'];
        foreach ($keys as $k) {
            if (array_key_exists($k, $_POST)) {
                $v = $k === 'queue_enabled' ? (isset($_POST[$k]) ? '1' : '0') : trim($_POST[$k]);
                $db->prepare('INSERT INTO settings(`key`,`value`) VALUES(?,?) ON DUPLICATE KEY UPDATE `value`=?')
                   ->execute([$k, $v, $v]);
            }
        }
        $msg = '✅ Setări salvate.';
    }

    // Adaugare/editare user
    if (isset($_POST['_save_user'])) {
        $uid      = (int)($_POST['user_id'] ?? 0);
        $uname    = trim($_POST['uname'] ?? '');
        $newpass  = $_POST['upass'] ?? '';
        $role     = 'admin';

        if (!$uname) { $msg = '❌ Numele de utilizator este obligatoriu.'; goto done; }

        if ($uid) {
            // Update
            if ($newpass) {
                $hash = password_hash($newpass, PASSWORD_BCRYPT);
                $db->prepare('UPDATE users SET username=?, password_hash=?, role=? WHERE id=?')
                   ->execute([$uname, $hash, $role, $uid]);
            } else {
                $db->prepare('UPDATE users SET username=?, role=? WHERE id=?')
                   ->execute([$uname, $role, $uid]);
            }
            $msg = '✅ Utilizator actualizat.';
        } else {
            // Adaugare
            if (!$newpass) { $msg = '❌ Parola este obligatorie pentru un user nou.'; goto done; }
            $hash = password_hash($newpass, PASSWORD_BCRYPT);
            try {
                $db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)')
                   ->execute([$uname, $hash, $role]);
                $msg = '✅ Utilizator creat.';
            } catch (Throwable) {
                $msg = '❌ Utilizatorul există deja.';
            }
        }
    }

    // Stergere user
    if (isset($_POST['_delete_user'])) {
        $uid = (int)($_POST['user_id'] ?? 0);
        if ($uid && $uid !== (int)$user['id']) { // nu te poti sterge pe tine
            $db->prepare('DELETE FROM users WHERE id=?')->execute([$uid]);
            $msg = '🗑 Utilizator șters.';
        } else {
            $msg = '⚠️ Nu poți șterge contul propriu.';
        }
    }

    // Adaugare bulk domenii
    if (isset($_POST['_bulk_add'])) {
        $raw   = $_POST['domains'] ?? '';
        $lines = array_filter(array_map('trim', explode("\n", $raw)));
        $added = 0; $skip = 0;
        foreach ($lines as $line) {
            $dom = strtolower(preg_replace('#^https?://#','',preg_replace('#/.*$#','',trim($line))));
            if (!$dom || !str_contains($dom, '.')) { $skip++; continue; }
            $ex = $db->prepare("SELECT id FROM scans WHERE domain=? AND status IN ('queued','running','pending') LIMIT 1");
            $ex->execute([$dom]);
            if ($ex->fetch()) { $skip++; continue; }
            $id = bin2hex(random_bytes(8));
            $db->prepare('INSERT INTO scans (id,domain,status,created_at) VALUES (?,?,?,?)')
               ->execute([$id, $dom, 'queued', date('Y-m-d H:i:s')]);
            $added++;
        }
        $msg = "✅ Adăugate în coadă: {$added}." . ($skip ? " Sărite: {$skip}." : '');
    }

    // Stergere scan
    if (isset($_POST['_delete_scan'])) {
        $db->prepare('DELETE FROM scans WHERE id=?')->execute([$_POST['scan_id'] ?? '']);
        $msg = '🗑 Scan șters.';
    }

    // Re-scanare
    if (isset($_POST['_rescan'])) {
        $sid = $_POST['scan_id'] ?? '';
        $db->prepare('DELETE FROM results WHERE scan_id=?')->execute([$sid]);
        $db->prepare("UPDATE scans SET status='queued',score=NULL,started_at=NULL,finished_at=NULL,created_at=? WHERE id=?")
           ->execute([date('Y-m-d H:i:s'), $sid]);
        $msg = '🔄 Repus în coadă.';
    }

    // Run Now — prioritizeaza scanarea si o porneste imediat
    if (isset($_POST['_run_now'])) {
        $sid = $_POST['scan_id'] ?? '';
        if (!$sid) { $msg = '❌ scan_id lipsa.'; goto done; }

        // Sterge rezultatele vechi si pune la inceputul cozii
        $db->prepare('DELETE FROM results WHERE scan_id=?')->execute([$sid]);
        $db->prepare("UPDATE scans SET status='queued',score=NULL,started_at=NULL,finished_at=NULL,created_at='2000-01-01 00:00:00' WHERE id=?")
           ->execute([$sid]);

        // Porneste cron_scan.php cu scan_id specific (fire-and-forget)
        $adminPass  = getSetting('admin_password', 'gpec2024');
        $cronKey    = substr(md5($adminPass), 0, 16);
        $scheme     = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        $basePath   = rtrim(dirname($_SERVER['PHP_SELF']), '/');
        $cronUrl    = $scheme . '://' . $_SERVER['HTTP_HOST'] . $basePath
                    . '/cron_scan.php?key=' . urlencode($cronKey)
                    . '&scan_id=' . urlencode($sid);

        $ch = curl_init($cronUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $cronResp = curl_exec($ch);
        $cronHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cronErr  = curl_error($ch);
        curl_close($ch);

        $isTimeout = ($cronErr === 28); // CURLE_OPERATION_TIMEDOUT — scanul ruleaza in background
        if ($isTimeout || $cronHttp === 200) {
            $msg = '▶ Scanare pornită — rulează în background. Reîncarcă pagina în câteva secunde pentru rezultate.';
        } elseif ($cronHttp === 403) {
            $msg = '❌ Eroare autentificare cron (key incorect).';
        } elseif ($cronErr && !$isTimeout) {
            $msg = "❌ Curl eroare ({$cronErr}): {$cronErr}. <a href='" . htmlspecialchars($cronUrl) . "' target='_blank'>Test direct</a>";
        } else {
            $debugResp = htmlspecialchars($cronResp ?: '(raspuns gol)');
            $msg = "❌ Cron HTTP {$cronHttp}. <a href='" . htmlspecialchars($cronUrl) . "' target='_blank'>Deschide direct</a><br><pre style='font-size:11px;background:#fee;padding:8px;border-radius:4px;margin-top:6px;white-space:pre-wrap'>{$debugResp}</pre>";
        }
    }

    // Nota scan
    if (isset($_POST['_save_note'])) {
        $db->prepare('UPDATE scans SET note=? WHERE id=?')
           ->execute([trim($_POST['note'] ?? ''), $_POST['scan_id'] ?? '']);
        $msg = '✅ Notă salvată.';
    }
}
done:

// ── Date ───────────────────────────────────────────────────
$settings = [];
foreach ($db->query('SELECT `key`,`value` FROM settings') as $r) $settings[$r['key']] = $r['value'];

$users = $db->query('SELECT id,username,role,created_at FROM users ORDER BY id')->fetchAll();

$scans = $db->query(
    'SELECT s.*,(SELECT COUNT(*) FROM results r WHERE r.scan_id=s.id) AS result_count
     FROM scans s ORDER BY s.created_at DESC LIMIT 300'
)->fetchAll();

$queueCount   = (int)$db->query("SELECT COUNT(*) FROM scans WHERE status='queued'")->fetchColumn();
$doneCount    = (int)$db->query("SELECT COUNT(*) FROM scans WHERE status='done'")->fetchColumn();
$runningCount = (int)$db->query("SELECT COUNT(*) FROM scans WHERE status='running'")->fetchColumn();
$checkInterval = (int)($settings['queue_interval_minutes'] ?? 15);

// Detalii scan
$viewScan = null; $viewResults = [];
if (!empty($_GET['view'])) {
    $vs = $db->prepare('SELECT * FROM scans WHERE id=?');
    $vs->execute([$_GET['view']]);
    $viewScan = $vs->fetch();
    if ($viewScan) {
        $vr = $db->prepare('SELECT * FROM results WHERE scan_id=? ORDER BY gpec_id');
        $vr->execute([$_GET['view']]);
        $viewResults = $vr->fetchAll();
        foreach ($viewResults as &$row) {
            $row['details']  = json_decode($row['details'],  true) ?? [];
            $row['raw_data'] = json_decode($row['raw_data'], true) ?? [];
        }
    }
}

$statusColor = ['pending'=>'#90A4AE','queued'=>'#1976D2','running'=>'#BF6000','done'=>'#1B7A47','error'=>'#B71C1C'];
$cronKey = substr(md5($settings['admin_password'] ?? 'gpec2024'), 0, 16);
$serverPath = realpath(__DIR__) ?: '/home/i0sub/gpec.iosub.ro';
?><!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPeC Admin</title>
<style>
:root{--y:#F5B800;--yd:#D9A100;--yl:#FFFBEA;--dark:#111827;--dark2:#1E2A3A;--bg:#F3F4F6;--border:#E5E7EB;--text:#111827;--muted:#6B7280}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',sans-serif;background:var(--bg);color:var(--text);font-size:14px}

/* HEADER */
.hdr{background:linear-gradient(135deg,#1E3A8A 0%,#2563EB 100%);border-bottom:none;box-shadow:0 2px 12px rgba(37,99,235,.35);position:sticky;top:0;z-index:100}
.hdr-in{max-width:1200px;margin:0 auto;display:flex;align-items:center;height:54px;padding:0 16px;gap:8px}
.logo{display:flex;align-items:center;gap:9px;text-decoration:none;flex:1}
.logo-mark{width:32px;height:32px;min-width:32px;background:rgba(255,255,255,.18);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;border:1px solid rgba(255,255,255,.25)}
.logo-title{font-size:14px;font-weight:700;color:#fff;letter-spacing:-.2px}
.logo-title b{color:#FDE68A}
.logo-sub{font-size:10px;color:rgba(255,255,255,.65)}
.hdr-nav{display:flex;align-items:center;gap:2px;flex-shrink:0}
.hdr-user{font-size:11px;color:rgba(255,255,255,.6);padding:0 10px;display:none}
.hl{display:inline-flex;align-items:center;gap:5px;color:rgba(255,255,255,.88);font-size:12px;font-weight:600;text-decoration:none;padding:6px 10px;border-radius:6px;transition:color .15s,background .15s;background:none;border:none;cursor:pointer;white-space:nowrap}
.hl:hover{color:#fff;background:rgba(255,255,255,.15)}
.hl svg{flex-shrink:0}
.hl-logout:hover{color:#FCA5A5;background:rgba(0,0,0,.2)}
@media(min-width:540px){.hdr-user{display:inline}}

/* LAYOUT */
.wrap{max-width:1200px;margin:0 auto;padding:16px 14px}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.stat{background:#fff;border-radius:10px;padding:14px 16px;border:1px solid var(--border)}
.stat-n{font-size:26px;font-weight:800;line-height:1}
.stat-l{font-size:11px;color:var(--muted);margin-top:3px;font-weight:500}

/* PANELS */
.panel{background:#fff;border-radius:12px;border:1px solid var(--border);margin-bottom:12px;overflow:hidden}
.ph{padding:11px 16px;background:#FAFAFA;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none;transition:background .12s}
.ph:hover{background:#F5F5F5}
.ph h3{font-size:13px;font-weight:700;flex:1;letter-spacing:-.1px}
.ph-arr{font-size:12px;color:var(--muted);transition:transform .2s}
.pb{padding:16px}

/* MESSAGES */
.msg{padding:10px 14px;border-radius:8px;margin-bottom:14px;font-size:13px;font-weight:600;background:#DCFCE7;color:#166534;border:1px solid #BBF7D0;display:flex;align-items:center;gap:8px}

/* FORMS */
textarea{width:100%;padding:9px 12px;border:1.5px solid var(--border);border-radius:7px;font-size:13px;font-family:monospace;resize:vertical;outline:none;line-height:1.5}
textarea:focus{border-color:var(--y)}
input[type=text],input[type=password],input[type=number],select{padding:8px 11px;border:1.5px solid var(--border);border-radius:7px;font-size:13px;outline:none;width:100%;background:#fff;color:var(--text);transition:border .15s}
input:focus,select:focus{border-color:var(--y);box-shadow:0 0 0 3px rgba(245,184,0,.1)}
.fg{margin-bottom:12px}
.fg label{display:block;font-size:11px;font-weight:700;color:var(--muted);margin-bottom:5px;text-transform:uppercase;letter-spacing:.4px}
.tip{font-size:11px;color:var(--muted);margin-top:4px;line-height:1.4}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:600px){.grid2{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}

/* BUTTONS */
.btn{padding:7px 14px;border:none;border-radius:7px;font-size:12px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px;transition:filter .12s}
.btn:hover{filter:brightness(.93)}
.btn-y{background:var(--y);color:var(--dark)}
.btn-dark{background:var(--dark);color:#fff}
.btn-red{background:#FEE2E2;color:#991B1B}
.btn-blue{background:#EFF6FF;color:#1D4ED8}
.btn-green{background:#DCFCE7;color:#166534}
.btn-sm{padding:5px 10px;font-size:11px;border-radius:6px}
.act-btns{display:flex;gap:3px;align-items:center}

/* TABLE */
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{text-align:left;padding:7px 10px;border-bottom:1.5px solid var(--border);color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.tbl td{padding:8px 10px;border-bottom:1px solid #F3F4F6;vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:#FAFAFA}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.2px}
.score-pill{display:inline-block;padding:2px 8px;border-radius:8px;font-size:11px;font-weight:800}

/* SINGLE CHECK */
.qc-row{display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:flex-end;margin-bottom:12px}
@media(max-width:600px){.qc-row{grid-template-columns:1fr}}
.qc-result{margin-top:14px;display:none}
.qc-card{border:1px solid var(--border);border-radius:9px;overflow:hidden}
.qc-hdr{padding:11px 14px;display:flex;align-items:center;gap:10px;font-weight:700;font-size:13px}
.qc-body{padding:12px 14px;font-size:13px;border-top:1px solid var(--border)}
.qc-detail{padding:2px 0;color:var(--muted);font-size:12px}
.qc-rec{background:var(--yl);padding:10px 13px;border-radius:7px;font-size:12px;white-space:pre-line;border-left:3px solid var(--y);margin-top:10px}
.qc-comment{background:#F9FAFB;padding:9px 12px;border-radius:7px;font-size:13px;border-left:3px solid var(--border);margin-top:8px}
.spin{display:inline-block;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* VIEW SCAN */
.vback{display:inline-flex;align-items:center;gap:6px;color:var(--dark);text-decoration:none;font-size:13px;font-weight:600;margin-bottom:14px;padding:6px 0}
.rcard{border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden}
.rch{padding:10px 14px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:13px}
.rcb{padding:12px 14px;font-size:13px;border-top:1px solid var(--border)}

/* MISC */
.cron-box{background:var(--dark);color:#A3E635;padding:11px 14px;border-radius:8px;font-family:'Courier New',monospace;font-size:12px;word-break:break-all;margin-top:8px;line-height:1.6}
hr.div{border:none;border-top:1px solid var(--border);margin:16px 0}
@media(max-width:600px){.qc-row{flex-direction:column}}
</style>
</head>
<body>
<header class="hdr">
  <div class="hdr-in">
    <a class="logo" href="index">
      <div class="logo-mark">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div>
        <div class="logo-title"><b>GPeC</b> Admin</div>
        <div class="logo-sub">Security Health Check</div>
      </div>
    </a>
    <nav class="hdr-nav">
      <span class="hdr-user"><?= htmlspecialchars($user['username']) ?></span>
      <a class="hl" href="index">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        Scanare
      </a>
      <a class="hl hl-logout" href="login?logout=1" title="Ieșire">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </a>
    </nav>
  </div>
</header>

<div class="wrap">

<?php if ($msg): ?>
  <div class="msg"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>

<?php if ($viewScan): ?>
<!-- ═══════════════ VIEW SCAN ═══════════════ -->
<?php
  $sc = $viewScan;
  $scColor = ['pass'=>'#1B7A47','warning'=>'#BF6000','fail'=>'#B71C1C','saas'=>'#455A64','error'=>'#7B1FA2'];
  $scBg    = ['pass'=>'#E6F4ED','warning'=>'#FFF3E0','fail'=>'#FFEBEE','saas'=>'#ECEFF1','error'=>'#F3E5F5'];

  // Hints salvate pentru scan
  $scanHints = json_decode($sc['hints'] ?? '{}', true) ?: [];

  // Definitii campuri hint per check (extensibil)
  $hintDefs = [
      'brute_force' => [
          ['key'=>'login_url','label'=>'URL pagină login','placeholder'=>'https://magazin.ro/my-account/login',
           'help'=>'Furnizați URL-ul exact al paginii de login dacă nu a fost detectat automat'],
      ],
  ];

  // Mapare: nume afisaj (stocat in DB la scanari vechi) → machine key
  $displayToMachine = [
      'Server Dedicat'                    => 'dedicated_server',
      'Malware / Phishing'                => 'malware',
      'Reputatie Spam'                    => 'spam_reputation',
      'HTTPS Full Site'                   => 'https_full',
      'Configuratie SSL'                  => 'ssl_config',
      'Acces Servicii Critice'            => 'critical_ports',
      'CMS si Extensii'                   => 'cms_updates',
      'Securitate Email (SPF/DKIM/DMARC)' => 'email_security',
      'Directory Listing'                 => 'directory_listing',
      'Protectie Brute Force'             => 'brute_force',
  ];
?>
<a href="admin" class="vback">← Înapoi la Admin</a>
<div class="panel">
  <div class="pb">
    <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
      <div>
        <div style="font-size:22px;font-weight:800"><?= htmlspecialchars($sc['domain']) ?></div>
        <div style="font-size:12px;color:var(--muted);margin-top:2px">ID: <?= $sc['id'] ?> &middot; <?= $sc['created_at'] ?></div>
      </div>
      <?php if ($sc['score'] !== null): $s=$sc['score']; $c=$s>=80?'#1B7A47':($s>=50?'#BF6000':'#B71C1C'); ?>
        <div style="font-size:34px;font-weight:900;color:<?= $c ?>"><?= $s ?>%</div>
      <?php endif; ?>
      <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">
        <form method="post" style="display:contents">
          <input type="hidden" name="scan_id" value="<?= $sc['id'] ?>">
          <button name="_run_now" value="1" class="btn btn-green btn-sm">▶ Run Now</button>
          <button name="_rescan" value="1" class="btn btn-blue btn-sm">↺ Re-scanare</button>
          <button name="_delete_scan" value="1" class="btn btn-red btn-sm" onclick="return confirm('Ștergi scanarea?')">Șterge</button>
        </form>
      </div>
    </div>
    <form method="post" style="display:flex;gap:8px;margin-top:12px">
      <input type="hidden" name="scan_id" value="<?= $sc['id'] ?>">
      <input type="text" name="note" value="<?= htmlspecialchars($sc['note']??'') ?>" placeholder="Notă audit (ex: client X, rundă 2024)..." style="flex:1">
      <button name="_save_note" value="1" class="btn btn-y btn-sm">Salvează nota</button>
    </form>
  </div>
</div>

<?php foreach ($viewResults as $r):
  $st          = $r['status'];
  $displayName = $r['check_name'];
  // Suporta atat machine key (scanari noi) cat si display name (scanari vechi)
  $machineKey  = $displayToMachine[$displayName] ?? $displayName;
  $details     = is_array($r['details'])  ? $r['details']  : (json_decode($r['details']  ?? '[]', true) ?: []);
  $rawData     = is_array($r['raw_data']) ? $r['raw_data'] : (json_decode($r['raw_data'] ?? '{}', true) ?: []);
  $rec         = $rawData['recommendation_ro'] ?? '';
  $cardId      = 'rc-' . preg_replace('/[^a-z0-9]/', '', $machineKey);
  $hints       = $hintDefs[$machineKey] ?? [];
  // Valori salvate pentru hint-urile acestui check
  $savedCheckHints = array_merge(
      array_intersect_key($scanHints, array_flip(array_column($hints,'key'))),
      $scanHints[$machineKey] ?? []
  );
?>
<div class="rcard" id="<?= $cardId ?>">
  <div class="rch" style="background:<?= $scBg[$st]??'#F4F7FB' ?>;display:flex;align-items:center;gap:8px">
    <span style="font-size:11px;font-weight:800;color:<?= $scColor[$st]??'#455A64' ?>;min-width:38px"><?= $r['gpec_id'] ?></span>
    <span style="flex:1;font-weight:600"><?= htmlspecialchars($r['check_name']) ?></span>
    <span style="font-size:11px;padding:2px 9px;border-radius:10px;background:<?= $scColor[$st]??'#455A64' ?>;color:#fff"><?= strtoupper($st) ?></span>
    <span style="font-size:13px"><?= str_repeat('★',$r['stars_suggested']) ?><?= str_repeat('☆',5-$r['stars_suggested']) ?></span>
    <!-- Buton Recheck -->
    <button class="btn btn-sm btn-green" style="padding:3px 10px;font-size:11px"
      onclick="recheckCriterion('<?= $sc['id'] ?>','<?= $machineKey ?>','<?= $cardId ?>')"
      title="Recheck doar acest criteriu" id="rcbtn-<?= $cardId ?>">
      ↺ Recheck
    </button>
  </div>
  <div class="rcb" id="rcbody-<?= $cardId ?>">
    <div style="font-weight:600;margin-bottom:6px"><?= htmlspecialchars($r['summary']) ?></div>
    <?php foreach($details as $d): ?>
      <div style="padding:1px 0;color:var(--muted);font-size:12px">› <?= htmlspecialchars((string)$d) ?></div>
    <?php endforeach; ?>
    <div style="background:#F4F7FB;padding:9px 13px;border-radius:7px;font-size:13px;margin-top:8px;border-left:3px solid var(--border)">
      <strong>Comentariu GPeC:</strong> <?= htmlspecialchars($r['comment_ro']) ?>
    </div>
    <?php if ($rec): ?>
    <div style="background:#FFFDE7;padding:10px 13px;border-radius:7px;font-size:12px;white-space:pre-line;border-left:3px solid var(--y);margin-top:8px">
      <strong>📋 Recomandare:</strong><br><?= htmlspecialchars($rec) ?>
    </div>
    <?php endif; ?>

    <?php if ($hints): ?>
    <!-- Hint section pentru acest check -->
    <div style="margin-top:10px;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:7px;padding:10px 13px">
      <div style="font-size:11px;font-weight:700;color:#1D4ED8;text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px">
        💡 Hint opțional pentru recheck
      </div>
      <?php foreach($hints as $hf): ?>
      <?php $hval = $savedCheckHints[$hf['key']] ?? ''; ?>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <label style="font-size:12px;font-weight:600;color:#374151;white-space:nowrap"><?= htmlspecialchars($hf['label']) ?></label>
        <input type="text"
          id="hint-<?= $cardId ?>-<?= $hf['key'] ?>"
          value="<?= htmlspecialchars($hval) ?>"
          placeholder="<?= htmlspecialchars($hf['placeholder']) ?>"
          style="flex:1;min-width:200px;padding:6px 10px;border:1px solid #93C5FD;border-radius:6px;font-size:12px;outline:none"
          title="<?= htmlspecialchars($hf['help']) ?>">
      </div>
      <?php endforeach; ?>
      <div style="font-size:11px;color:#6B7280;margin-top:5px">Hint-ul se salvează automat la Recheck și va fi folosit și la scanările viitoare.</div>
    </div>
    <?php endif; ?>
  </div>
</div>
<?php endforeach; ?>

<script>
// ── Recheck individual per criteriu ────────────────────────────
const HINT_FIELDS = <?= json_encode(array_map(
    fn($fields) => array_column($fields, 'key'),
    $hintDefs
), JSON_UNESCAPED_UNICODE) ?>;

async function recheckCriterion(scanId, checkName, cardId) {
  const btn  = document.getElementById('rcbtn-' + cardId);
  const body = document.getElementById('rcbody-' + cardId);
  if (!btn) return;

  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Rulează...';
  btn.style.background = '#6B7280';

  // Colecteaza hints din campurile de input ale acestui card
  const fd = new FormData();
  fd.append('action', 'run_check');
  fd.append('scan_id', scanId);
  fd.append('check', checkName);

  const hintKeys = HINT_FIELDS[checkName] || [];
  hintKeys.forEach(key => {
    const el = document.getElementById('hint-' + cardId + '-' + key);
    if (el && el.value.trim()) {
      fd.append('hints[' + key + ']', el.value.trim());
    }
  });

  try {
    const cronKey = <?= json_encode(substr(md5(getSetting('admin_password','gpec2024')),0,16)) ?>;
    const r = await fetch('api.php?cron_key=' + encodeURIComponent(cronKey), {method:'POST', body:fd});
    const d = await r.json();
    if (!d.success) throw new Error(d.error || 'Eroare API');

    const res = d.result;
    const stColors = {pass:'#1B7A47',warning:'#BF6000',fail:'#B71C1C',saas:'#455A64',error:'#7B1FA2'};
    const stBg = {pass:'#E6F4ED',warning:'#FFF3E0',fail:'#FFEBEE',saas:'#ECEFF1',error:'#F3E5F5'};
    const st = res.status;

    // Actualizeaza header-ul cardului
    const hdr = document.querySelector('#' + cardId + ' .rch');
    if (hdr) {
      hdr.style.background = stBg[st] || '#F4F7FB';
      const badge = hdr.querySelector('span:nth-child(3)');
      if (badge) { badge.textContent = st.toUpperCase(); badge.style.background = stColors[st] || '#455A64'; }
      const stars = hdr.querySelector('span:nth-child(4)');
      if (stars) stars.textContent = '★'.repeat(res.stars_suggested||1) + '☆'.repeat(5-(res.stars_suggested||1));
    }

    // Actualizeaza body (doar portiunea de text, pastreaza hint inputs)
    const details = (res.details||[]).map(d=>`<div style="padding:1px 0;color:#6B7280;font-size:12px">› ${esc(d)}</div>`).join('');
    const rec = (res.raw_data||{}).recommendation_ro||'';
    const recHtml = rec ? `<div style="background:#FFFDE7;padding:10px 13px;border-radius:7px;font-size:12px;white-space:pre-line;border-left:3px solid #F5B800;margin-top:8px"><strong>📋 Recomandare:</strong><br>${esc(rec)}</div>` : '';
    const hintSection = body.querySelector('div[style*="EFF6FF"]');
    body.innerHTML = `<div style="font-weight:600;margin-bottom:6px;color:${stColors[st]||'#111'}">${esc(res.summary)}</div>${details}<div style="background:#F4F7FB;padding:9px 13px;border-radius:7px;font-size:13px;margin-top:8px;border-left:3px solid #E5E7EB"><strong>Comentariu GPeC:</strong> ${esc(res.comment_ro)}</div>${recHtml}`;
    if (hintSection) body.appendChild(hintSection);

    btn.textContent = '✓ Done';
    btn.style.background = '#16A34A';
    setTimeout(() => { btn.textContent = origText; btn.style.background = ''; btn.disabled = false; }, 3000);

  } catch(e) {
    btn.textContent = '❌ ' + e.message;
    btn.style.background = '#DC2626';
    setTimeout(() => { btn.textContent = origText; btn.style.background = ''; btn.disabled = false; }, 4000);
  }
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
</script>

<?php else: ?>
<!-- ═══════════════ DASHBOARD ═══════════════ -->

<div class="stats">
  <div class="stat"><div class="stat-n" style="color:#2563EB"><?= $queueCount ?></div><div class="stat-l">În coadă</div></div>
  <div class="stat"><div class="stat-n" style="color:#D97706"><?= $runningCount ?></div><div class="stat-l">Rulează</div></div>
  <div class="stat"><div class="stat-n" style="color:#16A34A"><?= $doneCount ?></div><div class="stat-l">Finalizate</div></div>
  <div class="stat"><div class="stat-n" style="color:#374151"><?= count($scans) ?></div><div class="stat-l">Total scanări</div></div>
</div>

<!-- ── SINGLE CHECK ─────────────────────────── -->
<div class="panel">
  <div class="ph" onclick="tog('qc')"><h3>Single Check — verificare rapidă pe un domeniu</h3><span id="a-qc" class="ph-arr">▾</span></div>
  <div class="pb" id="qc">
    <div class="qc-row">
      <div class="fg">
        <label>Domeniu</label>
        <input type="text" id="qcDomain" placeholder="magazin.ro" autocomplete="off">
      </div>
      <div class="fg">
        <label>Verificare</label>
        <select id="qcCheck" onchange="qcCheckChanged()">
          <option value="dedicated_server">#1 — Server dedicat</option>
          <option value="malware">#2 — Malware / Phishing</option>
          <option value="spam_reputation">#3 — Reputație Spam</option>
          <option value="https_full">#4 — HTTPS Full Site</option>
          <option value="ssl_config">#5 — Configurație SSL</option>
          <option value="critical_ports">#6 — Porturi critice</option>
          <option value="cms_updates">#7 — CMS &amp; Extensii</option>
          <option value="email_security">#8 — Securitate Email</option>
          <option value="directory_listing">#9 — Directory Listing</option>
          <option value="brute_force">#10 — Brute Force</option>
        </select>
      </div>
      <div class="fg">
        <label>&nbsp;</label>
        <button class="btn btn-y" onclick="runQuickCheck()" style="width:100%">Rulează</button>
      </div>
    </div>
    <!-- Hint row — apare doar pt verificarile care au hint-uri (ex: Brute Force) -->
    <div id="qcHintRow" style="display:none;margin-top:10px;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:7px;padding:10px 13px">
      <div style="font-size:11px;font-weight:700;color:#1D4ED8;text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px">💡 Hint opțional pentru Brute Force</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <label style="font-size:12px;font-weight:600;color:#374151;white-space:nowrap">URL pagină login</label>
        <input type="text" id="qcHintLoginUrl" placeholder="https://magazin.ro/my-account/login"
          style="flex:1;min-width:220px;padding:6px 10px;border:1px solid #93C5FD;border-radius:6px;font-size:12px;outline:none"
          title="Furnizați URL-ul exact al paginii de login dacă nu este detectat automat">
      </div>
      <div style="font-size:11px;color:#6B7280;margin-top:5px">Dacă pagina de login nu este detectată automat, introduceți URL-ul exact.</div>
    </div>
    <div id="qcResult" class="qc-result"></div>
  </div>
</div>

<!-- ── SCANARI ───────────────────────────────── -->
<div class="panel">
  <div class="ph" onclick="tog('scans')"><h3>Scanări <span style="font-weight:400;color:var(--muted)">(<?= count($scans) ?>)</span></h3><span id="a-scans" class="ph-arr" style="transform:rotate(180deg)">▾</span></div>
  <div id="scans">
    <div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:#FAFBFC">
      <input type="text" id="scanSearch" placeholder="🔍 Caută domeniu..." oninput="filterScans()" style="width:200px;padding:6px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;outline:none">
      <div style="display:flex;gap:3px">
        <button class="btn btn-sm filter-btn" style="background:var(--dark);color:#fff" data-s="" onclick="setFilter('',this)">Toate</button>
        <button class="btn btn-sm filter-btn" data-s="queued" onclick="setFilter('queued',this)" style="background:#E3F2FD;color:#1565C0">Coadă</button>
        <button class="btn btn-sm filter-btn" data-s="running" onclick="setFilter('running',this)" style="background:#FFF3E0;color:#BF6000">Rulează</button>
        <button class="btn btn-sm filter-btn" data-s="done" onclick="setFilter('done',this)" style="background:#E6F4ED;color:#1B5E20">Done</button>
        <button class="btn btn-sm filter-btn" data-s="error" onclick="setFilter('error',this)" style="background:#FFEBEE;color:#B71C1C">Erori</button>
      </div>
      <button class="btn btn-sm btn-y" onclick="exportCSV()" style="margin-left:auto" title="Export CSV">
        <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        CSV
      </button>
    </div>
    <div style="overflow:auto">
    <table class="tbl" id="scansTable">
      <thead><tr>
        <th>Domeniu</th><th>Status</th><th>Scor</th><th>Checks</th><th>Data</th><th>Notă</th><th>Acțiuni</th>
      </tr></thead>
      <tbody>
      <?php foreach($scans as $s):
        $c=$statusColor[$s['status']]??'#90A4AE';
        $score=$s['score'];
        $sb=$score!==null?($score>=80?'#E8F5E9':($score>=50?'#FFF3E0':'#FFEBEE')):'';
        $sc2=$score!==null?($score>=80?'#1B5E20':($score>=50?'#BF6000':'#B71C1C')):'';
      ?>
      <tr data-domain="<?= htmlspecialchars(strtolower($s['domain'])) ?>" data-status="<?= $s['status'] ?>">
        <td><strong><?= htmlspecialchars($s['domain']) ?></strong></td>
        <td><span class="badge" style="background:<?= $c ?>22;color:<?= $c ?>"><?= $s['status'] ?></span></td>
        <td><?php if($score!==null): ?><span class="score-pill" style="background:<?= $sb ?>;color:<?= $sc2 ?>"><?= $score ?>%</span><?php else: ?>—<?php endif; ?></td>
        <td><?= $s['result_count'] ?>/10</td>
        <td style="white-space:nowrap;color:var(--muted);font-size:12px"><?= substr($s['created_at'],0,16) ?></td>
        <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--muted)"><?= htmlspecialchars($s['note']??'') ?></td>
        <td>
          <div class="act-btns">
            <a href="admin?view=<?= $s['id'] ?>" class="btn btn-sm btn-dark" title="Vezi detalii">
              <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/></svg>
            </a>
            <form method="post" style="display:contents">
              <input type="hidden" name="scan_id" value="<?= $s['id'] ?>">
              <button name="_run_now" value="1" class="btn btn-sm btn-green" title="Pornește imediat"
                <?= in_array($s['status'],['running','queued']) ? '' : '' ?>>
                <svg width="13" height="13" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
              </button>
              <button name="_rescan" value="1" class="btn btn-sm btn-blue" title="Re-scanare">
                <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M1 4v6h6M23 20v-6h-6"/><path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4-4.64 4.36A9 9 0 0 1 3.51 15"/></svg>
              </button>
              <button name="_delete_scan" value="1" class="btn btn-sm btn-red" title="Șterge" onclick="return confirm('Ștergi scanarea?')">
                <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
              </button>
            </form>
          </div>
        </td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div><!-- /overflow -->
  </div>
</div>

<!-- ── BULK ADD ──────────────────────────────── -->
<div class="panel">
  <div class="ph" onclick="tog('bulk')"><h3>Adaugă domenii în coadă (bulk)</h3><span id="a-bulk" class="ph-arr">▾</span></div>
  <div class="pb" id="bulk" style="display:none">
    <form method="post">
      <input type="hidden" name="_bulk_add" value="1">
      <div class="fg">
        <label>Un domeniu per linie (fără https:// sau /)</label>
        <textarea name="domains" rows="7" placeholder="magazin1.ro&#10;shop.exemplu.com&#10;magazin2.ro"></textarea>
      </div>
      <button type="submit" class="btn btn-y">Adaugă în coadă</button>
      <span style="font-size:12px;color:var(--muted);margin-left:10px">Duplicatele sunt ignorate automat.</span>
    </form>
  </div>
</div>

<!-- ── UTILIZATORI ───────────────────────────── -->
<div class="panel">
  <div class="ph" onclick="tog('users')"><h3>Utilizatori</h3><span id="a-users" class="ph-arr">▾</span></div>
  <div class="pb" id="users" style="display:none">
    <table class="tbl" style="margin-bottom:18px">
      <thead><tr><th>Utilizator</th><th>Rol</th><th>Creat</th><th>Acțiuni</th></tr></thead>
      <tbody>
      <?php foreach($users as $u): ?>
      <tr>
        <td><strong><?= htmlspecialchars($u['username']) ?></strong><?= $u['id']==$user['id'] ? ' <span style="font-size:11px;color:var(--y);font-weight:700">(tu)</span>' : '' ?></td>
        <td><span class="badge" style="background:#E8F5E9;color:#1B5E20"><?= $u['role'] ?></span></td>
        <td style="font-size:12px;color:var(--muted)"><?= substr($u['created_at'],0,10) ?></td>
        <td>
          <div class="act-btns">
            <button class="btn btn-sm btn-blue" onclick="editUser(<?= $u['id'] ?>,'<?= htmlspecialchars(addslashes($u['username'])) ?>','<?= $u['role'] ?>')">Editează</button>
            <?php if($u['id']!=$user['id']): ?>
            <form method="post" style="display:contents">
              <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
              <button name="_delete_user" value="1" class="btn btn-sm btn-red" onclick="return confirm('Ștergi utilizatorul?')">Șterge</button>
            </form>
            <?php endif; ?>
          </div>
        </td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>

    <hr class="div">
    <h4 style="font-size:13px;font-weight:700;margin-bottom:12px" id="userFormTitle">Utilizator nou</h4>
    <form method="post">
      <input type="hidden" name="_save_user" value="1">
      <input type="hidden" name="user_id" id="editUserId" value="0">
      <div class="grid2">
        <div class="fg">
          <label>Nume utilizator</label>
          <input type="text" name="uname" id="editUname" placeholder="prenume.nume">
        </div>
        <div class="fg">
          <label>Parolă nouă <span style="font-weight:400;text-transform:none">(lăsați gol = păstrați actuala)</span></label>
          <input type="password" name="upass" id="editUpass" placeholder="••••••••">
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button type="submit" class="btn btn-y" id="saveUserBtn">Salvează</button>
        <button type="button" class="btn btn-sm" onclick="resetUserForm()" style="background:#F4F7FB;color:var(--muted)">Anulează</button>
      </div>
    </form>
  </div>
</div>

<!-- ── SETARI API ────────────────────────────── -->
<div class="panel">
  <div class="ph" onclick="tog('settings')"><h3>Setări & API Keys</h3><span id="a-settings" class="ph-arr">▾</span></div>
  <div class="pb" id="settings" style="display:none">
    <form method="post">
      <input type="hidden" name="_save_settings" value="1">
      <div class="grid2">
        <div class="fg">
          <label>🔑 Google Safe Browsing API Key</label>
          <input type="text" name="google_safe_browsing_key" value="<?= htmlspecialchars($settings['google_safe_browsing_key']??'') ?>" placeholder="AIzaSy...">
          <div class="tip">console.cloud.google.com → Safe Browsing API → Credentials</div>
        </div>
        <div class="fg">
          <label>🦠 VirusTotal API Key</label>
          <input type="text" name="virustotal_key" value="<?= htmlspecialchars($settings['virustotal_key']??'') ?>" placeholder="64 chars hex">
          <div class="tip">virustotal.com → Profile → API Key (gratuit: 4 req/min)</div>
        </div>
        <div class="fg">
          <label>⏱ Interval coadă (minute)</label>
          <input type="number" name="queue_interval_minutes" value="<?= (int)($settings['queue_interval_minutes']??15) ?>" min="1" max="60">
        </div>
        <div class="fg" style="display:flex;align-items:center;gap:10px;padding-top:22px">
          <input type="checkbox" name="queue_enabled" value="1" id="qe" style="width:18px;height:18px" <?= ($settings['queue_enabled']??'1')==='1'?'checked':'' ?>>
          <label for="qe" style="font-weight:700;font-size:14px;cursor:pointer;text-transform:none;letter-spacing:0">Coadă automată activată</label>
        </div>
      </div>
      <button type="submit" class="btn btn-y">Salvează setările</button>
    </form>

    <hr class="div">
    <h4 style="font-size:13px;font-weight:700;margin-bottom:8px">Cron Job cPanel</h4>
    <div class="cron-box">*/<?= $checkInterval ?> * * * * /usr/local/bin/php <?= htmlspecialchars($serverPath) ?>/cron_scan.php</div>
    <div class="tip" style="margin-top:6px">Sau via URL (wget): cron_scan.php?key=<?= htmlspecialchars($cronKey) ?></div>

    <hr class="div">
    <h4 style="font-size:13px;font-weight:700;margin-bottom:10px">Servicii & API Keys folosite</h4>
    <table class="tbl" style="font-size:12px">
      <thead><tr><th>Serviciu</th><th>Criteriu</th><th>Cheie API</th><th>Unde o obții</th></tr></thead>
      <tbody>
        <tr><td>Google Safe Browsing</td><td>#2</td><td>Da (opțional)</td><td>console.cloud.google.com</td></tr>
        <tr><td>VirusTotal</td><td>#2</td><td>Da (opțional)</td><td>virustotal.com/gui/my-apikey</td></tr>
        <tr><td>SSL Labs API</td><td>#5</td><td>Nu (public)</td><td>automat prin ssllabs.com</td></tr>
        <tr><td>HackerTarget</td><td>#1</td><td>Nu (public)</td><td>automat pentru reverse IP</td></tr>
        <tr><td>Spamhaus / SURBL / CBL</td><td>#2 #3</td><td>Nu (DNS)</td><td>query DNS direct</td></tr>
        <tr><td>SpamCop / Barracuda / SORBS</td><td>#3</td><td>Nu (DNS)</td><td>query DNS direct</td></tr>
      </tbody>
    </table>
  </div>
</div>

<?php endif; ?>
</div><!-- /wrap -->

<script>
function tog(id) {
  const el = document.getElementById(id);
  const ar = document.getElementById('a-'+id);
  if (!el) return;
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  if (ar) ar.style.transform = hidden ? 'rotate(180deg)' : '';
}

function editUser(id, name, role) {
  document.getElementById('editUserId').value = id;
  document.getElementById('editUname').value  = name;
  document.getElementById('editUpass').value  = '';
  document.getElementById('userFormTitle').textContent = 'Editare: ' + name;
  document.getElementById('saveUserBtn').textContent   = 'Actualizează';
  document.getElementById('users').style.display = '';
  document.getElementById('a-users').textContent = '▲';
  document.getElementById('editUname').focus();
  document.getElementById('editUname').scrollIntoView({behavior:'smooth',block:'center'});
}

function resetUserForm() {
  document.getElementById('editUserId').value = '0';
  document.getElementById('editUname').value  = '';
  document.getElementById('editUpass').value  = '';
  document.getElementById('userFormTitle').textContent = 'Utilizator nou';
  document.getElementById('saveUserBtn').textContent   = 'Salvează';
}

const STATUS_COLOR = {pass:'#1B7A47',warning:'#BF6000',fail:'#B71C1C',saas:'#455A64'};
const STATUS_BG    = {pass:'#E6F4ED',warning:'#FFF3E0',fail:'#FFEBEE',saas:'#ECEFF1'};

function qcCheckChanged() {
  const check = document.getElementById('qcCheck').value;
  const hintRow = document.getElementById('qcHintRow');
  // Map check keys that have hints
  const checksWithHints = { brute_force: true };
  hintRow.style.display = checksWithHints[check] ? '' : 'none';
}

async function runQuickCheck() {
  const domain = document.getElementById('qcDomain').value.trim();
  const check  = document.getElementById('qcCheck').value;
  const out    = document.getElementById('qcResult');

  if (!domain) { document.getElementById('qcDomain').focus(); return; }

  out.style.display = 'block';
  out.innerHTML = '<div style="padding:14px;text-align:center;color:var(--muted)"><span class="spin">⏳</span> Rulează verificarea <strong>' + check + '</strong> pe <strong>' + esc(domain) + '</strong>…</div>';

  const fd = new FormData();
  fd.append('action','quick_check'); fd.append('domain',domain); fd.append('check',check);

  // Include hint fields daca exista
  if (check === 'brute_force') {
    const loginUrl = document.getElementById('qcHintLoginUrl').value.trim();
    if (loginUrl) fd.append('hints[login_url]', loginUrl);
  }

  try {
    const r = await fetch('api.php', {method:'POST',body:fd});
    const d = await r.json();
    if (!d.success) throw new Error(d.error);
    renderQuickResult(out, d.result);
  } catch(e) {
    out.innerHTML = '<div style="padding:14px;color:#B71C1C">❌ Eroare: ' + esc(e.message) + '</div>';
  }
}

function renderQuickResult(out, r) {
  const st  = r.status || 'fail';
  const col = STATUS_COLOR[st] || '#455A64';
  const bg  = STATUS_BG[st]    || '#F4F7FB';
  const rec = (r.raw_data || {}).recommendation_ro || '';
  const stars = '★'.repeat(r.stars_suggested||1) + '☆'.repeat(5-(r.stars_suggested||1));

  const details = (r.details||[]).map(d=>`<div class="qc-detail">› ${esc(d)}</div>`).join('');
  const recHtml = rec ? `<div class="qc-rec"><strong>📋 Recomandare:</strong>\n${esc(rec)}</div>` : '';
  const comHtml = r.comment_ro ? `<div class="qc-comment"><strong>Comentariu GPeC:</strong> ${esc(r.comment_ro)}</div>` : '';

  out.innerHTML = `
  <div class="qc-card">
    <div class="qc-hdr" style="background:${bg}">
      <span style="font-size:12px;font-weight:800;color:${col};min-width:38px">${esc(r.gpec_id||'')}</span>
      <span style="flex:1">${esc(r.check_name||check)}</span>
      <span style="font-size:12px;padding:2px 10px;border-radius:10px;background:${col};color:#fff">${st.toUpperCase()}</span>
      <span style="font-size:14px;margin-left:8px">${stars}</span>
    </div>
    <div class="qc-body">
      <div style="font-weight:700;margin-bottom:8px">${esc(r.summary||'')}</div>
      ${details}
      ${comHtml}
      ${recHtml}
    </div>
  </div>`;
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Filtrare scanări ──────────────────────────
let filterStatus = '';
function filterScans() {
  const q = (document.getElementById('scanSearch')?.value || '').toLowerCase().trim();
  document.querySelectorAll('#scansTable tbody tr').forEach(tr => {
    const dom = (tr.dataset.domain || '').toLowerCase();
    const st  = tr.dataset.status || '';
    tr.style.display = (!q || dom.includes(q)) && (!filterStatus || st === filterStatus) ? '' : 'none';
  });
}
function setFilter(s, el) {
  filterStatus = s;
  document.querySelectorAll('.filter-btn').forEach(b => b.style.opacity = '0.55');
  if (el) el.style.opacity = '1';
  filterScans();
}
// Activează "Toate" implicit
document.addEventListener('DOMContentLoaded', () => {
  const all = document.querySelector('.filter-btn[data-s=""]');
  if (all) all.style.opacity = '1';
});

// ── Export CSV ───────────────────────────────
function exportCSV() {
  const rows = [['Domeniu','Status','Scor','Checks','Data','Nota']];
  document.querySelectorAll('#scansTable tbody tr').forEach(tr => {
    if (tr.style.display === 'none') return;
    const cells = tr.querySelectorAll('td');
    rows.push([
      cells[0]?.innerText?.trim() || '',
      cells[1]?.innerText?.trim() || '',
      cells[2]?.innerText?.trim() || '',
      cells[3]?.innerText?.trim() || '',
      cells[4]?.innerText?.trim() || '',
      cells[5]?.innerText?.trim() || '',
    ]);
  });
  const csv = rows.map(r => r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\r\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,\uFEFF' + encodeURIComponent(csv);
  a.download = 'gpec-scanari-' + new Date().toISOString().slice(0,10) + '.csv';
  a.click();
}

<?php if ($runningCount > 0): ?>
// Auto-refresh la fiecare 12 secunde cand sunt scanari active
(function() {
  const badge = document.createElement('div');
  badge.style.cssText = 'position:fixed;bottom:14px;right:14px;background:#1C2340;color:#F5B800;padding:7px 16px;border-radius:20px;font-size:12px;font-weight:700;box-shadow:0 2px 8px rgba(0,0,0,.3);z-index:999';
  let secs = 12;
  badge.textContent = '⟳ Auto-refresh în ' + secs + 's';
  document.body.appendChild(badge);
  const iv = setInterval(() => {
    secs--;
    badge.textContent = '⟳ Auto-refresh în ' + secs + 's';
    if (secs <= 0) { clearInterval(iv); location.reload(); }
  }, 1000);
})();
<?php endif; ?>
</script>
</body>
</html>
