<?php
/**
 * GPeC — Generator .htpasswd
 * Viziteaza ODATA aceasta pagina pentru a crea fisierul de autentificare,
 * apoi STERGE acest fisier de pe server!
 */

$users = [
    'liviu.baltoi'    => '!@#Tpro123',
    'cristian.iosub'  => '!@#Tpro123',
];

$htpasswdFile = __DIR__ . '/.htpasswd';
$htaccessFile = __DIR__ . '/.htaccess';
$absolutePath = __DIR__ . '/.htpasswd';

// Genereaza .htpasswd cu hash-uri bcrypt (suportat de Apache 2.4+)
$lines = [];
foreach ($users as $user => $pass) {
    $hash   = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 10]);
    $lines[] = "{$user}:{$hash}";
}
$htpasswdContent = implode("\n", $lines) . "\n";

// Scrie .htpasswd
$ok1 = file_put_contents($htpasswdFile, $htpasswdContent) !== false;

// Actualizeaza .htaccess cu calea absoluta corecta
$htaccessContent = <<<HTACCESS
AuthType Basic
AuthName "GPeC Security Tool — Acces Restrictionat"
AuthUserFile {$absolutePath}
Require valid-user

# Permite cron_scan.php fara autentificare (apel intern)
<Files "cron_scan.php">
  Satisfy Any
  Allow from all
</Files>
HTACCESS;

$ok2 = file_put_contents($htaccessFile, $htaccessContent) !== false;

?><!DOCTYPE html>
<html lang="ro"><head><meta charset="UTF-8"><title>GPeC Auth Setup</title>
<style>
body{font-family:monospace;background:#1C2340;color:#E0E0E0;padding:40px;max-width:700px}
h2{color:#F5B800}
.ok{color:#4CAF50}.err{color:#EF5350}.warn{color:#F5B800}
pre{background:#0D1117;padding:14px;border-radius:8px;font-size:13px;overflow:auto}
.box{background:#252D4A;padding:16px 20px;border-radius:10px;margin:16px 0}
</style></head><body>
<h2>🔐 GPeC Auth Setup</h2>

<div class="box">
  <p><?= $ok1 ? '<span class="ok">✅ .htpasswd creat cu succes</span>' : '<span class="err">❌ Eroare la crearea .htpasswd</span>' ?></p>
  <p><?= $ok2 ? '<span class="ok">✅ .htaccess actualizat cu calea corecta</span>' : '<span class="err">❌ Eroare la scrierea .htaccess</span>' ?></p>
  <p><strong>Cale .htpasswd:</strong> <?= htmlspecialchars($absolutePath) ?></p>
</div>

<?php if ($ok1 && $ok2): ?>
<div class="box">
  <p class="ok">✅ Utilizatori creati:</p>
  <?php foreach (array_keys($users) as $u): ?>
  <p>&nbsp;&nbsp;› <strong><?= htmlspecialchars($u) ?></strong> — rol admin</p>
  <?php endforeach; ?>
</div>

<div class="box">
  <p class="warn">⚠️ IMPORTANT: Sterge imediat acest fisier de pe server!</p>
  <pre>rm /home/i0sub/gpec.iosub.ro/generate_auth.php</pre>
  <p style="font-size:13px;margin-top:8px">Sau sterge-l din cPanel → File Manager.</p>
</div>

<p class="ok" style="margin-top:20px;font-size:15px;font-weight:bold">
  ✅ Autentificarea este activa. Reincarca orice pagina din tool pentru a testa.
</p>
<?php else: ?>
<div class="box">
  <p class="err">❌ A aparut o eroare. Verifica permisiunile de scriere pe directorul:</p>
  <pre><?= htmlspecialchars(__DIR__) ?></pre>
  <p>In cPanel → File Manager → selecteaza directorul → Permissions → seteaza 755.</p>
</div>
<?php endif; ?>
</body></html>
