<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/config.php';

// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: login'); exit;
}

// Deja logat → redirect
if (isLoggedIn()) {
    header('Location: index'); exit;
}

$err  = '';
$next = trim($_GET['next'] ?? 'index');
// Sanitizeaza next sa nu iasa din domeniu
if (!preg_match('#^[a-zA-Z0-9/_\-\.?=&]+$#', $next)) $next = 'index';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = trim($_POST['username'] ?? '');
    $pass = $_POST['password'] ?? '';

    if ($user && $pass) {
        try {
            $s = getDB()->prepare('SELECT id, username, password_hash, role FROM users WHERE username=? LIMIT 1');
            $s->execute([$user]);
            $row = $s->fetch();
            if ($row && password_verify($pass, $row['password_hash'])) {
                $_SESSION['gpec_user'] = [
                    'id'       => $row['id'],
                    'username' => $row['username'],
                    'role'     => $row['role'],
                ];
                header('Location: ' . $next); exit;
            }
        } catch (Throwable) {}
        $err = 'Utilizator sau parolă incorectă.';
    } else {
        $err = 'Completează ambele câmpuri.';
    }
}
?><!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GPeC — Autentificare</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:linear-gradient(135deg,#1C2340 0%,#252D4A 100%);
     min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;padding:40px 44px;width:100%;max-width:400px;
      box-shadow:0 20px 60px rgba(0,0,0,.35)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.logo-icon{width:46px;height:46px;background:#F5B800;border-radius:12px;
           display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0}
.logo-name{font-size:20px;font-weight:800;color:#1C2340;line-height:1.2}
.logo-name em{color:#F5B800;font-style:normal}
.logo-sub{font-size:12px;color:#78909C;margin-top:2px}
h2{font-size:18px;font-weight:700;color:#1A2332;margin-bottom:6px}
p.sub{font-size:13px;color:#607D8B;margin-bottom:24px}
.field{margin-bottom:16px}
label{display:block;font-size:12px;font-weight:700;color:#455A64;margin-bottom:6px;letter-spacing:.3px;text-transform:uppercase}
input{width:100%;padding:12px 16px;border:2px solid #E2E8F0;border-radius:9px;font-size:15px;
      outline:none;transition:border .15s;color:#1A2332;background:#fff}
input:focus{border-color:#F5B800}
.btn{width:100%;padding:13px;background:#F5B800;color:#1C2340;border:none;
     border-radius:9px;font-size:16px;font-weight:800;cursor:pointer;
     transition:background .15s,transform .1s;margin-top:6px}
.btn:hover{background:#C99900}
.btn:active{transform:scale(.98)}
.err{background:#FFEBEE;color:#B71C1C;padding:10px 14px;border-radius:8px;
     font-size:13px;font-weight:500;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.footer{text-align:center;margin-top:22px;font-size:12px;color:#B0BEC5}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">🔐</div>
    <div>
      <div class="logo-name">GPeC <em>Security</em></div>
      <div class="logo-sub">Health Check Tool</div>
    </div>
  </div>

  <h2>Autentificare</h2>
  <p class="sub">Accesul este restricționat auditorilor autorizați.</p>

  <?php if ($err): ?>
  <div class="err">⚠️ <?= htmlspecialchars($err) ?></div>
  <?php endif; ?>

  <form method="post">
    <div class="field">
      <label>Utilizator</label>
      <input type="text" name="username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
             placeholder="ex: liviu.baltoi" autofocus autocomplete="username">
    </div>
    <div class="field">
      <label>Parolă</label>
      <input type="password" name="password" placeholder="••••••••••" autocomplete="current-password">
    </div>
    <button type="submit" class="btn">Intră în aplicație →</button>
  </form>

  <div class="footer">GPeC Security Health Check &copy; <?= date('Y') ?></div>
</div>
</body>
</html>
