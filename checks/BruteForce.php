<?php
require_once __DIR__ . '/BaseCheck.php';

class BruteForce extends BaseCheck {

    private const LOGIN_PATHS = [
        // English / CMS standard
        '/wp-login.php', '/wp-admin/', '/administrator/', '/admin/',
        '/login', '/login/', '/user/login', '/signin', '/account/login',
        '/customer/account/login/', '/backend/', '/cp/', '/panel/',
        '/admin/login', '/index.php/customer/account/login',
        // Romanian e-commerce paths
        '/autentificare', '/autentificare/', '/autentificare-client',
        '/inregistrare', '/inregistrare/', '/inregistrare-client',
        '/logare', '/logare/', '/cont', '/cont/', '/contul-meu',
        '/contul-meu/', '/my-account', '/my-account/',
        '/index.php/autentificare', '/index.php/cont',
        '/index.php/contul-meu', '/index.php/inregistrare',
        // PrestaShop RO
        '/autentificare?back=my-account', '/index.php?controller=authentication',
        // OpenCart RO
        '/index.php?route=account/login',
        // Generic fallbacks
        '/user', '/users/sign_in', '/account', '/accounts/sign_in',
    ];

    private const CAPTCHA_SIGNS = [
        'recaptcha', 'g-recaptcha', 'hcaptcha', 'captcha',
        'cf-turnstile', 'turnstile', 'cloudflare', 'challenge',
        'robot', 'verificare umana', 'human verification',
    ];

    private const RATELIMIT_SIGNS = [
        'too many', 'rate limit', 'too many attempts', 'temporarily blocked',
        'try again', 'prea multe', 'blocat temporar', 'incercari multiple',
        'account locked', 'cont blocat', 'suspicious activity',
    ];

    public function run(): array {
        $details = [];

        // Gaseste pagina de login
        $loginUrl  = null;
        $loginBody = '';
        $base      = "https://{$this->domain}";

        // 1. Verifica mai intai hint-ul furnizat manual (prioritate maxima)
        $hintUrl = $this->getHint('login_url');
        if ($hintUrl) {
            // Normalizeaza: adauga protocolul daca lipseste
            if (!preg_match('#^https?://#i', $hintUrl)) {
                $hintUrl = 'https://' . ltrim($hintUrl, '/');
            }
            $res = $this->httpGet($hintUrl, 10, true);
            if ($res['httpCode'] === 200) {
                $loginUrl  = $hintUrl;
                $loginBody = $res['body'];
                $details[] = "Pagina de login (din hint manual): {$loginUrl}";
            } else {
                $details[] = "⚠️ URL furnizat manual ({$hintUrl}) a returnat HTTP {$res['httpCode']} — continui cu detectia automata";
            }
        }

        // 2. Detectie automata pe caile standard (daca hint-ul nu a functionat)
        if (!$loginUrl) {
            foreach (self::LOGIN_PATHS as $path) {
                $res = $this->httpGet("{$base}{$path}", 7, true);
                if ($res['httpCode'] === 200 && $this->looksLikeLoginPage($res['body'])) {
                    $loginUrl  = "{$base}{$path}";
                    $loginBody = $res['body'];
                    break;
                }
            }
        }

        if (!$loginUrl) {
            // Incearca si HTTP
            $baseHttp = "http://{$this->domain}";
            foreach (self::LOGIN_PATHS as $path) {
                $res = $this->httpGet("{$baseHttp}{$path}", 6, true);
                if ($res['httpCode'] === 200 && $this->looksLikeLoginPage($res['body'])) {
                    $loginUrl  = "{$baseHttp}{$path}";
                    $loginBody = $res['body'];
                    break;
                }
            }
        }

        if (!$loginUrl) {
            $details[] = 'Pagina de login: neidentificata (' . count(self::LOGIN_PATHS) . ' cai verificate)';
            $hintMsg = $hintUrl
                ? " URL-ul furnizat manual ({$hintUrl}) nu a putut fi accesat (HTTP error)."
                : " Adaugati un hint cu URL-ul paginii de login din panoul de admin pentru o verificare precisa.";
            $hintTip = $hintUrl
                ? " URL-ul furnizat manual ({$hintUrl}) nu a putut fi accesat."
                : " Puteti furniza manual URL-ul paginii de login din panoul de admin (buton Hints).";
            return $this->result('#10', 'Protectie Brute Force', 'warning', 3,
                'Pagina de login nedetectata automat — verificare manuala necesara.',
                $details,
                "Pagina de autentificare a magazinului {$this->domain} nu a putut fi identificata automat.{$hintTip} " .
                "Se recomanda verificarea manuala a mecanismelor de protectie impotriva atacurilor brute force.",
                ['login_found' => false, 'recommendation_ro' => $this->recNotFound()]
            );
        }

        $details[] = "Pagina de login: {$loginUrl}";

        // Verifica CAPTCHA pe pagina initiala
        $hasCaptcha = $this->hasCaptcha($loginBody);
        if ($hasCaptcha)  $details[] = '✅ CAPTCHA: prezent pe pagina de login';
        else              $details[] = '⚠️ CAPTCHA: nedetectat pe pagina de login';

        // Cloudflare / WAF
        $cfRes    = $this->httpGet($loginUrl, 5);
        $cfActive = !empty($cfRes['headers']['cf-ray'])
                 || str_contains($cfRes['headers']['server'] ?? '', 'cloudflare');
        if ($cfActive) $details[] = '✅ Cloudflare WAF: detectat — protectie la nivel CDN';

        // Simulare tentative cu credentiale invalide
        $isWP     = str_contains($loginUrl, 'wp-login');
        $postData = $isWP
            ? ['log' => 'gpec_test_xxxxx', 'pwd' => 'gpec_wrong_pass_xxxxx', 'wp-submit' => 'Log+In', 'testcookie' => '1']
            : ['username' => 'gpec_test_xxxxx', 'password' => 'gpec_wrong_xxxxx', 'email' => 'test@gpec-audit.ro'];

        $rateLimitDetected = false;
        $blockedAt         = null;
        for ($i = 1; $i <= 4; $i++) {
            $res     = $this->httpPost($loginUrl, $postData, 7);
            $blocked = $res['httpCode'] === 429
                    || $res['httpCode'] === 403
                    || $this->hasRateLimit($res['body'], $res['httpCode'])
                    || ($this->hasCaptcha($res['body']) && !$hasCaptcha);

            $details[] = "Tentativa {$i}: HTTP {$res['httpCode']}" . ($blocked ? ' ✅ [BLOCAT/CAPTCHA aparut]' : '');
            if ($blocked) {
                $rateLimitDetected = true;
                $blockedAt         = $i;
                $details[] = "Rate limiting activ — blocat dupa {$i} incercari";
                break;
            }
            if ($i < 4) usleep(300000); // 300ms pauza intre tentative
        }

        if (!$rateLimitDetected) {
            $details[] = '⚠️ Nicio blocare detectata dupa 4 incercari gresite consecutive';
        }

        // Evaluare
        if ($hasCaptcha && $rateLimitDetected) {
            return $this->result('#10', 'Protectie Brute Force', 'pass', 5,
                'Protectie completa: CAPTCHA + rate limiting active.',
                $details,
                "Site-ul {$this->domain} are protectie completa impotriva atacurilor brute force: CAPTCHA pe pagina de login si blocare activa dupa incercari repetate (la {$blockedAt} tentative). Conformitate deplina cu recomandarile GPeC.",
                ['login_url' => $loginUrl, 'captcha' => true, 'rate_limit' => true, 'blocked_at' => $blockedAt,
                 'recommendation_ro' => $this->recPass(true, true)]
            );
        }
        if ($hasCaptcha || $rateLimitDetected || $cfActive) {
            $what = implode(' + ', array_filter([
                $hasCaptcha        ? 'CAPTCHA' : null,
                $rateLimitDetected ? "rate limiting (blocat la tentativa {$blockedAt})" : null,
                $cfActive          ? 'Cloudflare WAF' : null,
            ]));
            return $this->result('#10', 'Protectie Brute Force', 'pass', 4,
                "Protectie partiala detectata: {$what}.",
                $details,
                "Site-ul {$this->domain} are mecanisme de protectie: {$what}. " .
                (!$hasCaptcha ? 'Se recomanda adaugarea CAPTCHA pe formularul de login. ' : '') .
                (!$rateLimitDetected ? 'Se recomanda configurarea rate limiting explicit dupa 4-5 incercari.' : ''),
                ['login_url' => $loginUrl, 'captcha' => $hasCaptcha, 'rate_limit' => $rateLimitDetected,
                 'cloudflare' => $cfActive, 'recommendation_ro' => $this->recPass($hasCaptcha, $rateLimitDetected)]
            );
        }
        return $this->result('#10', 'Protectie Brute Force', 'fail', 1,
            'NICIO protectie brute force detectata — login vulnerabil la atacuri automate.',
            $details,
            "Pagina de autentificare ({$loginUrl}) nu are niciun mecanism de protectie impotriva atacurilor brute force: " .
            "nu exista CAPTCHA, nu s-a detectat rate limiting dupa 4 incercari. " .
            "Un atacator poate incerca automat mii de combinatii. Se impune implementarea imediata.",
            ['login_url' => $loginUrl, 'captcha' => false, 'rate_limit' => false,
             'recommendation_ro' => $this->recFail($loginUrl)]
        );
    }

    /**
     * Detecteaza daca un body HTML contine un formular de autentificare/inregistrare.
     * Suporta atat keyword-urile englezesti cat si cele romanesti.
     */
    private function looksLikeLoginPage(string $html): bool {
        $lower = strtolower($html);
        $keywords = [
            // English
            'password', 'passwd', 'type="password"',
            // Romanian
            'parola', 'autentificare', 'autentific', 'inregistrare',
            'logare', 'contul meu', 'my account',
            // Generic form signals
            'type="email"', 'name="email"', 'name="username"',
            'name="user"', 'name="log"',
        ];
        foreach ($keywords as $kw) {
            if (str_contains($lower, $kw)) return true;
        }
        return false;
    }

    private function hasCaptcha(string $html): bool {
        $lower = strtolower($html);
        foreach (self::CAPTCHA_SIGNS as $s) {
            if (str_contains($lower, $s)) return true;
        }
        return false;
    }

    private function hasRateLimit(string $html, int $code): bool {
        if ($code === 429) return true;
        $lower = strtolower($html);
        foreach (self::RATELIMIT_SIGNS as $s) {
            if (str_contains($lower, $s)) return true;
        }
        return false;
    }

    private function recNotFound(): string {
        return <<<REC
PAGINA DE LOGIN NEIDENTIFICATA — VERIFICARE MANUALA NECESARA

Auditorul automat nu a gasit pagina de autentificare pe caile standard. Aceasta poate insemna:
a) Pagina de login este pe o cale personalizata (securitate prin obscuritate — buna practica)
b) Autentificarea este realizata pe un subdomain (ex. admin.domeniu.ro)
c) Platforma foloseste SSO sau autentificare externa

Verificare manuala recomandata:
1. Accesati manual pagina de admin/cont client si testati:
   - CAPTCHA (Google reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile)
   - Blocarea temporara dupa 4-5 parole gresite
   - Mesaj de eroare generic (nu "parola incorecta" ci "credentiale invalide")
2. Daca folositi WordPress: wp-login.php trebuie protejat cu CAPTCHA si limitare incercari

Configurari recomandate indiferent de platforma:
- Implementati CAPTCHA pe toate formularele de autentificare
- Blocati temporar (15-60 min) contul sau IP-ul dupa 4-5 incercari gresite
- Logati toate tentativele de autentificare esuate cu IP si timestamp
- Trimiteti alerta email la autentificare din IP nou (suspicious login)
REC;
    }

    private function recFail(string $loginUrl): string {
        return <<<REC
NICIO PROTECTIE BRUTE FORCE — ACTIUNI URGENTE

Pagina de login ({$loginUrl}) accepta tentative nelimitate de autentificare, permitand atacuri automate cu parole.

1. IMPLEMENTAREA CAPTCHA (cea mai rapida solutie)
Google reCAPTCHA v3 (invizibil, fara friction pentru utilizatori):
- Inregistrati domeniul la google.com/recaptcha
- Integrati script-ul frontend si verificarea backend
- WordPress: plugin WP Cerber Security sau Google Captcha Pro
- Magento: module-ul Magento_ReCaptcha (inclus in Magento 2.4+)
- PrestaShop: modul Google reCAPTCHA din marketplace

Cloudflare Turnstile (alternativa gratuita, privacy-friendly):
- Inregistrati pe dash.cloudflare.com → Turnstile
- Embed widget HTML + verificare server-side

2. RATE LIMITING SI BLOCARE IP
WordPress — plugin WP Cerber Security (gratuit):
  - Max login attempts: 4
  - Account lockout duration: 60 minute
  - IP blocklist automatic
  - Notificare email la blocare

Apache .htaccess (limitare generala cereri):
  <IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        3
    DOSSiteCount        50
    DOSBlockingPeriod   10
  </IfModule>

Nginx (limitare cereri pe ruta de login):
  limit_req_zone \$binary_remote_addr zone=login:10m rate=3r/m;
  location /wp-login.php {
    limit_req zone=login burst=5 nodelay;
  }

3. BLOCARE DUPA INCERCARI GRESITE LA NIVEL APLICATIE
Daca aveti control asupra codului, implementati:
  - Contor de incercari in sesiune sau baza de date per IP
  - Dupa 4 incercari: CAPTCHA obligatoriu
  - Dupa 8 incercari: blocare temporara 15-30 minute (returnati 429 Too Many Requests)
  - Logati IP, user-agent, timestamp pentru fiecare tentativa esuata

4. MONITORIZARE SI ALERTE
- Activati notificari email pentru: autentificari esuate multiple, autentificari din tari neobisnuite
- Utilizati un WAF (Cloudflare, ModSecurity) pentru blocarea pattern-urilor de atac cunoscute
- Revizuiti saptamanal logurile de autentificare

5. MASURI SUPLIMENTARE RECOMANDATE
- Autentificare cu doi factori (2FA/MFA) pentru conturile de admin
- Parole complexe obligatorii (minim 12 caractere, alfanumerice + simboluri)
- Sesiuni cu timeout automat (ex. 30 minute inactivitate)
- Dezactivarea user-ilor inactivi

PRIORITATE: INALTA — Implementati CAPTCHA in maximum 48 ore.
REC;
    }

    private function recPass(bool $captcha, bool $rateLimit): string {
        $tips = [];
        if (!$captcha) {
            $tips[] = "Adaugati CAPTCHA pe formularul de login (Google reCAPTCHA v3 — invizibil, fara friction) pentru protectie completa.";
        }
        if (!$rateLimit) {
            $tips[] = "Configurati rate limiting explicit in aplicatie (blocare dupa 4-5 incercari) pentru protectie redundanta fata de CAPTCHA.";
        }

        $tipsText = $tips ? "\nASPECTE DE IMBUNATATIT:\n- " . implode("\n- ", $tips) . "\n" : '';

        return <<<REC
PROTECTIE BRUTE FORCE ACTIVA — RECOMANDARI AVANSATE
{$tipsText}
1. AUTENTIFICARE CU DOI FACTORI (2FA/MFA)
Chiar cu CAPTCHA si rate limiting, conturile cu parole slabe sau compromise (credential stuffing) raman vulnerabile. 2FA elimina aceasta vulnerabilitate:
- WordPress: plugin WP 2FA sau Google Authenticator
- Custom: utilizati TOTP (Time-based One-Time Password) cu biblioteca otphp/otphp
- Email OTP: cod unic trimis pe email la fiecare autentificare

2. CREDENTIAL STUFFING PROTECTION
Atacurile de tip credential stuffing folosesc baze de date de parole furate (ex. de pe alte site-uri compromise). Protectie:
- Integrare HaveIBeenPwned API: verificati la inregistrare/schimbare parola daca parola e compromisa
- Obligati utilizatorii sa-si schimbe parola dupa un incident de securitate al altor servicii

3. MONITORIZARE COMPORTAMENTALA
Implementati detectarea login-urilor suspecte:
- Login din tara/timezone neobisnuita → alerta email
- Login de pe IP nou → verificare suplimentara (OTP)
- Multiple conturi accesate de pe acelasi IP → alerta fraud

4. TESTARE PERIODICA
Testati periodic rezistenta la brute force cu instrumente legale:
- Burp Suite Community Edition — test manual pe mediu de testare
- OWASP ZAP — scanner automatizat

5. POLITICA PAROLE PUTERNICE
Asigurati-va ca platforma impune:
- Minim 10 caractere (recomandat 14+)
- Mix de caractere (majuscule, minuscule, cifre, simboluri)
- Interzicerea parolelor comune (top 10.000 parole cel mai des folosite)
- Blocarea refolosirii ultimelor 5-10 parole
REC;
    }
}
