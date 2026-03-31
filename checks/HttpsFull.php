<?php
require_once __DIR__ . '/BaseCheck.php';

class HttpsFull extends BaseCheck {

    // Pagini reprezentative de verificat pentru mixed content / HTTPS
    private const PAGES = [
        '/', '/contact', '/about', '/despre', '/produse', '/products',
        '/cart', '/cos', '/checkout', '/comanda', '/cont', '/account',
        '/categorie', '/category', '/blog',
    ];

    public function run(): array {
        $details = [];
        $issues  = [];

        // 1. Redirect HTTP → HTTPS (homepage)
        $http = $this->httpGet("http://{$this->domain}", 10, false);
        if ($http['httpCode'] >= 301 && $http['httpCode'] <= 308) {
            $loc = $http['headers']['location'] ?? '';
            if (str_starts_with($loc, 'https://')) {
                $details[] = "Redirect HTTP → HTTPS: DA ({$http['httpCode']})";
            } else {
                $issues[] = 'redirect_wrong';
                $details[] = "Redirect HTTP → HTTPS: PARTIAL (redirecteaza catre: {$loc})";
            }
        } elseif ($http['httpCode'] === 200) {
            $issues[] = 'no_redirect';
            $details[] = "Redirect HTTP → HTTPS: NU — site accesibil via HTTP fara redirect";
        } else {
            $details[] = "HTTP status {$http['httpCode']}: nedeterminat";
        }

        // 2. HSTS header
        $https     = $this->httpGet("https://{$this->domain}", 10);
        $hsts      = $https['headers']['strict-transport-security'] ?? '';
        if ($hsts) {
            $details[] = "HSTS: prezent — {$hsts}";
            // Verifica max-age
            if (preg_match('/max-age=(\d+)/', $hsts, $m) && (int)$m[1] < 2592000) {
                $details[] = 'HSTS: max-age sub 30 zile — recomandat minim 6 luni (15768000)';
                $issues[]  = 'hsts_short';
            }
        } else {
            $issues[]  = 'no_hsts';
            $details[] = "HSTS: lipsa — recomandat pentru securitate maxima";
        }

        // 3. Mixed content scan pe mai multe pagini
        $mixedPages = [];
        $checkedPages = 0;
        $homeBody = $https['body'] ?? '';

        foreach (self::PAGES as $path) {
            $url = "https://{$this->domain}{$path}";
            if ($path === '/') {
                $body = $homeBody;
            } else {
                $res = $this->httpGet($url, 7);
                if ($res['httpCode'] !== 200) continue;
                $body = $res['body'] ?? '';
            }
            if (!$body) continue;
            $checkedPages++;

            preg_match_all('/(?:src|href|action)=["\']http:\/\/([^"\']+)["\']/', $body, $matches);
            foreach ($matches[0] as $m) {
                if (!str_contains($m, $this->domain)) {
                    $mixedPages[$path][] = substr($m, 0, 70);
                }
            }
            if ($checkedPages >= 6) break; // max 6 pagini pentru performanta
        }

        $totalMixed = array_sum(array_map('count', $mixedPages));
        if ($totalMixed > 0) {
            $issues[]  = 'mixed_content';
            foreach ($mixedPages as $pg => $res) {
                $details[] = "Mixed content pe {$pg}: " . implode(', ', array_unique(array_slice($res, 0, 3)));
            }
        } else {
            $details[] = "Mixed content: nicio resursa HTTP detectata pe {$checkedPages} pagini verificate";
        }

        // 4. www subdomain redirect
        $www = $this->httpGet("http://www.{$this->domain}", 8, false);
        if ($www['httpCode'] >= 301 && str_starts_with($www['headers']['location'] ?? '', 'https://')) {
            $details[] = "www: redirect HTTPS corect";
        } elseif ($www['httpCode'] === 200) {
            $details[] = "www: accesibil via HTTP fara redirect (risc secundar)";
        }

        // 5. Securitate headers suplimentare (informationale)
        $xframe = $https['headers']['x-frame-options'] ?? '';
        $xcto   = $https['headers']['x-content-type-options'] ?? '';
        $csp    = $https['headers']['content-security-policy'] ?? '';
        if (!$xframe)  $details[] = 'X-Frame-Options: lipsa (protectie clickjacking)';
        if (!$xcto)    $details[] = 'X-Content-Type-Options: lipsa';
        if ($csp)      $details[] = 'Content-Security-Policy: prezent (excelent)';

        // Evaluare finala
        if (in_array('no_redirect', $issues)) {
            return $this->result('#4', 'HTTPS Full Site', 'fail', 1,
                'Site-ul NU redirecteaza HTTP → HTTPS — conexiuni nesecurizate posibile.',
                $details,
                "Site-ul {$this->domain} este accesibil via HTTP fara redirectare automata catre HTTPS. " .
                "Datele utilizatorilor (inclusiv date de card sau parole) pot fi interceptate. " .
                "Necesita configurare imediata: redirect permanent (301) HTTP→HTTPS si implementarea HSTS.",
                ['issues' => $issues, 'recommendation_ro' => $this->recFail($totalMixed)]
            );
        }
        if (!empty($issues)) {
            $probs = [];
            if (in_array('mixed_content',   $issues)) $probs[] = "mixed content ({$totalMixed} resurse HTTP)";
            if (in_array('no_hsts',         $issues)) $probs[] = 'HSTS lipsa';
            if (in_array('hsts_short',      $issues)) $probs[] = 'HSTS max-age prea scurt';
            if (in_array('redirect_wrong',  $issues)) $probs[] = 'redirect incomplet';
            return $this->result('#4', 'HTTPS Full Site', 'warning', 3,
                'HTTPS partial implementat: ' . implode(', ', $probs) . '.',
                $details,
                "Site-ul {$this->domain} foloseste HTTPS, insa exista probleme: " . implode('; ', $probs) . ". " .
                (in_array('mixed_content', $issues) ? "Continutul mixt poate fi interceptat de atacatori (MITM). " : '') .
                (in_array('no_hsts',       $issues) ? "Lipsa HSTS permite atacuri de tip SSL stripping. " : '') .
                "Se recomanda remedierea completa pentru conformitate GPeC.",
                ['issues' => $issues, 'mixed_pages' => array_keys($mixedPages), 'recommendation_ro' => $this->recWarning($issues, $totalMixed)]
            );
        }
        return $this->result('#4', 'HTTPS Full Site', 'pass', 5,
            "HTTPS corect implementat — redirect activ, HSTS prezent, fara mixed content ({$checkedPages} pagini scanate).",
            $details,
            "Site-ul {$this->domain} are HTTPS corect implementat: redirectul HTTP→HTTPS este activ, headerul HSTS este prezent si nu au fost detectate resurse mixed content pe {$checkedPages} pagini verificate. Comunicatia este securizata end-to-end.",
            ['checked_pages' => $checkedPages, 'recommendation_ro' => $this->recPass()]
        );
    }

    private function recFail(int $mixed): string {
        return <<<REC
HTTPS NE-IMPLEMENTAT CORECT — ACTIUNI OBLIGATORII

1. ACTIVAREA REDIRECTULUI HTTP → HTTPS
Orice cerere HTTP trebuie redirectata automat catre HTTPS cu cod 301 (redirect permanent).
Apache (.htaccess):
  RewriteEngine On
  RewriteCond %{HTTPS} off
  RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
Nginx:
  server { listen 80; return 301 https://\$host\$request_uri; }
cPanel: activati optiunea "Force HTTPS Redirect" din sectiunea Domains.

2. CERTIFICAT SSL VALID
Verificati ca certificatul SSL nu este expirat si este emis de o autoritate de certificare recunoscuta (Let's Encrypt, DigiCert, Sectigo). Certificatele self-signed nu sunt acceptate de browsere fara avertisment.

3. IMPLEMENTAREA HSTS (HTTP Strict Transport Security)
Adaugati headerul Strict-Transport-Security pentru a forta HTTPS pe termen lung:
  Header always set Strict-Transport-Security "max-age=15768000; includeSubDomains; preload"
max-age=15768000 reprezinta 6 luni. Dupa verificare, puteti creste la 31536000 (1 an) si adauga domeniul la lista HSTS Preload (hstspreload.org).

4. ELIMINAREA MIXED CONTENT
Orice resursa (imagine, script, CSS, iframe, API call) incarcata prin HTTP pe o pagina HTTPS constituie mixed content si poate fi blocata de browser sau exploatata prin MITM.
Cautati in codul sursa: src="http://, href="http://, action="http://, url(http://
Inlocuiti toate URL-urile absolute HTTP cu HTTPS sau cu URL-uri relative (//exemplu.com/...).

5. VERIFICAREA SUBDOMENIURILOR
Asigurati-va ca www, checkout, api, cdn si alte subdomenii au de asemenea certificate SSL valide si redirecteaza catre HTTPS.

6. IMPACT CONFORMITATE GPeC
Lipsa HTTPS afecteaza direct scorul GPeC la criteriul #967. Un magazin fara HTTPS nu poate procesa platile online in siguranta si incalca cerintele PCI DSS. Clientii vor vedea avertismentul "Not Secure" in browser, ceea ce afecteaza major increderea si rata de conversie.

PRIORITATE: CRITICA — Implementati in maximum 24 ore.
REC;
    }

    private function recWarning(array $issues, int $mixed): string {
        $parts = [];
        if (in_array('no_hsts', $issues) || in_array('hsts_short', $issues)) {
            $parts[] = <<<HSTS
IMPLEMENTAREA / IMBUNATATIREA HSTS
Headerul HTTP Strict Transport Security (HSTS) instruieste browserele sa acceseze intotdeauna site-ul prin HTTPS, chiar daca utilizatorul introduce manual http://. Fara HSTS, atacurile SSL stripping pot intercepta prima conexiune.
Valoare recomandata:
  Strict-Transport-Security: max-age=15768000; includeSubDomains; preload
Pasii de configurare:
- Apache: Header always set Strict-Transport-Security "max-age=15768000; includeSubDomains"
- Nginx: add_header Strict-Transport-Security "max-age=15768000; includeSubDomains" always;
- cPanel/LiteSpeed: adaugati in .htaccess sau din Security Headers
Dupa 1-2 luni fara probleme, trimiteti domeniul la hstspreload.org pentru includere in lista Chromium HSTS Preload — dupa care browserele nu vor mai incerca niciodata HTTP pentru domeniu.
HSTS;
        }
        if (in_array('mixed_content', $issues)) {
            $parts[] = <<<MIXED
ELIMINAREA MIXED CONTENT ({$mixed} resurse HTTP detectate)
Mixed content apare cand o pagina HTTPS incarca resurse prin HTTP. Browserele moderne blocheaza continutul activ mixt (scripturi, iframes) si avertizeaza pentru continutul pasiv (imagini, CSS).
Cum sa gasiti si sa rezolvati:
1. Deschideti Chrome DevTools (F12) → Console → cautati erori "Mixed Content"
2. Rulati in terminal: grep -r "src=\"http://" ./public_html/ --include="*.php" --include="*.html"
3. Inlocuiti toate URL-urile http:// cu https:// sau cu URL-uri protocol-relative //
4. Verificati fisierele CSS pentru url(http://...)
5. Verificati continuturile dinamice din baza de date (CMS-urile stocheaza URL-uri absolute)
   - WordPress: rulati in phpMyAdmin:
     UPDATE wp_options SET option_value = REPLACE(option_value, 'http://', 'https://') WHERE option_name IN ('siteurl', 'home');
     Sau folositi plugin-ul "Better Search Replace" pentru inlocuire completa in DB.
6. Verificati si subpaginile: produse, checkout, cont — nu doar homepage-ul.
MIXED;
        }
        return implode("\n\n---\n\n", $parts) ?: 'Remediati problemele identificate pentru conformitate completa HTTPS.';
    }

    private function recPass(): string {
        return <<<REC
HTTPS IMPLEMENTAT CORECT — RECOMANDARI PENTRU OPTIMIZARE AVANSATA

Site-ul respecta cerintele de baza GPeC pentru criteriul #967. Pentru a mentine si imbunatatit nivelul de securitate, luati in considerare urmatoarele:

1. HSTS PRELOAD
Daca nu este deja adaugat, trimiteti domeniul la hstspreload.org. Dupa includere in lista Chrome/Firefox, browserele vor forta HTTPS intotdeauna, chiar inaintea primei conexiuni.

2. CERTIFICATE PINNING / CAA DNS
Adaugati un record DNS de tip CAA (Certification Authority Authorization) pentru a restrictioa ce autoritati de certificare pot emite certificate pentru domeniu:
  example.com. CAA 0 issue "letsencrypt.org"
Acest lucru previne emiterea neautorizata a certificatelor.

3. CONTENT SECURITY POLICY (CSP)
Implementati un header CSP strict pentru a preveni XSS si mixed content programatic:
  Content-Security-Policy: default-src 'self' https:; img-src 'self' https: data:; script-src 'self' https: 'nonce-{RANDOM}';
Incepeti cu Content-Security-Policy-Report-Only pentru a testa fara a bloca continut.

4. MONITORIZARE CERTIFICAT
Configurati alerte pentru expirarea certificatului SSL (Certificate Transparency logs — crt.sh). Servicii ca UptimeRobot sau Zabbix pot notifica cu 30 zile inainte de expirare.

5. VERIFICARE PERIODICA
Rulati un audit SSL Labs (ssllabs.com/ssltest) la fiecare 6 luni sau dupa modificari majore ale serverului. Mentineti nota A sau A+.
REC;
    }
}
