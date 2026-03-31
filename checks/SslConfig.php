<?php
require_once __DIR__ . '/BaseCheck.php';

class SslConfig extends BaseCheck {

    public function run(): array {
        // Încearcă SSL Labs (cu cache de 24h — rapid dacă domeniu recent testat)
        $labsResult = $this->checkSSLLabs();

        if ($labsResult && isset($labsResult['grade'])) {
            return $this->buildFromLabsGrade($labsResult);
        }

        // Fallback: verificare directă TLS
        return $this->checkDirectTLS();
    }

    private function checkSSLLabs(): ?array {
        // Încearcă mai întâi din cache
        $url = "https://api.ssllabs.com/api/v3/analyze?host={$this->domain}&publish=off&fromCache=on&maxAge=24&all=done";
        $res = $this->httpGet($url, 15);

        if ($res['httpCode'] !== 200) return null;
        $data = json_decode($res['body'], true);
        if (!$data || !isset($data['status'])) return null;

        if ($data['status'] === 'READY') {
            return $this->parseLabsResult($data);
        }

        // Nu e în cache — pornește scan nou și asteaptă max 90s
        $startUrl = "https://api.ssllabs.com/api/v3/analyze?host={$this->domain}&publish=off&startNew=on&all=done";
        $this->httpGet($startUrl, 10);

        // Polling la fiecare 15 secunde, max 5 încercări (75s)
        for ($i = 0; $i < 5; $i++) {
            sleep(15);
            $poll = $this->httpGet("https://api.ssllabs.com/api/v3/analyze?host={$this->domain}&publish=off&all=done", 12);
            if ($poll['httpCode'] !== 200) continue;
            $d = json_decode($poll['body'], true);
            if (!$d) continue;
            if ($d['status'] === 'READY') return $this->parseLabsResult($d);
            if ($d['status'] === 'ERROR')  return null;
        }

        return null; // timeout — fallback la verificare directă
    }

    private function parseLabsResult(array $data): array {
        $endpoints = $data['endpoints'] ?? [];
        if (empty($endpoints)) return null;

        // Ia cel mai bun grad (sau cel mai slab dacă vrem sa fim conservatori)
        // Folosim cel mai slab grad pentru a fi corect
        $grades = array_filter(array_column($endpoints, 'grade'), fn($g) => !empty($g));
        if (empty($grades)) return null;

        $order = ['A+' => 0, 'A' => 1, 'A-' => 2, 'B' => 3, 'C' => 4, 'D' => 5, 'E' => 6, 'F' => 7, 'T' => 8, 'M' => 9];
        usort($grades, fn($a, $b) => ($order[$a] ?? 99) <=> ($order[$b] ?? 99));
        $best  = $grades[0];
        $worst = end($grades);

        $expiry   = null;
        $certInfo = [];
        foreach ($endpoints as $ep) {
            if (isset($ep['details']['cert']['notAfter'])) {
                $expiry   = (int)$ep['details']['cert']['notAfter'];
                $certInfo = $ep['details']['cert'] ?? [];
                break;
            }
        }

        return [
            'grade'    => $worst,   // cel mai slab = nota finală
            'best'     => $best,
            'expiry'   => $expiry,
            'certInfo' => $certInfo,
            'source'   => 'ssllabs',
            'endpoints'=> count($endpoints),
        ];
    }

    private function buildFromLabsGrade(array $labs): array {
        $grade    = $labs['grade'];
        $daysLeft = $labs['expiry'] ? (int)(($labs['expiry'] - time()) / 86400) : null;
        $details  = [
            "Sursa: SSL Labs (ssllabs.com/ssltest/)",
            "Grad SSL Labs: {$grade}" . ($labs['best'] !== $grade ? " (cel mai bun endpoint: {$labs['best']})" : ''),
        ];

        if ($daysLeft !== null) {
            if ($daysLeft < 0)  $details[] = "Certificat: EXPIRAT de " . abs($daysLeft) . " zile";
            elseif ($daysLeft < 14) $details[] = "Certificat: expiră în {$daysLeft} zile — URGENT";
            else $details[] = "Certificat: valid, expiră în {$daysLeft} zile";
        }

        $gradeMap = [
            'A+'=> [5, 'pass',    'Configurație SSL optimă — nota A+ SSL Labs.'],
            'A' => [5, 'pass',    'Configurație SSL excelentă — nota A SSL Labs.'],
            'A-'=> [4, 'pass',    'Configurație SSL foarte bună — nota A- SSL Labs.'],
            'B' => [3, 'warning', 'Configurație SSL acceptabilă dar cu vulnerabilități minore — nota B.'],
            'C' => [2, 'warning', 'Configurație SSL slabă — nota C SSL Labs, protocoale vechi active.'],
            'D' => [1, 'fail',    'Configurație SSL nesigură — nota D SSL Labs.'],
            'F' => [1, 'fail',    'Configurație SSL critică — nota F SSL Labs, vulnerabilități grave.'],
            'T' => [1, 'fail',    'Certificat SSL neîncrezut (self-signed sau CA necunoscută).'],
            'M' => [1, 'fail',    'Nepotrivire certificat — domeniu neacoperit de certificat.'],
        ];

        [$stars, $status, $summary] = $gradeMap[$grade] ?? [1, 'fail', "Grad SSL necunoscut: {$grade}"];

        $comment = match($status) {
            'pass'    => "Configurația SSL a site-ului {$this->domain} a obținut nota {$grade} pe SSL Labs (ssllabs.com/ssltest/). " .
                         ($daysLeft !== null ? "Certificatul este valid, expiră în {$daysLeft} zile. " : '') .
                         "Aceasta asigură securitatea datelor transmise de utilizatori.",
            'warning' => "Configurația SSL a site-ului {$this->domain} a obținut nota {$grade} pe SSL Labs, indicând vulnerabilități minore. " .
                         "Se recomandă consultarea raportului complet pe ssllabs.com/ssltest/ pentru detalii și remediere.",
            default   => "Configurația SSL a site-ului {$this->domain} a obținut nota {$grade} pe SSL Labs — situație critică. " .
                         "Necesită remediere urgentă. Consultați raportul complet pe ssllabs.com/ssltest/analyze.html?d={$this->domain}",
        };

        return $this->result('#5', 'Configuratie SSL', $status, $stars, $summary, $details, $comment,
            ['recommendation_ro' => $this->recByGrade($grade, $daysLeft), 'labs_grade' => $grade]);
    }

    private function checkDirectTLS(): array {
        $details = ['Sursa: verificare directă TLS (SSL Labs indisponibil sau timeout)'];
        $issues  = [];

        $certInfo = $this->getCertInfo($this->domain);
        if (!$certInfo) {
            return $this->result('#5', 'Configuratie SSL', 'fail', 1,
                'Nu s-a putut stabili conexiunea TLS/HTTPS.',
                array_merge($details, ['Conexiune SSL eșuată — HTTPS indisponibil sau certificat invalid']),
                "Site-ul {$this->domain} nu acceptă conexiuni HTTPS. Certificatul SSL poate fi expirat, invalid sau serverul nu suportă TLS.",
                ['recommendation_ro' => $this->recByGrade('F', null)]
            );
        }

        $validTo  = $certInfo['validTo_time_t'] ?? 0;
        $daysLeft = (int)(($validTo - time()) / 86400);
        $cn       = $certInfo['subject']['CN'] ?? '';
        $issuer   = $certInfo['issuer']['O']   ?? ($certInfo['issuer']['CN'] ?? 'necunoscut');

        if ($daysLeft < 0)   { $issues[] = 'expired';       $details[] = "Certificat: EXPIRAT de " . abs($daysLeft) . " zile"; }
        elseif ($daysLeft < 14) { $issues[] = 'exp_soon';   $details[] = "Certificat: expiră în {$daysLeft} zile — URGENT"; }
        elseif ($daysLeft < 30) { $issues[] = 'exp';        $details[] = "Certificat: expiră în {$daysLeft} zile"; }
        else                     $details[] = "Certificat: valid {$daysLeft} zile (emis pentru: {$cn}, de: {$issuer})";

        // Self-signed
        if (($certInfo['issuer']['CN'] ?? '') === ($certInfo['subject']['CN'] ?? '') && $cn) {
            $issues[] = 'self_signed';
            $details[] = 'Certificat self-signed — nu este de încredere în browsere';
        }

        // TLS versiuni
        [$tls10, $tls11, $tls12, $tls13] = $this->checkTLSVersions();
        if ($tls10) { $issues[] = 'tls10'; $details[] = 'TLS 1.0: ACTIV — vulnerabil (POODLE, BEAST)'; }
        else          $details[] = 'TLS 1.0: dezactivat ✓';
        if ($tls11) { $issues[] = 'tls11'; $details[] = 'TLS 1.1: ACTIV — depreciat'; }
        else          $details[] = 'TLS 1.1: dezactivat ✓';
        if ($tls13)   $details[] = 'TLS 1.3: suportat (optim) ✓';
        elseif ($tls12) $details[] = 'TLS 1.2: suportat ✓';

        $details[] = "Notă: pentru nota precisă SSL Labs accesați: ssllabs.com/ssltest/analyze.html?d={$this->domain}";

        $critical = array_intersect($issues, ['expired','self_signed']);
        $warnings = array_intersect($issues, ['exp_soon','exp','tls10','tls11']);

        if (!empty($critical)) {
            $grade = 'F'; $status = 'fail'; $stars = 1;
            $summary = "Probleme critice SSL: " . implode(', ', array_map(fn($i) => match($i) { 'expired'=>'expirat','self_signed'=>'self-signed', default=>$i }, $critical)) . '.';
        } elseif (!empty($warnings)) {
            $grade = 'B'; $status = 'warning'; $stars = 3;
            $summary = "SSL funcțional cu probleme: " . implode(', ', array_map(fn($i) => match($i) { 'exp_soon'=>'expiră curând','exp'=>'expiră în curând','tls10'=>'TLS 1.0 activ','tls11'=>'TLS 1.1 activ', default=>$i }, $warnings)) . '.';
        } else {
            $grade = 'A'; $status = 'pass'; $stars = 5;
            $summary = "SSL corect configurat — TLS modern, certificat valid ({$daysLeft} zile).";
        }

        $comment = "Configurație SSL {$this->domain}: {$summary}. Verificare manuală recomandată pe ssllabs.com/ssltest/analyze.html?d={$this->domain} pentru raport complet.";

        return $this->result('#5', 'Configuratie SSL', $status, $stars, $summary, $details, $comment,
            ['recommendation_ro' => $this->recByGrade($grade, $daysLeft)]);
    }

    private function getCertInfo(string $domain): ?array {
        $ctx = stream_context_create(['ssl' => [
            'capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $domain,
        ]]);
        $fp = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) return null;
        $params = stream_context_get_params($fp);
        fclose($fp);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        return $cert ? (openssl_x509_parse($cert) ?: null) : null;
    }

    private function checkTLSVersions(): array {
        $versions = [STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT, STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT];
        return array_map(function($ver) {
            $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'crypto_method' => $ver]]);
            $fp  = @stream_socket_client("ssl://{$this->domain}:443", $e, $s, 5, STREAM_CLIENT_CONNECT, $ctx);
            if ($fp) { fclose($fp); return true; }
            return false;
        }, $versions);
    }

    private function recByGrade(string $grade, ?int $daysLeft): string {
        return match(true) {
            in_array($grade, ['A+','A','A-']) => $this->recPass($grade, $daysLeft),
            $grade === 'B' => $this->recWarningB($daysLeft),
            in_array($grade, ['C','D']) => $this->recWarningCD($grade),
            default => $this->recFail($grade),
        };
    }

    private function recPass(string $grade, ?int $daysLeft): string {
        $expMsg = $daysLeft !== null ? "Certificatul mai este valabil {$daysLeft} zile." : '';
        return "✅ CONFIGURAȚIE SSL EXCELENTĂ — Nota {$grade} SSL Labs

Felicitări! Configurația SSL/TLS a magazinului dvs. este la un nivel excelent. {$expMsg}

CE FUNCȚIONEAZĂ BINE:
• Protocoale TLS moderne activate (TLS 1.2 și/sau 1.3)
• Protocoalele vulnerabile (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) sunt dezactivate
• Suitele de cifrare sunt moderne și securizate
• Certificatul este valid și emis de o autoritate de certificare de încredere

RECOMANDĂRI DE MENȚINERE:
1. Configurați reînnoirea automată a certificatului (Let's Encrypt cu certbot sau prin cPanel) — cu cel puțin 30 de zile înainte de expirare
2. Activați HSTS (HTTP Strict Transport Security) cu directiva preload dacă nu este deja activă: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
3. Verificați periodic pe ssllabs.com/ssltest/ — vizați menținerea notei A sau A+
4. Activați OCSP Stapling pentru performanță îmbunătățită la validarea certificatelor
5. Configurați Certificate Transparency Monitoring pentru a fi notificat dacă cineva emite certificate false pentru domeniul dvs.
6. Dacă folosiți Let's Encrypt, verificați că reînnoirea automată (cron job) funcționează corect

MONITORIZARE:
• Setați un reminder calendaristic cu 45 de zile înainte de expirarea certificatului ca backup
• Monitorizați configurația cu Mozilla Observatory: observatory.mozilla.org
• Urmăriți anunțurile despre vulnerabilități TLS noi (ex: Heartbleed, BEAST, POODLE) și reacționați prompt";
    }

    private function recWarningB(?int $daysLeft): string {
        return "⚠️ CONFIGURAȚIE SSL — NOTA B: ÎMBUNĂTĂȚIRI NECESARE

Configurația SSL a magazinului dvs. este funcțională dar prezintă vulnerabilități minore care pot afecta securitatea și pot duce la o notă sub A pe SSL Labs.

CAUZE FRECVENTE ALE NOTEI B:
• TLS 1.0 sau TLS 1.1 sunt încă activate pe server
• Suite de cifrare slabe sunt disponibile ca opțiune (RC4, 3DES, export ciphers)
• Lipsa suportului pentru Forward Secrecy (PFS) pe unele suite
• Renegociere TLS nesigură activată
• Certificatul nu are toate intermediarele configurate corect în lanț

PAȘI DE REMEDIERE (ordinea priorităților):

1. DEZACTIVAȚI TLS 1.0 și TLS 1.1 — aceasta singură poate ridica nota la A:
   În Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
   În Nginx: ssl_protocols TLSv1.2 TLSv1.3;

2. CONFIGURAȚI SUITE DE CIFRARE MODERNE:
   Nginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
   Apache: SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4

3. ACTIVAȚI HSTS:
   Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"

4. ACTIVAȚI OCSP STAPLING:
   Nginx: ssl_stapling on; ssl_stapling_verify on;

5. VERIFICAȚI lanțul de certificate — certificatele intermediare trebuie incluse corect

RESURSE UTILE:
• Raport detaliat: ssllabs.com/ssltest/analyze.html?d={$this->domain}
• Generator configurație SSL: ssl-config.mozilla.org
• Ghid complet: cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

TIMELINE: Remediere în 1-2 săptămâni. Vizați nota A sau A+.";
    }

    private function recWarningCD(string $grade): string {
        return "🔴 CONFIGURAȚIE SSL NESIGURĂ — NOTA {$grade}: REMEDIERE URGENTĂ

Nota {$grade} pe SSL Labs indică vulnerabilități semnificative în configurația SSL care pot pune în pericol datele utilizatorilor și pot afecta conformitatea PCI-DSS necesară pentru procesarea plăților online.

RISCURI CONCRETE:
• Protocoalele vechi active (TLS 1.0/1.1, SSL 3.0) permit atacuri de tip POODLE, BEAST, CRIME
• Suite de cifrare slabe permit atacuri de tip man-in-the-middle
• Datele transmise de clienți (inclusiv datele de card dacă nu se folosește un procesor extern) pot fi interceptate
• Browserele moderne pot afișa avertismente de securitate utilizatorilor

PAȘI DE REMEDIERE IMEDIATĂ:

1. Dezactivați COMPLET SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
2. Activați TLS 1.2 și TLS 1.3 exclusiv
3. Eliminați suitele de cifrare slabe (RC4, DES, 3DES, EXPORT, NULL, anon)
4. Actualizați OpenSSL la cea mai recentă versiune disponibilă
5. Verificați că certificatul este emis de o CA de încredere și că lanțul e complet
6. Activați HSTS cu max-age de minim 6 luni

CONFIGURAȚIE NGINX RECOMANDATĂ MINIMAL:
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
add_header Strict-Transport-Security \"max-age=63072000\" always;

Contactați furnizorul de hosting pentru asistență dacă nu aveți acces la configurația serverului. TIMELINE: Remediere urgentă în maxim 72 de ore.";
    }

    private function recFail(string $grade): string {
        return "🔴 CRITICA SSL — NOTA {$grade}: PERICOL PENTRU UTILIZATORI

Configurația SSL/TLS a magazinului prezintă vulnerabilități critice. " . match($grade) {
            'F' => "Nota F SSL Labs indică vulnerabilități grave exploatabile activ.",
            'T' => "Nota T indică un certificat neîncrezut (self-signed sau CA necunoscută) — browserele afișează avertismente roșii utilizatorilor.",
            'M' => "Nota M indică o nepotrivire între certificat și domeniu — utilizatorii văd erori de securitate.",
            default => "Situație critică detectată."
        } . "

IMPACT IMEDIAT:
• Browserele Chrome, Firefox, Safari pot bloca accesul utilizatorilor la site
• Google poate penaliza site-ul în rezultatele căutărilor
• Procesatorii de plăți pot suspenda accesul la API dacă configurația SSL nu respectă PCI-DSS
• Datele utilizatorilor pot fi interceptate

ACȚIUNI IMEDIATE (în 24 ore):
1. Contactați furnizorul de hosting URGENT pentru remedierea configurației SSL
2. Dacă certificatul este expirat sau self-signed, emiteți imediat un certificat valid (Let's Encrypt este GRATUIT și se configurează în câteva minute din cPanel)
3. Activați HTTPS forțat (redirect 301 de la HTTP la HTTPS)
4. Testați după remediere pe: ssllabs.com/ssltest/analyze.html?d={$this->domain}

OBȚINERE CERTIFICAT LET'S ENCRYPT (cPanel):
1. Intrați în cPanel → SSL/TLS → Manage SSL Sites
2. Sau: cPanel → Let's Encrypt (dacă e disponibil ca plugin)
3. Alternativ: accesați sslforfree.com sau zerossl.com pentru ghiduri

NU PERMITEȚI operarea magazinului cu SSL compromis — riscul pentru datele clienților și pentru reputația afacerii este prea mare.";
    }
}
