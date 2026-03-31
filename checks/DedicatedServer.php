<?php
require_once __DIR__ . '/BaseCheck.php';

class DedicatedServer extends BaseCheck {

    // Cloudflare IP ranges (actualizate 2024)
    private const CF_RANGES = [
        '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22',
        '141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20',
        '197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13',
        '104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
    ];

    private const PORT_NAMES = [
        21 => 'FTP', 22 => 'SSH', 25 => 'SMTP', 53 => 'DNS',
        80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP', 443 => 'HTTPS',
        465 => 'SMTPS', 587 => 'SMTP/TLS', 993 => 'IMAPS', 995 => 'POP3S',
        3000 => 'Dev Server', 3306 => 'MySQL', 5432 => 'PostgreSQL',
        8080 => 'HTTP Alt', 8443 => 'HTTPS Alt', 2082 => 'cPanel HTTP',
        2083 => 'cPanel HTTPS', 2086 => 'WHM HTTP', 2087 => 'WHM HTTPS',
        3389 => 'RDP', 5900 => 'VNC', 6379 => 'Redis', 27017 => 'MongoDB',
    ];

    private const ALLOWED = [80, 443];
    private const SCAN    = [21, 22, 25, 53, 110, 143, 465, 587, 993, 995,
                              3000, 3306, 5432, 6379, 8080, 8443, 27017,
                              2082, 2083, 2086, 2087, 3389, 5900];

    public function run(): array {
        $ip = $this->resolveIP($this->domain);
        if (!$ip) {
            return $this->makeResult('fail', 1,
                'Nu s-a putut rezolva IP-ul domeniului.',
                ['DNS resolution eșuată pentru ' . $this->domain],
                'Nu s-a putut determina adresa IP.',
                $this->recFail(null, [], 0)
            );
        }

        $details = ["IP detectat: {$ip}"];

        // Verifica Cloudflare
        $isCF = $this->isCloudflare($ip);
        if ($isCF) {
            $details[] = "Cloudflare: DA — IP-ul real al serverului este ascuns în spatele CDN-ului Cloudflare";
            $details[] = "Avantaj: protecție DDoS, WAF, rate limiting, ascundere IP real";
        } else {
            $details[] = "Cloudflare: NU — IP real al serverului este vizibil public";
        }

        // Verifica header CF pe HTTP
        $httpCheck = $this->httpGet("https://{$this->domain}", 6);
        $cfHeader  = $httpCheck['headers']['cf-ray'] ?? $httpCheck['headers']['server'] ?? '';
        if (str_contains(strtolower($cfHeader), 'cloudflare')) {
            $details[] = "Header CF-RAY confirmat în răspunsul HTTP";
        }

        // Port scan
        $openPorts = [];
        foreach (self::SCAN as $port) {
            if ($this->testPort($ip, $port, 3)) {
                $openPorts[] = $port;
            }
        }

        $openUnexpected = array_filter($openPorts, fn($p) => !in_array($p, self::ALLOWED));
        $openUnexpected = array_values($openUnexpected);

        if (empty($openPorts)) {
            $details[] = "Porturi deschise detectate: niciun port scanat nu răspunde (firewall strict sau IP ascuns de CDN)";
        } else {
            foreach ($openPorts as $port) {
                $name      = self::PORT_NAMES[$port] ?? "Unknown";
                $isAllowed = in_array($port, self::ALLOWED);
                $details[] = "Port {$port} ({$name}): DESCHIS" . ($isAllowed ? " — normal" : " — verificați dacă e necesar");
            }
        }

        // Reverse IP (co-hosting)
        $cohosted = [];
        if (!$isCF) {
            $rev = $this->httpGet("https://api.hackertarget.com/reverseiplookup/?q={$ip}", 8);
            if ($rev['httpCode'] === 200 && !str_contains($rev['body'], 'error')) {
                $cohosted = array_filter(array_map('trim', explode("\n", $rev['body'])));
                $cohosted = array_values($cohosted);
            }
        }
        $cnt = count($cohosted);

        if ($isCF) {
            $details[] = "Co-hosting: neverificabil — IP-ul real este mascat de Cloudflare (situație pozitivă)";
        } elseif ($cnt > 0) {
            $preview   = implode(', ', array_slice($cohosted, 0, 4)) . ($cnt > 4 ? ' (+' . ($cnt-4) . ' altele)' : '');
            $details[] = "Co-hosting pe {$ip}: {$cnt} domenii ({$preview})";
        } else {
            $details[] = "Co-hosting: nicio altă gazduire detectată pe {$ip}";
        }

        // Recomandari de inchidere porturi
        $portRecs = [];
        foreach ($openUnexpected as $port) {
            $name = self::PORT_NAMES[$port] ?? "port {$port}";
            $portRecs[] = "Portul {$port} ({$name}) este deschis — verificați dacă e strict necesar și restricționați accesul prin firewall";
        }
        if (!empty($portRecs)) {
            foreach ($portRecs as $rec) $details[] = "⚠️ {$rec}";
        }

        // Evaluare
        $hasDangerous = !empty(array_intersect($openUnexpected, [3389, 5900, 27017, 6379, 3306, 5432, 2086, 2087]));
        $hasMedium    = !empty(array_intersect($openUnexpected, [21, 22, 25, 2082, 2083, 8080, 8443, 3000]));

        if (!$isCF && $hasDangerous && $cnt > 15) {
            $status = 'fail'; $stars = 1;
        } elseif (!$isCF && ($hasDangerous || $cnt > 10)) {
            $status = 'fail'; $stars = 2;
        } elseif ($isCF && empty($openUnexpected)) {
            $status = 'pass'; $stars = 5;
        } elseif ($isCF || (empty($openUnexpected) && $cnt <= 3)) {
            $status = 'pass'; $stars = 4;
        } elseif ($hasMedium || $cnt > 3) {
            $status = 'warning'; $stars = 3;
        } else {
            $status = 'pass'; $stars = 4;
        }

        $cfNote = $isCF ? " Serverul este protejat de Cloudflare CDN." : '';
        $portNote = !empty($openUnexpected)
            ? " Porturi deschise suplimentare: " . implode(', ', array_map(fn($p) => $p . ' (' . (self::PORT_NAMES[$p] ?? 'Unknown') . ')', $openUnexpected)) . '.'
            : ' Niciun port neautorizat detectat.';
        $coNote = $isCF ? '' : ($cnt > 0 ? " Pe IP-ul {$ip} sunt co-hostate {$cnt} domenii." : '');

        $comment = match($status) {
            'pass'    => "Serverul {$this->domain} ({$ip}) are o configurație corectă din punct de vedere al izolării.{$cfNote}{$portNote}{$coNote}",
            'warning' => "Serverul {$this->domain} ({$ip}) are aspecte de îmbunătățit.{$cfNote}{$portNote}{$coNote} GPeC recomandă izolarea serviciilor și minimizarea suprafeței de atac.",
            default   => "Serverul {$this->domain} ({$ip}) prezintă riscuri de izolare.{$portNote}{$coNote} Necesită restricționare urgentă prin firewall.",
        };

        return $this->makeResult($status, $stars,
            match($status) {
                'pass'    => $isCF ? "Server protejat Cloudflare — configurație optimă." : "Server bine configurat, porturi conforme.",
                'warning' => "Servicii suplimentare detectate" . ($cnt > 3 ? " + {$cnt} domenii co-hostate" : '') . '.',
                default   => "Riscuri de izolare: porturi critice expuse / co-hosting excesiv.",
            },
            $details, $comment,
            $this->recByStatus($status, $ip, $isCF, $openUnexpected, $cnt)
        );
    }

    private function isCloudflare(string $ip): bool {
        $long = ip2long($ip);
        if ($long === false) return false;
        foreach (self::CF_RANGES as $cidr) {
            [$network, $bits] = explode('/', $cidr);
            $mask = -1 << (32 - (int)$bits);
            if ((ip2long($network) & $mask) === ($long & $mask)) return true;
        }
        return false;
    }

    private function recByStatus(string $status, ?string $ip, bool $isCF, array $openPorts, int $cohosted): string {
        if ($status === 'pass' && $isCF) {
            return $this->recPass($ip, $isCF, $openPorts, $cohosted);
        }
        if ($status === 'pass') {
            return $this->recPassNoCF($ip, $openPorts, $cohosted);
        }
        if ($status === 'warning') {
            return $this->recWarning($ip, $openPorts, $cohosted);
        }
        return $this->recFail($ip, $openPorts, $cohosted);
    }

    private function recPass(string $ip, bool $isCF, array $openPorts, int $cohosted): string {
        return "✅ CONFIGURAȚIE EXCELENTĂ — Server cu protecție Cloudflare

Felicitări! Magazinul dvs. folosește Cloudflare ca strat de protecție, ceea ce reprezintă una dintre cele mai bune practici de securitate pentru magazine online. Iată de ce această configurație este benefică și cum o puteți menține:

DE CE CLOUDFLARE ESTE AVANTAJOS:
• IP-ul real al serverului este ascuns — atacatorii nu pot viza direct serverul dvs.
• Protecție DDoS inclusă — Cloudflare absoarbe atacurile de volum mare înainte să ajungă la server
• WAF (Web Application Firewall) — filtrează traficul malițios, injecțiile SQL, XSS și alte atacuri comune
• Rate limiting — limitează automat cererile excesive din aceeași sursă
• SSL/TLS gestionat — certificatele sunt gestionate automat

RECOMANDĂRI DE MENȚINERE:
1. Verificați că modul SSL în Cloudflare este setat pe \"Full (Strict)\" — nu pe \"Flexible\" care poate crea vulnerabilități
2. Activați \"Always Use HTTPS\" în setările Cloudflare
3. Activați \"HSTS\" în Cloudflare SSL/TLS → Edge Certificates
4. Configurați regulile de firewall Cloudflare pentru a bloca traficul suspect din țări cu risc ridicat
5. Activați \"Bot Fight Mode\" pentru a reduce traficul de boți
6. Verificați periodic secțiunea \"Security Events\" din Cloudflare pentru activitate suspectă
7. Nu expuneți niciodată IP-ul real al serverului (evitați subdomeniile DNS directe care arată IP-ul)

MONITORIZARE CONTINUĂ:
• Verificați lunar rapoartele de securitate din dashboardul Cloudflare
• Activați alertele email pentru amenințări detectate
• Considerați planul Pro sau Business pentru reguli WAF avansate dacă volumul de tranzacții o justifică";
    }

    private function recPassNoCF(string $ip, array $openPorts, int $cohosted): string {
        return "✅ CONFIGURAȚIE BUNĂ — Server izolat, porturi conforme

Serverul magazinului dvs. ({$ip}) are o configurație de securitate bună — nu sunt detectate porturi neautorizate deschise și co-hosting-ul este minim. Iată recomandări pentru menținerea și îmbunătățirea acestei configurații:

CE FUNCȚIONEAZĂ BINE:
• Suprafața de atac este minimă — sunt expuse doar porturile necesare
• Izolarea serverului este adecvată

RECOMANDĂRI DE ÎMBUNĂTĂȚIRE:
1. Implementați Cloudflare sau un CDN similar pentru protecție suplimentară — ascunde IP-ul real al serverului și adaugă un strat de protecție WAF
2. Configurați un firewall de nivel server (iptables/ufw) cu politica implicită DROP și whitelist explicit pentru porturile necesare
3. Dacă folosiți SSH (port 22), restricționați accesul doar la IP-urile dvs. statice și dezactivați autentificarea cu parolă în favoarea cheilor SSH
4. Implementați fail2ban pentru a bloca automat IP-urile care încearcă atacuri brute force
5. Monitorizați regulat porturile deschise cu comenzi de tip \"nmap localhost\" sau servicii externe de monitoring
6. Separați serverul de e-mail de serverul web dacă nu este deja separat
7. Documentați toate porturile deschise și motivul deschiderii lor

VERIFICARE PERIODICĂ:
• Rulați un scan nmap lunar: nmap -sV [IP]
• Abonați-vă la notificări de securitate ale furnizorului de hosting
• Verificați cu instrumente ca Shodan.io că serverul dvs. nu apare în indexări nedorite";
    }

    private function recWarning(string $ip, array $openPorts, int $cohosted): string {
        $portList = implode(', ', array_map(fn($p) => $p . ' (' . (self::PORT_NAMES[$p] ?? 'Unknown') . ')', $openPorts));
        return "⚠️ CONFIGURAȚIE CU RISC MEDIU — Servicii suplimentare expuse

Serverul magazinului dvs. ({$ip}) expune public porturi sau servicii care nu sunt strict necesare pentru funcționarea unui magazin online.
" . ($portList ? "Porturi cu risc detectate: {$portList}." : '') . "
" . ($cohosted > 3 ? "Co-hosting: {$cohosted} domenii pe același IP cresc riscul de contaminare încrucișată." : '') . "

DE CE CONTEAZĂ ACEASTĂ CONFIGURAȚIE:
• Fiecare port deschis reprezintă un potențial punct de intrare pentru atacatori
• Serviciile suplimentare (mail, panouri de control, servicii web alternative) pot conține vulnerabilități care pot fi exploatate pentru a accesa indirect magazinul dvs.
• Co-hosting-ul ridicat înseamnă că o compromitere a unui alt site poate afecta resursele serverului și reputația IP-ului

PAȘI DE REMEDIERE RECOMANDAȚI:
1. Inventariați TOATE porturile deschise și identificați care serviciu le folosește
2. Dezactivați sau opriți serviciile care nu sunt necesare pentru funcționarea magazinului
3. Pentru porturile necesare (ex: SSH), restricționați accesul prin firewall doar la IP-urile statice ale echipei tehnice
4. Configurați fail2ban pentru toate serviciile expuse
5. Dacă folosiți cPanel (porturile 2082/2083), restricționați accesul la panoul de control prin lista albă de IP-uri
6. Mutați serverul de e-mail pe un IP/server separat — recomandare GPeC explicită
7. Implementați un CDN/proxy (Cloudflare) pentru a ascunde IP-ul real

PENTRU PORTURI DE MAIL (25/465/587/993):
Dacă serverul de e-mail este pe același IP cu magazinul, există riscul că o blocare a IP-ului pentru spam să afecteze și accesul la magazin. Separarea serviciilor de e-mail pe un server/IP dedicat este o practică recomandată în industrie și explicit menționată în criteriile GPeC.

TIMELINE RECOMANDAT: Remedierea în maxim 2-4 săptămâni.";
    }

    private function recFail(?string $ip, array $openPorts, int $cohosted): string {
        $portList = implode(', ', array_map(fn($p) => $p . ' (' . (self::PORT_NAMES[$p] ?? 'Unknown') . ')', $openPorts));
        return "🔴 CONFIGURAȚIE CU RISC RIDICAT — Acțiune imediată necesară

Serverul magazinului dvs." . ($ip ? " ({$ip})" : "") . " prezintă vulnerabilități serioase de izolare care pot pune în pericol datele clienților și integritatea magazinului online.
" . ($portList ? "\nPorturi critice expuse public: {$portList}" : '') . "
" . ($cohosted > 10 ? "\nCo-hosting extrem: {$cohosted} domenii pe același IP — risc major de contaminare." : '') . "

RISCURI IDENTIFICATE:
• Porturile de baze de date sau servicii critice expuse public permit atacuri directe de autentificare
• Un atacator poate scana IP-ul și identifica versiunile software cu vulnerabilități cunoscute
• Co-hosting-ul excesiv înseamnă că orice site de pe server poate fi exploatat pentru a accesa resursele dvs.
• Conformitate PCI-DSS și GDPR poate fi afectată de această configurație

PAȘI DE REMEDIERE IMEDIATĂ (în 24-48 ore):
1. Configurați firewall-ul de server (iptables) cu politica DROP pentru tot, whitelist doar porturile 80 și 443
2. Dacă SSH (22) este necesar, mutați-l pe un port non-standard și restricționați la IP statice
3. Legați serviciile de baze de date la 127.0.0.1 (localhost only) — nu la 0.0.0.0
4. Dezactivați serviciile nefolosite (stop și disable din servicii sistem)
5. Instalați și configurați fail2ban cu limite stricte
6. Activați Cloudflare pentru a ascunde IP-ul real

CONFIGURAȚIE FIREWALL MINIMĂ RECOMANDATĂ:
- INPUT DROP (politica implicită)
- INPUT ACCEPT pentru portul 80 (HTTP) de la orice sursă
- INPUT ACCEPT pentru portul 443 (HTTPS) de la orice sursă
- INPUT ACCEPT pentru portul SSH doar de la IP-urile echipei tehnice
- INPUT ACCEPT pentru ESTABLISHED, RELATED (conexiuni deja stabilite)
- OUTPUT ACCEPT (de regulă)

TIMELINE: Remediere urgentă — în maxim 48 de ore.";
    }

    private function makeResult(string $status, int $stars, string $summary, array $details, string $comment, string $rec): array {
        return $this->result('#1', 'Server Dedicat', $status, $stars, $summary, $details, $comment, ['recommendation_ro' => $rec]);
    }
}
