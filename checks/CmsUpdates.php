<?php
require_once __DIR__ . '/BaseCheck.php';

class CmsUpdates extends BaseCheck {

    // Platforme SaaS românești și internaționale — dacă detectăm, scor special
    private const SAAS_SIGNATURES = [
        // Românești
        'gomag'        => ['Gomag', ['gomag.ro', 'gomag', 'cdn.gomag']],
        'contentspeed' => ['ContentSpeed', ['contentspeed', 'contentspeed.ro']],
        'merchantpro'  => ['MerchantPro', ['merchantpro', 'merchant-pro.ro']],
        'tazz'         => ['Tazz', ['tazz.ro']],
        'frisbo'       => ['Frisbo', ['frisbo']],
        // Internaționale
        'shopify'      => ['Shopify', ['cdn.shopify.com', 'shopify.com', 'myshopify.com', 'Shopify.theme']],
        'wix'          => ['Wix', ['static.wixstatic.com', 'wix.com', '_wix_']],
        'squarespace'  => ['Squarespace', ['squarespace.com', 'sqsp.net', 'squarespace-cdn']],
        'bigcommerce'  => ['BigCommerce', ['bigcommerce.com', 'bigcommerce', 'bcapp.dev']],
        'vtex'         => ['VTEX', ['vtexcommercestable', 'vtex.com', 'vtex.io', 'myvtex.com']],
        'salesforce'   => ['Salesforce Commerce Cloud', ['demandware', 'salesforce.com', 'force.com', 'commercecloud']],
        'webflow'      => ['Webflow', ['webflow.com', 'uploads-ssl.webflow.com']],
        'prestashop_saas' => ['PrestaShop SaaS', ['prestashop.com/en/saas']],
    ];

    private const EOL = [
        'WordPress' => ['3.','4.0','4.1','4.2','4.3','4.4','4.5','4.6','4.7','4.8','4.9','5.0','5.1','5.2','5.3','5.4','5.5','5.6','5.7','5.8','5.9','6.0','6.1','6.2','6.3','6.4'],
        'Joomla'    => ['1.','2.','3.','4.0','4.1','4.2','4.3'],
        'Drupal'    => ['6.','7.','8.','9.','10.0','10.1','10.2'],
        'Magento'   => ['1.','2.0','2.1','2.2','2.3','2.4.0','2.4.1','2.4.2','2.4.3','2.4.4','2.4.5'],
        'OpenCart'  => ['1.','2.','3.0'],
    ];

    public function run(): array {
        $base = "https://{$this->domain}";

        // Ia homepage o singură dată
        $home = $this->httpGet($base, 10);
        $html = $home['body'] ?? '';
        $hdrs = $home['headers'] ?? [];

        // Verifica SaaS mai întâi
        $saas = $this->detectSaaS($html, $hdrs);
        if ($saas) {
            return $this->result('#7', 'CMS si Extensii', 'saas', 3,
                "Platformă SaaS detectată: {$saas} — auditul direct nu este aplicabil.",
                [
                    "CMS/Platform: {$saas} (platformă SaaS/hosted)",
                    "Securitatea infrastructurii este gestionată de furnizorul platformei",
                    "Actualizările sunt aplicate automat de furnizor",
                    "Verificați că extensiile/aplicațiile instalate de dvs. în platformă sunt la zi",
                ],
                "Site-ul {$this->domain} rulează pe platforma SaaS {$saas}. Infrastructura și actualizările de securitate sunt gestionate de furnizor. Auditarea directă a platformei nu este aplicabilă — se recomandă verificarea setărilor de securitate din panoul platformei.",
                ['recommendation_ro' => $this->recSaaS($saas), 'saas' => $saas]
            );
        }

        // Detectare CMS self-hosted
        $cms = null; $version = null;

        if (!$cms) { $r = $this->detectWordPress($base, $html); if ($r) { $cms = 'WordPress'; $version = $r; } }
        if (!$cms) { $r = $this->detectJoomla($base, $html);    if ($r) { $cms = 'Joomla';    $version = $r; } }
        if (!$cms) { $r = $this->detectMagento($base, $html);   if ($r) { $cms = $r['name'];  $version = $r['version']; } }
        if (!$cms) { $r = $this->detectDrupal($base, $html, $hdrs); if ($r) { $cms = 'Drupal'; $version = $r; } }
        if (!$cms) { $r = $this->detectOpenCart($base, $html);  if ($r) { $cms = 'OpenCart'; $version = $r; } }
        if (!$cms) { $r = $this->detectPrestaShop($base, $html); if ($r) { $cms = 'PrestaShop'; $version = $r; } }

        if (!$cms) {
            $powered = $hdrs['x-powered-by'] ?? '';
            $server  = $hdrs['server'] ?? '';
            $details = ['CMS: nedetectat — custom sau informații ascunse (bună practică)'];
            if ($powered) $details[] = "X-Powered-By: {$powered}";
            if ($server)  $details[] = "Server: {$server}";
            $details[] = "Recomandare: verificați manual versiunea platformei și extensiilor";
            return $this->result('#7', 'CMS si Extensii', 'warning', 3,
                'CMS nedetectat automat — verificare manuală necesară.',
                $details,
                "CMS-ul magazinului {$this->domain} nu a putut fi identificat automat. Se recomandă verificarea manuală a versiunii și actualizărilor.",
                ['recommendation_ro' => $this->recUnknown()]
            );
        }

        $details = ["CMS detectat: {$cms}", "Versiune: " . ($version ?: 'nedetectată')];
        $eol     = $this->isEOL($cms, $version);

        // Verificări specifice WordPress
        if ($cms === 'WordPress') {
            $readme = $this->httpGet("{$base}/readme.html", 5);
            if ($readme['httpCode'] === 200 && str_contains($readme['body'], 'WordPress')) {
                $details[] = '⚠️ readme.html accesibil public — expune versiunea WordPress';
            }
            $wpconfig = $this->httpGet("{$base}/wp-config.php", 4);
            if ($wpconfig['httpCode'] === 200 && strlen($wpconfig['body'] ?? '') > 50) {
                $details[] = '🔴 wp-config.php accesibil public — PERICOL CRITIC';
            }
            $xmlrpc = $this->httpGet("{$base}/xmlrpc.php", 4);
            if ($xmlrpc['httpCode'] === 200) {
                $details[] = '⚠️ xmlrpc.php activ — vector de atac brute force';
            }
        }

        if ($eol) {
            return $this->result('#7', 'CMS si Extensii', 'fail', 1,
                "{$cms} versiunea {$version} este end-of-life — fără patch-uri de securitate.",
                $details,
                "Magazinul {$this->domain} folosește {$cms} versiunea {$version} care este end-of-life și nu mai primește actualizări de securitate. Risc major de exploatare.",
                ['recommendation_ro' => $this->recEOL($cms, $version)]
            );
        }
        if (!$version || $version === 'detected') {
            return $this->result('#7', 'CMS si Extensii', 'warning', 3,
                "{$cms} detectat — versiunea exactă nu a putut fi determinată.",
                $details,
                "Magazinul {$this->domain} folosește {$cms}. Versiunea exactă nu a putut fi determinată automat. Verificare manuală recomandată.",
                ['recommendation_ro' => $this->recUnknownVersion($cms)]
            );
        }
        return $this->result('#7', 'CMS si Extensii', 'pass', 5,
            "{$cms} versiunea {$version} — versiune detectată, verificați că e cea mai recentă.",
            $details,
            "Magazinul {$this->domain} folosește {$cms} versiunea {$version}. Verificați că această versiune este cea mai recentă disponibilă și că extensiile/plugin-urile sunt actualizate.",
            ['recommendation_ro' => $this->recCurrent($cms, $version)]
        );
    }

    private function detectSaaS(string $html, array $hdrs): ?string {
        $combined = strtolower($html . implode(' ', $hdrs));
        foreach (self::SAAS_SIGNATURES as $key => [$name, $sigs]) {
            foreach ($sigs as $sig) {
                if (str_contains($combined, strtolower($sig))) return $name;
            }
        }
        return null;
    }

    private function detectWordPress(string $base, string $html): ?string {
        // Verifică mai întâi dacă există wp-login (cel mai sigur indicator)
        $login = $this->httpGet("{$base}/wp-login.php", 6);
        if ($login['httpCode'] !== 200 || !str_contains($login['body'] ?? '', 'user_login')) {
            // Fallback: caută în HTML
            if (!str_contains($html, '/wp-content/') && !str_contains($html, '/wp-includes/')) return null;
        }

        // 1. Versiune din meta generator (homepage) — cea mai rapida si fiabila
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]*content=["\']WordPress\s*([\d.]+)/i', $html, $m)) return $m[1];

        // 2. Versiune din RSS feed: <generator>https://wordpress.org/?v=6.8.1</generator>
        $feed = $this->httpGet("{$base}/feed/", 6);
        if ($feed['httpCode'] === 200 && preg_match('#\?v=([\d.]+)#', $feed['body'], $m)) return $m[1];

        // 3. Versiune din wp-json root (nu /wp/v2/ care e namespace, nu WP version)
        $api = $this->httpGet("{$base}/wp-json/", 6);
        if ($api['httpCode'] === 200) {
            $d = json_decode($api['body'], true);
            // Cauta "version" explicit la nivelul root (nu namespace)
            if (!empty($d['version']) && preg_match('/^\d+\.\d+/', $d['version'])) return $d['version'];
            if (!empty($d['namespaces'])) return 'detected'; // WordPress confirmat, versiune necunoscuta
        }

        // 4. readme.html — restrictionat la formatul oficial: "Version X.Y" langa logo
        $rm = $this->httpGet("{$base}/readme.html", 5);
        if ($rm['httpCode'] === 200) {
            // Format WP 3.x+: <br /> Version X.Y  sau  Version X.Y.Z
            if (preg_match('/<br\s*\/?>\s*Version\s+([\d.]+)/i', $rm['body'], $m)) return $m[1];
            // Format alternativ: <h1...>...Version X.Y</h1>
            if (preg_match('/<h1[^>]*>.*?Version\s+([\d.]+).*?<\/h1>/is', $rm['body'], $m)) return $m[1];
        }

        return 'detected';
    }

    private function detectJoomla(string $base, string $html): ?string {
        $hasJoomla = str_contains(strtolower($html), 'joomla') || str_contains($html, '/media/com_');
        if (!$hasJoomla) return null;
        $manifest = $this->httpGet("{$base}/administrator/manifests/files/joomla.xml", 5);
        if ($manifest['httpCode'] === 200 && preg_match('/<version>([\d.]+)<\/version>/', $manifest['body'], $m)) return $m[1];
        if (preg_match('/<meta[^>]+content=["\']Joomla!\s*([\d.]+)/i', $html, $m)) return $m[1];
        return 'detected';
    }

    private function detectMagento(string $base, string $html): ?array {
        $skin = $this->httpGet("{$base}/skin/frontend/", 4);
        if ($skin['httpCode'] === 200) return ['name' => 'Magento 1.x', 'version' => 'detected'];
        if (str_contains($html, 'Magento') || str_contains($html, 'mage/') || str_contains($html, 'requirejs/require')) {
            $ver = $this->httpGet("{$base}/magento_version", 4);
            $v = 'detected';
            if ($ver['httpCode'] === 200 && preg_match('/([\d.]+)/', $ver['body'], $m)) $v = $m[1];
            return ['name' => 'Magento 2.x', 'version' => $v];
        }
        return null;
    }

    private function detectDrupal(string $base, string $html, array $hdrs): ?string {
        $gen = $hdrs['x-generator'] ?? '';
        if (stripos($gen, 'drupal') !== false) {
            preg_match('/drupal\s*([\d.]+)/i', $gen, $m);
            return $m[1] ?? 'detected';
        }
        if (preg_match('/<meta[^>]*content=["\']Drupal\s*([\d.]+)/i', $html, $m)) return $m[1];
        if (str_contains($html, 'sites/default/files') || str_contains($html, 'drupal.js')) return 'detected';
        return null;
    }

    private function detectOpenCart(string $base, string $html): ?string {
        if (!str_contains($html, 'route=common/home') && !str_contains($html, 'OpenCart') && !str_contains($html, 'catalog/view/theme')) return null;
        if (preg_match('/OpenCart\s*([\d.]+)/i', $html, $m)) return $m[1];
        return 'detected';
    }

    private function detectPrestaShop(string $base, string $html): ?string {
        if (!str_contains(strtolower($html), 'prestashop') && !str_contains($html, '/themes/') ) return null;
        $ch = $this->httpGet("{$base}/modules/", 4);
        if (!str_contains(strtolower($html), 'prestashop')) return null;
        if (preg_match('/PrestaShop\s*([\d.]+)/i', $html, $m)) return $m[1];
        return 'detected';
    }

    private function isEOL(string $cms, ?string $version): bool {
        if (!$version || $version === 'detected') return false;
        $cmsBare = explode(' ', $cms)[0]; // "Magento 1.x" → "Magento"
        $prefixes = self::EOL[$cms] ?? self::EOL[$cmsBare] ?? [];
        foreach ($prefixes as $p) { if (str_starts_with($version, $p)) return true; }
        return false;
    }

    private function recSaaS(string $saas): string {
        return "ℹ️ PLATFORMĂ SAAS — AUDIT INDIRECT

Site-ul dvs. este construit pe platforma {$saas}, o soluție SaaS (Software as a Service) unde infrastructura tehnică și securitatea de bază sunt gestionate de furnizorul platformei.

CE ÎNSEAMNĂ ASTA PENTRU SECURITATE:
• Actualizările de sistem operare, server web și core-ul platformei sunt aplicate automat de {$saas}
• Furnizorul asigură protecție de bază împotriva vulnerabilităților comune
• Responsabilitatea dvs. este limitată la configurațiile din panoul platformei și la conținutul adăugat

CE TREBUIE SĂ VERIFICAȚI ÎN PANOUL {$saas}:
1. Toate aplicațiile/extensiile/plugin-urile instalate din marketplace-ul platformei sunt la ultima versiune
2. Accesul la panoul de administrare este securizat cu parolă puternică și autentificare în doi pași (2FA)
3. API-urile și integrările de terțe părți (plată, logistică, marketing) sunt active doar cele necesare
4. Certificatul SSL este valid și activ (de obicei gestionat automat de platformă)
5. Datele de acces ale echipei sunt individualizate — nu partajați o singură parolă

RECOMANDĂRI SPECIFICE PENTRU SECURITATE:
• Activați notificările de securitate din platforma {$saas}
• Verificați periodic jurnalele de acces dacă platforma le pune la dispoziție
• Asigurați-vă că contractul cu {$saas} include clauze de securitate a datelor (important pentru GDPR)
• Păstrați o copie de siguranță a datelor (produse, comenzi, clienți) independent de platformă
• Contactați suportul {$saas} pentru raportul de securitate și certificările de conformitate (ISO 27001, SOC 2 etc.)

NOTĂ: Un audit complet al infrastructurii tehnice poate fi realizat direct cu furnizorul {$saas}, nu independent.";
    }

    private function recEOL(string $cms, ?string $version): string {
        return "🔴 CMS END-OF-LIFE — ACTUALIZARE URGENTĂ NECESARĂ

{$cms} versiunea {$version} nu mai primește actualizări de securitate de la producător. Aceasta este o vulnerabilitate critică pentru orice magazin online.

RISCURI IMEDIATE:
• Vulnerabilitățile de securitate descoperite NU vor fi patchuite de producătorul {$cms}
• Există exploituri publice cunoscute pentru versiunile vechi — atacatorii le folosesc activ
• Risc de compromitere completă a site-ului: injecție de cod malițios, furt de date clienți, redirect spre site-uri de phishing
• Procesatorii de plăți pot refuza integrarea dacă platforma nu e actualizată (PCI-DSS)
• GDPR: utilizarea unui software fără suport de securitate poate fi considerată neglijență în protecția datelor

PAȘI DE ACTUALIZARE (în ordinea priorităților):

1. BACKUP COMPLET înainte de orice: fișiere + baza de date
2. Citiți ghidul oficial de actualizare de pe site-ul {$cms}
3. Testați actualizarea ÎNTÂI pe un mediu de staging/test
4. Actualizați PHP la versiunea minimă necesară pentru noua versiune {$cms}
5. Actualizați toate extensiile/plugin-urile la versiuni compatibile cu noua versiune
6. Rulați actualizarea în producție după validarea pe staging
7. Testați funcționalitatea completă după actualizare (checkout, plăți, cont client)

DACĂ ACTUALIZAREA IMEDIATĂ NU ESTE POSIBILĂ:
• Instalați un WAF (Web Application Firewall) ca protecție temporară — ex: Cloudflare WAF, Wordfence (WP)
• Dezactivați toate extensiile nefolosite
• Restricționați accesul la pagina de administrare la IP-urile echipei tehnice
• Monitorizați activ jurnalele de acces pentru activitate suspectă

TIMELINE: Actualizare urgentă — maxim 2 săptămâni pentru start, 4 săptămâni pentru finalizare.";
    }

    private function recUnknown(): string {
        return "ℹ️ CMS NEDETECTAT — VERIFICARE MANUALĂ NECESARĂ

CMS-ul magazinului dvs. nu a putut fi identificat automat. Aceasta poate fi o situație bună (platformă custom sau informații CMS ascunse) sau poate necesita verificare.

CE TREBUIE VERIFICAT MANUAL:
1. Identificați platforma folosită — WordPress, Magento, OpenCart, PrestaShop, soluție custom sau altele
2. Verificați versiunea platformei și asigurați-vă că nu este end-of-life
3. Verificați că toate extensiile/modulele instalate sunt la ultima versiune
4. Dacă este o soluție custom, asigurați-vă că echipa de dezvoltare aplică actualizări de securitate regulat

BUNE PRACTICI GENERALE PENTRU ORICE PLATFORMĂ:
• Mențineti un inventar al tuturor componentelor software cu versiunile lor
• Abonați-vă la newsletter-urile de securitate ale platformei folosite
• Programați actualizări de securitate trimestrial minimum
• Testați actualizările pe mediu de staging înainte de producție
• Păstrați backup-uri automate zilnice

RESURSE PENTRU VERIFICARE:
• WhatCMS.org — detectare CMS online
• Wappalyzer browser extension — analiză stack tehnologic
• BuiltWith.com — identificare tehnologii";
    }

    private function recUnknownVersion(string $cms): string {
        return "⚠️ {$cms} DETECTAT — VERSIUNE NEIDENTIFICATĂ

{$cms} a fost detectat pe site-ul dvs. dar versiunea exactă nu a putut fi determinată automat. Aceasta poate însemna că informațiile de versiune sunt ascunse (bună practică de securitate) sau că accesul la fișierele relevante este restricționat.

ACȚIUNI RECOMANDATE:
1. Verificați manual versiunea {$cms} din panoul de administrare
2. Comparați versiunea detectată cu ultima versiune stabilă disponibilă pe site-ul oficial
3. Aplicați toate actualizările de securitate disponibile
4. Verificați că plugin-urile/extensiile instalate sunt și ele actualizate

PENTRU {$cms} SPECIFIC:
" . match($cms) {
            'WordPress' => "• Accesați: Panoul WP Admin → Dashboard → Updates\n• Verificați și actualizați: Core, Themes, Plugins\n• Dezactivați și ștergeți plugin-urile nefolosite\n• Recomandăm utilizarea Wordfence Security pentru monitorizare",
            'Joomla'    => "• Accesați: Administrator → System → Update\n• Verificați extensiile: Administrator → Extensions → Manage\n• Activați Joomla! Security Strike Team notifications",
            'Magento'   => "• Verificați versiunea: Admin → System → Web Setup Wizard\n• Aplicați Security Patches disponibile pe magento.com/security\n• Considerați Magento Security Scan Tool (gratuit)",
            'OpenCart'  => "• Verificați: Admin → Dashboard → versiunea din footer\n• Actualizați din: opencart.com/index.php?route=cms/download",
            default     => "• Consultați documentația oficială {$cms} pentru instrucțiuni de actualizare",
        };
    }

    private function recCurrent(string $cms, string $version): string {
        return "✅ {$cms} DETECTAT — MENȚINERE ȘI SECURIZARE

{$cms} versiunea {$version} a fost identificat. Iată recomandările complete pentru securizarea și menținerea platformei:

VERIFICĂRI IMEDIATE:
1. Confirmați că versiunea {$version} este cea mai recentă stabilă disponibilă pe site-ul oficial {$cms}
2. Verificați că TOATE extensiile/plugin-urile instalate sunt la ultima versiune
3. Dezactivați și ștergeți extensiile/plugin-urile nefolosite — fiecare reprezintă o suprafață de atac
4. Verificați că tema/template-ul este actualizat și provine dintr-o sursă de încredere

SECURIZARE SPECIFICĂ {$cms}:
" . match(strtolower(explode(' ', $cms)[0])) {
            'wordpress' => "• Instalați un plugin de securitate: Wordfence, iThemes Security sau Sucuri Security\n• Dezactivați xmlrpc.php dacă nu este necesar (vector comun de atac)\n• Schimbați URL-ul paginii de administrare de la /wp-admin/ la ceva custom\n• Activați autentificarea în doi pași pentru toți utilizatorii admin\n• Restricționați editarea fișierelor din Admin: define('DISALLOW_FILE_EDIT', true) în wp-config.php\n• Utilizați parole puternice și unice pentru fiecare cont WordPress",
            'magento'   => "• Rulați Magento Security Scan Tool: account.magento.com/scanner\n• Aplicați patch-urile de securitate disponibile pe magento.com/security\n• Dezactivați Magento Admin la URL standard /admin — schimbați la un path custom\n• Activați Two-Factor Authentication pentru admin\n• Verificați că nu există extensii compromise (verificare integritate fișiere)",
            'joomla'    => "• Activați Joomla! Two-Factor Authentication\n• Verificați și actualizați toate extensiile din Administrator → Extensions\n• Folosiți Akeeba Admin Tools pentru securizare avansată\n• Schimbați URL-ul de admin de la /administrator/ la ceva custom",
            'prestashop' => "• Verificați modulele din Back Office → Modules → Module Manager\n• Dezactivați accesul la /admin sau schimbați directorul de admin\n• Activați 2FA pentru conturile de administrare\n• Verificați că fișierele de configurare nu sunt accesibile public",
            default     => "• Urmăriți anunțurile de securitate ale platformei și aplicați patch-urile prompt\n• Limitați accesul la panoul de administrare la IP-uri cunoscute\n• Activați autentificarea în doi pași",
        } . "

MONITORIZARE CONTINUĂ:
• Configurați alerte de actualizare automată sau notificări pentru versiuni noi
• Verificați lunar: BuiltWith.com și Wappalyzer pentru a vedea ce versiune detectează extern
• Abonați-vă la newsletter-ul de securitate al producătorului platformei";
    }
}
