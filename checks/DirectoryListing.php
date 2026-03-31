<?php
require_once __DIR__ . '/BaseCheck.php';

class DirectoryListing extends BaseCheck {

    private const DIRS = [
        '/images/', '/uploads/', '/backup/', '/backups/', '/tmp/', '/temp/',
        '/logs/', '/log/', '/css/', '/js/', '/assets/', '/media/', '/files/',
        '/attachments/', '/documents/', '/data/', '/export/', '/cache/',
        '/wp-content/uploads/', '/wp-content/backup/', '/storage/',
        '/app/logs/', '/var/', '/sql/',
    ];

    private const LISTING_SIGNS = [
        'Index of /', '<title>Index of', 'Directory listing',
        'Parent Directory', '[DIR]', 'Last modified',
    ];

    public function run(): array {
        $base    = "https://{$this->domain}";
        $exposed = [];
        $details = [];

        foreach (self::DIRS as $dir) {
            $res = $this->httpGet("{$base}{$dir}", 6, false);
            if ($res['httpCode'] === 200 && $this->hasListing($res['body'])) {
                $exposed[] = $dir;
                $details[] = "🔴 LISTARE ACTIVA: {$base}{$dir}";
            }
        }

        $total = count(self::DIRS);
        $safe  = $total - count($exposed);
        $details[] = "Directoare verificate: {$total} — {$safe} protejate, " . count($exposed) . " cu listare publica";

        if (count($exposed) >= 3) {
            return $this->result('#9', 'Directory Listing', 'fail', 1,
                count($exposed) . ' directoare cu listare publica activa.',
                $details,
                "Pe site-ul {$this->domain} au fost identificate " . count($exposed) . " directoare cu listare publica activa: " .
                implode(', ', $exposed) . ". Aceasta expune structura fisierelor si permite download-ul de fisiere sensibile. " .
                "Se impune dezactivarea imediata prin configuratia serverului web.",
                ['exposed' => $exposed, 'recommendation_ro' => $this->recFail($exposed)]
            );
        }
        if (!empty($exposed)) {
            return $this->result('#9', 'Directory Listing', 'warning', 2,
                count($exposed) . ' director(e) cu listare activa: ' . implode(', ', $exposed) . '.',
                $details,
                "Pe site-ul {$this->domain} a fost detectata listare publica activa pentru: " . implode(', ', $exposed) . ". " .
                "Se recomanda dezactivarea prin configuratia serverului (Options -Indexes).",
                ['exposed' => $exposed, 'recommendation_ro' => $this->recWarning($exposed)]
            );
        }
        return $this->result('#9', 'Directory Listing', 'pass', 5,
            "Nicio listare publica detectata — {$total} directoare verificate.",
            $details,
            "Site-ul {$this->domain} nu are listare publica de directoare activa. Toate cele {$total} directoare verificate returneaza acces restrictionat sau 403/404.",
            ['recommendation_ro' => $this->recPass($total)]
        );
    }

    private function hasListing(string $body): bool {
        foreach (self::LISTING_SIGNS as $sign) {
            if (str_contains($body, $sign)) return true;
        }
        return false;
    }

    private function recFail(array $exposed): string {
        $list = implode(', ', $exposed);
        return <<<REC
LISTARE DIRECTOARE ACTIVA — RISC RIDICAT DE EXPUNERE DATE

Directoare expuse: {$list}

Directory listing permite oricui sa navigheze si sa descarce fisierele din aceste directoare, similar cu un File Manager public. Datele expuse frecvent includ: fisiere de backup (.sql, .zip, .tar.gz), loguri cu informatii sensibile, documente interne, fisiere de configurare, imagini si documente uploadate de utilizatori.

1. DEZACTIVAREA DIRECTORY LISTING IN APACHE (.htaccess)
Adaugati in fisierul .htaccess din radacina site-ului (sau in fiecare director problematic):
  Options -Indexes
Sau pentru a bloca listarea in toate directoarele copil:
  <IfModule mod_autoindex.c>
    Options -Indexes
  </IfModule>
Daca .htaccess nu functioneaza, adaugati in httpd.conf sau in blocul VirtualHost:
  <Directory /var/www/html>
    Options -Indexes
  </Directory>

2. DEZACTIVAREA IN NGINX
In fisierul de configurare nginx.conf sau site-ul specific:
  server {
    location / {
      autoindex off;
    }
  }
Restartati Nginx dupa modificare: nginx -s reload

3. DEZACTIVAREA IN cPANEL (Hosting Shared)
- Mergeti in cPanel → File Manager → selectati directorul problematic → Settings → Directory Privacy
- Sau: cPanel → Indexes → setati pe "No Indexing" pentru directoarele dorite
Alternativ, creati un fisier index.html gol in fiecare director problematic (solutie de urgenta).

4. PROTEJAREA DIRECTOARELOR SENSIBILE SUPLIMENTAR
Directoare precum /backup, /sql, /export, /logs nu ar trebui sa fie accesibile via web deloc.
Blocati accesul complet:
  <DirectoryMatch "/(backup|sql|logs|export|tmp|temp)/">
    Require all denied
  </DirectoryMatch>
Sau in .htaccess adaugat in directorul respectiv:
  Deny from all

5. VERIFICAREA FISIERELOR EXPUSE
Auditati manual directoarele expuse si stergeti sau mutati fisierele sensibile:
- Fisiere .sql (dump-uri baze de date) — contin toate datele clientilor
- Fisiere .zip, .tar.gz (backup-uri) — contin intreaga structura site
- Fisiere .log — pot contine parole, tokens, date personale
- Fisiere .env, .git, wp-config.php — configuratii critice

6. PROTECTIA DIRECTOARELOR DE UPLOAD
Directoarele /uploads/ si /images/ sunt frecvent expuse. Adaugati in directorul uploads:
  Options -ExecCGI -Indexes
  <FilesMatch "\.(php|php3|php5|phtml|pl|py|cgi)$">
    Deny from all
  </FilesMatch>
Aceasta previne si executarea fisierelor PHP uploadate de atacatori.

PRIORITATE: INALTA — Remediati in urmatoarele 24-48 ore.
REC;
    }

    private function recWarning(array $exposed): string {
        $list = implode(', ', $exposed);
        return <<<REC
DIRECTOARE CU LISTARE ACTIVA DETECTATE: {$list}

Dezactivati directory listing imediat. In .htaccess (Apache):
  Options -Indexes

Sau in Nginx:
  autoindex off;

Dupa dezactivare, verificati manual daca in directoarele respective exista fisiere sensibile (backup-uri, fisiere de configurare, loguri) si stergeti-le sau mutati-le in afara radacinii web (/public_html).

Daca directoarele respective sunt necesare operational (ex. /uploads/ pentru imagini produse), asigurati-va ca:
1. Nu contine fisiere PHP executabile — adaugati: deny from all in .htaccess pentru extensii PHP
2. Fisierele uploadate sunt validate si redenumite (fara extensii executabile)
3. Accesul direct la directoare este blocat (403), chiar daca fisierele individuale raman accesibile

Verificati dupa implementare accesand directoarele din browser: ar trebui sa returneze 403 Forbidden.
REC;
    }

    private function recPass(int $total): string {
        return <<<REC
DIRECTORY LISTING DEZACTIVAT — BUNA PRACTICA IMPLEMENTATA

Site-ul protejeaza corect {$total} directoare verificate. Pentru a mentine acest nivel de securitate:

1. VERIFICARE DUPA FIECARE UPDATE/DEPLOY
Asigurati-va ca optiunea -Indexes (Apache) sau autoindex off (Nginx) nu este suprascris de framework-uri sau scripturi de instalare. Unele CMS-uri sau plugin-uri pot crea fisiere .htaccess care suprascriu setarile de securitate.

2. PROTECTIA FISIERELOR SENSIBILE IN PLUS FATA DE DIRECTOARE
Chiar daca listarea e dezactivata, fisierele pot fi accesate direct daca cineva cunoaste calea:
- Blocati accesul la .env: <Files ".env"> Deny from all </Files>
- Blocati wp-config.php (WordPress): <Files wp-config.php> order allow,deny deny from all </Files>
- Blocati fisierele de backup: <FilesMatch "\.(sql|bak|backup|old|zip|tar\.gz)$"> Deny from all </FilesMatch>

3. SCANARE PERIODICA
Rulati lunar un scan de fisiere expuse cu:
- Nikto: nikto -h domeniu.ro
- OWASP ZAP (gratuit)
- Sau manual: verificati daca accesul la /backup/, /sql/, /logs/ returneaza 403

4. POLITICA DE UPLOAD STRICTA
Directoarele de upload trebuie protejate suplimentar:
- Validarea tipului MIME la upload (nu doar extensia)
- Redenumirea aleatorie a fisierelor uploadate
- Stocarea fisierelor sensibile in afara web root (neaccesibile direct)
- Servirea prin PHP cu verificarea autentificarii
REC;
    }
}
