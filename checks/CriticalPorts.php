<?php
require_once __DIR__ . '/BaseCheck.php';

class CriticalPorts extends BaseCheck {

    private const PORTS = [
        ['port' => 3306,  'name' => 'MySQL',          'sev' => 'critical'],
        ['port' => 5432,  'name' => 'PostgreSQL',      'sev' => 'critical'],
        ['port' => 1433,  'name' => 'MSSQL',           'sev' => 'critical'],
        ['port' => 27017, 'name' => 'MongoDB',         'sev' => 'critical'],
        ['port' => 6379,  'name' => 'Redis',           'sev' => 'critical'],
        ['port' => 9200,  'name' => 'Elasticsearch',   'sev' => 'critical'],
        ['port' => 5984,  'name' => 'CouchDB',         'sev' => 'critical'],
        ['port' => 3389,  'name' => 'RDP',             'sev' => 'critical'],
        ['port' => 5900,  'name' => 'VNC',             'sev' => 'critical'],
        ['port' => 22,    'name' => 'SSH',             'sev' => 'medium'],
        ['port' => 21,    'name' => 'FTP',             'sev' => 'medium'],
    ];

    public function run(): array {
        $ip = $this->resolveIP($this->domain);
        if (!$ip) {
            return $this->result('#6', 'Acces Servicii Critice', 'fail', 1,
                'Nu s-a putut rezolva IP-ul.',
                ['DNS resolution esuata — verificare manuala necesara'],
                "Nu s-a putut verifica accesul la serviciile critice ale serverului {$this->domain}.",
                ['recommendation_ro' => $this->recNoIP()]
            );
        }

        $details = ["IP verificat: {$ip}"];
        $openCritical = [];
        $openMedium   = [];

        foreach (self::PORTS as $p) {
            $open = $this->testPort($ip, $p['port'], 3);
            if ($open) {
                if ($p['sev'] === 'critical') {
                    $openCritical[] = "{$p['name']} ({$p['port']})";
                    $details[] = "🔴 Port {$p['port']} ({$p['name']}): DESCHIS — accesibil public PERICULOS";
                } else {
                    $openMedium[] = "{$p['name']} ({$p['port']})";
                    $details[] = "⚠️ Port {$p['port']} ({$p['name']}): deschis — risc mediu";
                }
            } else {
                $details[] = "✅ Port {$p['port']} ({$p['name']}): inchis/filtrat (corect)";
            }
        }

        if (!empty($openCritical)) {
            $names = implode(', ', $openCritical);
            return $this->result('#6', 'Acces Servicii Critice', 'fail', 1,
                "Servicii critice EXPUSE public: {$names}.",
                $details,
                "Serverul {$this->domain} ({$ip}) expune public servicii critice: {$names}. " .
                "Aceasta reprezinta un risc major de securitate — atacatorii pot incerca autentificari directe. " .
                "Restricionati accesul imediat prin firewall, permitand doar IP-uri de incredere.",
                ['ip' => $ip, 'open_critical' => $openCritical, 'open_medium' => $openMedium,
                 'recommendation_ro' => $this->recCritical($openCritical, $ip)]
            );
        }
        if (!empty($openMedium)) {
            $names = implode(', ', $openMedium);
            return $this->result('#6', 'Acces Servicii Critice', 'warning', 3,
                "Servicii cu risc mediu accesibile din exterior: {$names}.",
                $details,
                "Pe serverul {$this->domain} ({$ip}) sunt accesibile public: {$names}. " .
                "GPeC recomanda restrictionarea accesului SSH/FTP prin firewall si implementarea fail2ban.",
                ['ip' => $ip, 'open_critical' => $openCritical, 'open_medium' => $openMedium,
                 'recommendation_ro' => $this->recMedium($openMedium, $ip)]
            );
        }
        return $this->result('#6', 'Acces Servicii Critice', 'pass', 5,
            'Niciun serviciu critic accesibil din exterior — firewall corect configurat.',
            $details,
            "Serverul {$this->domain} ({$ip}) are corect restrictionat accesul la serviciile critice. Niciun port de baze de date, remote desktop sau serviciu intern nu este accesibil din internet. Respecta bunele practici GPeC.",
            ['ip' => $ip, 'recommendation_ro' => $this->recPass()]
        );
    }

    private function recNoIP(): string {
        return "Nu s-a putut determina IP-ul serverului pentru verificarea porturilor. Verificati manual cu nmap sau un port scanner online (ex: pentest-tools.com) ca porturile 3306, 5432, 27017, 6379, 3389, 5900 sunt filtrate/inchise din internet.";
    }

    private function recCritical(array $open, string $ip): string {
        $portList = implode(', ', $open);
        return <<<REC
SERVICII CRITICE EXPUSE PUBLIC — ACTIUNI URGENTE NECESARE

Porturile deschise detectate: {$portList} pe IP {$ip}

Aceasta configuratie permite oricarui atacator de pe internet sa:
- Incerce autentificari brute-force direct pe baza de date
- Exploateze vulnerabilitati cunoscute ale serviciilor respective
- Extragere sau modificare date fara autentificare (MongoDB, Redis, Elasticsearch pot fi fara parola by default)

1. RESTRICTIONAREA PRIN FIREWALL (OBLIGATORIU — in urmatoarele ore)
Pe server Linux (iptables/firewalld):
  iptables -A INPUT -p tcp --dport 3306 -s IP_BIROU_TU -j ACCEPT
  iptables -A INPUT -p tcp --dport 3306 -j DROP
  (inlocuiti 3306 cu fiecare port deschis)
cPanel/WHM: Security Center → Host Access Control → adaugati reguli de deny pentru porturile respective
Cloudflare: nu protejeaza porturile non-HTTP — necesita configurare direct pe server.

2. SCHIMBAREA PORTURILOR DEFAULT
Mutati serviciile pe porturi nestandard pentru a reduce scanarile automate:
- MySQL: schimbati din 3306 in ex. 13306 (in /etc/mysql/my.cnf: port=13306)
- SSH: schimbati din 22 in ex. 2222 (in /etc/ssh/sshd_config: Port 2222)
Atentie: aceasta NU inlocuieste firewall-ul, ci e un nivel suplimentar de obscuritate.

3. AUTENTIFICARE PUTERNICA
Daca serviciile TREBUIE sa fie accesibile din exterior (ex: acces remote la DB pentru echipa de dev):
- Implementati un VPN (OpenVPN, WireGuard) si accesati DB-ul doar prin VPN
- Activati autentificarea cu cheie SSH (dezactivati parola SSH: PasswordAuthentication no)
- Folositi parole complexe, unice (minim 20 caractere, alfanumerice + simboluri)
- Activati 2FA pentru SSH (Google Authenticator + PAM)

4. AUDITAREA ACCESURILOR EXISTENTE
Verificati imediat logurile pentru accesuri neautorizate:
- MySQL: SELECT user, host, time FROM information_schema.processlist;
- Redis: CONFIG GET requirepass (daca e gol, oricine are acces fara parola!)
- MongoDB: db.getUsers() — verificati ca exista autentificare activata
- Elasticsearch: GET _cat/nodes?v — verificati setarile de securitate

5. CONFIGURARI SPECIFICE PENTRU SECURIZAREA SERVICIILOR
Redis (fara parola = risc maxim):
  requirepass PAROLA_COMPLEXA_REDIS
  bind 127.0.0.1
  protected-mode yes
MongoDB:
  security: authorization: enabled
  net: bindIp: 127.0.0.1
Elasticsearch:
  xpack.security.enabled: true
  network.host: 127.0.0.1

PRIORITATE: CRITICA — Actionati in maximum 2-4 ore.
REC;
    }

    private function recMedium(array $open, string $ip): string {
        $portList = implode(', ', $open);
        return <<<REC
SERVICII SSH/FTP ACCESIBILE PUBLIC — RECOMANDARI DE SECURIZARE

Porturile deschise: {$portList} pe {$ip}

SSH si FTP sunt necesare pentru managementul serverului, dar expunerea lor publica creste suprafata de atac. Zilnic, serverele expuse public primesc mii de tentative de autentificare automate (brute force).

1. PROTECTIA SSH (Port 22)
a) Schimbati portul SSH din 22 in unul nestandard (ex. 2222, 4822):
   In /etc/ssh/sshd_config: Port 2222
   Actualizati firewall-ul sa permita noul port.

b) Dezactivati autentificarea cu parola, folositi doar chei SSH:
   PasswordAuthentication no
   PubkeyAuthentication yes
   Generati cheie: ssh-keygen -t ed25519 -C "admin@domeniu.ro"
   Copiati cheia: ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

c) Instalati fail2ban pentru blocarea automata a IP-urilor cu tentative repetate:
   apt install fail2ban
   Configurati /etc/fail2ban/jail.local: [sshd] maxretry=3 bantime=3600

d) Implementati allowlist IP in SSH:
   In sshd_config: AllowUsers admin@IP_VPN_TU admin@IP_BIROU_TU

2. PROTECTIA FTP (Port 21)
a) Inlocuiti FTP cu SFTP (SSH File Transfer Protocol) — FTP nu cripteaza datele/credentialele
b) Daca FTP este necesar, folositi FTPS (FTP Secure cu TLS)
c) Restrangeti accesul FTP la IP-uri specifice (cPanel: FTP → FTP Session Control)
d) Dezactivati FTP anonymous si limitati utilizatorii la directorul lor (chroot)

3. CONSIDERATI UN VPN
Cea mai sigura solutie: dezactivati accesul SSH/FTP din internet public si accesati serverul exclusiv prin VPN intern (WireGuard sau OpenVPN). Porturile SSH/FTP raman deschise doar pe interfata VPN.

4. MONITORIZARE TENTATIVE
Verificati logurile SSH periodic:
  grep "Failed password" /var/log/auth.log | tail -50
  grep "Accepted" /var/log/auth.log | tail -20
Configurati alerte email pentru autentificari reusie din IP-uri noi.
REC;
    }

    private function recPass(): string {
        return <<<REC
CONFIGURATIE FIREWALL EXCELENTA — RECOMANDARI PENTRU MENTINERE

1. AUDITARE PERIODICA
Rulati lunar o scanare de porturi din exterior pentru a verifica ca firewall-ul functioneaza corect:
- nmap -sS -O domeniu.ro (din alta retea)
- Shodan.io — cautati IP-ul serverului pentru a vedea ce indexeaza
- Pentest-tools.com — port scanner online gratuit

2. DOCUMENTAREA REGULILOR FIREWALL
Mentineti un document actualizat cu toate regulile firewall, inclusiv:
- Ce porturi sunt deschise, de ce, si de la ce IP-uri
- Data adaugarii fiecarei reguli
- Persoana responsabila
Aceasta faciliteaza auditul si identificarea regulilor redundante.

3. FAIL2BAN SI RATE LIMITING
Chiar daca porturile sunt filtrate, implementati fail2ban pentru serviciile expuse (SSH, HTTP, email):
- Blocati automat IP-urile dupa 3-5 tentative esuate
- Configurati ban time de minim 1 ora, recidivistii — 24-48 ore

4. NETWORK SEGMENTATION
Pe servere dedicate, izolati serviciile intr-o retea privata:
- Baza de date pe o retea interna, accesibila doar de la serverul web (private networking)
- Backupurile pe o retea separata, cu acces restricted
Furnizori cloud (Hetzner, OVH, Linode) ofera private networking gratuit.

5. VERIFICAREA REGULATA A CVE-urilor
Abonati-va la notificari de securitate pentru software-ul de pe server (MySQL, Nginx, OpenSSH) si aplicati patch-urile in maximum 72 ore de la publicare.
REC;
    }
}
