<?php
require_once __DIR__ . '/BaseCheck.php';

class SpamReputation extends BaseCheck {

    public function run(): array {
        $ip      = $this->resolveIP($this->domain);
        $details = [];
        $listed  = [];

        if ($ip) {
            $details[] = "IP verificat: {$ip}";
            $rev = implode('.', array_reverse(explode('.', $ip)));

            $ipLists = [
                "{$rev}.zen.spamhaus.org"         => 'Spamhaus ZEN',
                "{$rev}.bl.spamcop.net"            => 'SpamCop',
                "{$rev}.b.barracudacentral.org"    => 'Barracuda',
                "{$rev}.dnsbl.sorbs.net"           => 'SORBS',
                "{$rev}.cbl.abuseat.org"           => 'CBL',
            ];

            foreach ($ipLists as $host => $name) {
                $inList = !empty(@dns_get_record($host, DNS_A));
                if ($inList) {
                    $listed[] = $name;
                    $details[] = "{$name}: LISTAT — IP {$ip} in blacklist";
                } else {
                    $details[] = "{$name}: curat";
                }
            }
        } else {
            $details[] = 'IP: nerezolvat — verificare DNSBL imposibila';
        }

        // Domain blacklist
        $domainLists = [
            "{$this->domain}.dbl.spamhaus.org" => 'Spamhaus DBL',
            "{$this->domain}.multi.surbl.org"  => 'SURBL',
        ];
        foreach ($domainLists as $host => $name) {
            $inList = !empty(@dns_get_record($host, DNS_A));
            if ($inList) {
                $listed[] = "{$name} (domeniu)";
                $details[] = "{$name}: DOMENIU LISTAT";
            } else {
                $details[] = "{$name}: domeniu curat";
            }
        }

        $cnt = count($listed);

        if ($cnt >= 2) {
            $listStr = implode(', ', $listed);
            return $this->result('#3', 'Reputatie Spam', 'fail', 1,
                "Prezent in {$cnt} liste de spam: {$listStr}.",
                $details,
                "Adresa IP ({$ip}) sau domeniul este raportat pentru spam in: {$listStr}. " .
                "Aceasta afecteaza livrabilitatea email-urilor si credibilitatea magazinului.",
                ['ip' => $ip, 'listed' => $listed, 'recommendation_ro' => $this->recFail($listed, $ip)]
            );
        }
        if ($cnt === 1) {
            return $this->result('#3', 'Reputatie Spam', 'warning', 3,
                "Detectat in 1 lista de spam: {$listed[0]}.",
                $details,
                "Domeniul/IP-ul magazinului apare in lista {$listed[0]}. " .
                "Se recomanda investigarea cauzei si initierea procesului de delist.",
                ['ip' => $ip, 'listed' => $listed, 'recommendation_ro' => $this->recWarning($listed[0], $ip)]
            );
        }
        return $this->result('#3', 'Reputatie Spam', 'pass', 5,
            'Nicio prezenta in liste de spam/blacklist verificate.',
            $details,
            "IP-ul " . ($ip ?: 'N/A') . " si domeniul {$this->domain} nu sunt prezente in nicio lista de blacklist (Spamhaus ZEN, SpamCop, Barracuda, SORBS, CBL). Reputatia de email este curata.",
            ['ip' => $ip, 'recommendation_ro' => $this->recPass()]
        );
    }

    private function recFail(array $listed, ?string $ip): string {
        $listStr = implode(', ', $listed);
        return <<<REC
IP/DOMENIU IN BLACKLIST SPAM — ACTIUNI URGENTE

Liste detectate: {$listStr} (IP: {$ip})

1. IDENTIFICAREA CAUZEI BLACKLISTARII
Serverul trimite spam (malware pe server, cont email compromis, script de contact abuzat) sau IP-ul a fost folosit anterior pentru spam.
Verificati logurile de email: /var/log/maillog sau cPanel → Email → Email Deliverability.

2. PROCESUL DE DELIST
Spamhaus: spamhaus.org/lookup → tastati IP-ul → delist request
SpamCop: delist automat dupa 24-48h daca spam-ul a incetat
Barracuda: barracudacentral.org/rbl/removal-request
SORBS: sorbs.net → My SORBS → delist request
MxToolbox (verificare completa 100+ liste): mxtoolbox.com/blacklists.aspx

3. SECURIZAREA SERVERULUI
- Schimbati parola cPanel si a tuturor conturilor email
- Dezactivati conturile email compromise
- Limitati rata de trimitere email in cPanel
- Instalati Imunify360 sau ClamAV pentru a detecta malware care trimite spam

4. PREVENTIA VIITOARE
- SPF cu -all, DKIM si DMARC p=reject
- reCAPTCHA pe formulare de contact
- Monitorizare MxToolbox Blacklist Monitor (alerte email gratuite)
- Reverse DNS (PTR record) configurat corect

PRIORITATE: INALTA — Afecteaza livrabilitatea tuturor email-urilor magazinului.
REC;
    }

    private function recWarning(string $list, ?string $ip): string {
        return <<<REC
IP DETECTAT INTR-O LISTA DE SPAM — ACTIUNE RECOMANDATA

Lista: {$list} (IP: {$ip})

Initiati procesul de delist accesand direct pagina furnizorului listei. O singura listare poate fi falsa pozitiva sau o listare veche, dar trebuie investigata.

Verificati cu MxToolbox (mxtoolbox.com/blacklists.aspx) toate listele simultan pentru o imagine completa.

Dupa delist, monitorizati 7 zile pentru a confirma ca IP-ul ramane curat. Configurati alerte MxToolbox Blacklist Monitor pentru a fi notificat la viitoare listari.

Verificati daca serverul este shared si daca alte domenii pe acelasi IP sunt sursa problemei.
REC;
    }

    private function recPass(): string {
        return <<<REC
REPUTATIE EMAIL CURATA — RECOMANDARI PENTRU MENTINERE

1. MONITORIZARE AUTOMATA
Configurati MxToolbox Blacklist Monitor (gratuit) pentru alerte email la listare.
Google Postmaster Tools (postmaster.google.com) — monitorizare reputatie in Gmail.
Microsoft SNDS — sendersupport.olc.protection.outlook.com/snds pentru Outlook/Hotmail.

2. DMARC CU RAPOARTE ACTIVATE
Un DMARC cu rua= va notifica zilnic despre spoofing sau server compromis care trimite spam.
Implementati daca nu exista sau adaugati rua= daca DMARC e prezent fara rapoarte.

3. PREVENIREA COMPROMITERII
- Parole unice si complexe pentru toate conturile email
- 2FA pe cPanel si conturile de administrare
- Scanare regulata cu Imunify360 sau ClamAV
- Actualizarea regulata a scripturilor de trimitere email (evitati biblioteci vechi)

4. REVERSE DNS (PTR RECORD)
Asigurati-va ca reverse DNS al IP-ului serverului pointeaza la un hostname valid al domeniului. Lipsa PTR record sau PTR incorect creste probabilitatea de listare si de respingere a email-urilor.
REC;
    }
}
