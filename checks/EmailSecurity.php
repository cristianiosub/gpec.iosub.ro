<?php
require_once __DIR__ . '/BaseCheck.php';

class EmailSecurity extends BaseCheck {

    private const DKIM_SELECTORS = [
        'default', 'google', 'mail', 'k1', 'k2',
        'selector1', 'selector2', 'smtp', 'dkim', 's1', 's2', 'mandrill',
    ];

    public function run(): array {
        $details = [];
        $missing = [];
        $weak    = [];

        // SPF
        $txtAll = $this->getTxtRecords($this->domain);
        $spf    = '';
        foreach ($txtAll as $t) {
            if (str_starts_with($t, 'v=spf1')) { $spf = $t; break; }
        }
        if ($spf) {
            $details[] = 'SPF: prezent — ' . substr($spf, 0, 120);
            if (str_contains($spf, '+all') || str_contains($spf, '?all')) {
                $weak[]    = 'spf_permissive';
                $details[] = 'SPF: politica permisiva (+all / ?all) — risc spoofing ridicat';
            } elseif (str_contains($spf, '~all')) {
                $details[] = 'SPF: politica ~all (softfail) — recomandat -all (hardfail)';
                $weak[]    = 'spf_softfail';
            } elseif (str_contains($spf, '-all')) {
                $details[] = 'SPF: politica -all (hardfail) — optima';
            }
        } else {
            $missing[] = 'SPF';
            $details[] = 'SPF: LIPSA — oricine poate trimite email in numele domeniului';
        }

        // DMARC
        $dmarcRecs = $this->getTxtRecords("_dmarc.{$this->domain}");
        $dmarc     = '';
        foreach ($dmarcRecs as $t) {
            if (str_contains($t, 'v=DMARC1')) { $dmarc = $t; break; }
        }
        if ($dmarc) {
            $details[] = 'DMARC: prezent — ' . substr($dmarc, 0, 120);
            if (str_contains($dmarc, 'p=none')) {
                $details[] = 'DMARC: p=none (monitorizare, fara blocare) — recomandat p=quarantine sau p=reject';
                $weak[]    = 'dmarc_none';
            } elseif (str_contains($dmarc, 'p=quarantine')) {
                $details[] = 'DMARC: p=quarantine (buna practica)';
            } elseif (str_contains($dmarc, 'p=reject')) {
                $details[] = 'DMARC: p=reject (politica optima — email fals respins)';
            }
            // Verifica rua/ruf (rapoarte)
            if (str_contains($dmarc, 'rua=')) {
                preg_match('/rua=mailto:([^\s;]+)/', $dmarc, $m);
                $details[] = 'DMARC rua (rapoarte agregate): ' . ($m[1] ?? 'prezent');
            } else {
                $details[] = 'DMARC rua: lipsa — recomandat pentru monitorizare';
                $weak[]    = 'dmarc_no_rua';
            }
            if (str_contains($dmarc, 'ruf=')) {
                $details[] = 'DMARC ruf (rapoarte forensice): prezent';
            }
        } else {
            $missing[] = 'DMARC';
            $details[] = 'DMARC: LIPSA — nicio politica de autentificare email';
        }

        // DKIM
        $dkimFound    = false;
        $dkimSelector = '';
        foreach (self::DKIM_SELECTORS as $sel) {
            $recs = $this->getTxtRecords("{$sel}._domainkey.{$this->domain}");
            foreach ($recs as $r) {
                if (str_contains($r, 'v=DKIM1') || str_contains($r, 'p=')) {
                    $dkimFound    = true;
                    $dkimSelector = $sel;
                    break 2;
                }
            }
        }
        if ($dkimFound) {
            $details[] = "DKIM: prezent (selector: {$dkimSelector})";
        } else {
            $missing[] = 'DKIM';
            $details[] = 'DKIM: LIPSA sau selector necunoscut (testat: ' . implode(', ', self::DKIM_SELECTORS) . ')';
        }

        // BIMI (Brand Indicators for Message Identification) — bonus
        $bimiRecs = $this->getTxtRecords("default._bimi.{$this->domain}");
        $bimi = '';
        foreach ($bimiRecs as $r) {
            if (str_contains($r, 'v=BIMI1')) { $bimi = $r; break; }
        }
        if ($bimi) {
            $details[] = 'BIMI: prezent — logo brand afisat in clienti email compatibili';
        } else {
            $details[] = 'BIMI: lipsa (optional, dar recomandat pentru brand trust)';
        }

        // MX + porturi securizate
        $mxRecs = @dns_get_record($this->domain, DNS_MX);
        if ($mxRecs) {
            usort($mxRecs, fn($a, $b) => $a['pri'] - $b['pri']);
            $mxHost = $mxRecs[0]['target'];
            $details[] = 'MX: ' . implode(', ', array_column($mxRecs, 'target'));

            $port587 = $this->testPort($mxHost, 587, 4);
            $port993 = $this->testPort($mxHost, 993, 4);
            $port465 = $this->testPort($mxHost, 465, 4);

            if ($port587)  $details[] = 'Port 587 (SMTP/STARTTLS): deschis (corect)';
            if ($port993)  $details[] = 'Port 993 (IMAPS): deschis (corect)';
            if ($port465)  $details[] = 'Port 465 (SMTPS): deschis';
            if (!$port587 && !$port993 && !$port465) {
                $weak[]    = 'no_secure_ports';
                $details[] = 'Porturile securizate mail (587/993/465) nu raspund — posibil filtrate extern';
            }

            // Verifica port 25 direct (ar trebui filtrat pentru clienti)
            $port25 = $this->testPort($mxHost, 25, 3);
            if ($port25) $details[] = 'Port 25 (SMTP direct): deschis — normal pentru MX, clientii trebuie sa foloseasca 587/465';
        } else {
            $details[] = 'MX: niciun record — domeniu fara email propriu sau externalizat';
        }

        $cnt = count($missing);

        if ($cnt >= 2 || (in_array('SPF', $missing) && in_array('DMARC', $missing))) {
            return $this->result('#8', 'Securitate Email (SPF/DKIM/DMARC)', 'fail', 1,
                'Lipsesc configuratii critice email: ' . implode(', ', $missing) . '.',
                $details,
                "Domeniul {$this->domain} nu are configurate " . implode(' si ', $missing) . ", " .
                "permitand atacatorilor sa trimita emailuri frauduloase in numele magazinului (spoofing). " .
                "SPF, DKIM si DMARC sunt obligatorii pentru securitate si livrabilitate email.",
                ['spf' => (bool)$spf, 'dkim' => $dkimFound, 'dmarc' => (bool)$dmarc, 'missing' => $missing,
                 'recommendation_ro' => $this->recFail($missing)]
            );
        }
        if ($cnt > 0 || !empty($weak)) {
            $issues = array_merge(
                array_map(fn($m) => "{$m} lipsa", $missing),
                array_map(fn($w) => match($w) {
                    'spf_permissive'  => 'SPF cu politica permisiva (+all)',
                    'spf_softfail'    => 'SPF ~all (softfail, recomandat -all)',
                    'dmarc_none'      => 'DMARC p=none (fara blocare activa)',
                    'dmarc_no_rua'    => 'DMARC fara rapoarte rua',
                    'no_secure_ports' => 'porturi mail securizate neconfirmate',
                    default           => $w
                }, $weak)
            );
            return $this->result('#8', 'Securitate Email (SPF/DKIM/DMARC)', 'warning', 3,
                'Securitate email partiala: ' . implode(', ', $issues) . '.',
                $details,
                "Configuratia email a domeniului {$this->domain} este partiala: " . implode('; ', $issues) . ". " .
                "Se recomanda completarea configuratiei pentru a preveni phishing-ul si abuzurile.",
                ['missing' => $missing, 'weak' => $weak, 'recommendation_ro' => $this->recWarning($missing, $weak)]
            );
        }
        return $this->result('#8', 'Securitate Email (SPF/DKIM/DMARC)', 'pass', 5,
            'SPF, DKIM si DMARC configurate corect — email securizat.',
            $details,
            "Domeniul {$this->domain} are configurate corect SPF, DKIM si DMARC. " .
            "Emailurile frauduloase in numele magazinului vor fi blocate/marcate spam. " .
            ($bimi ? 'BIMI este de asemenea prezent — logo-ul brandului apare in clienti email compatibili.' : ''),
            ['spf' => true, 'dkim' => true, 'dmarc' => true, 'bimi' => (bool)$bimi,
             'recommendation_ro' => $this->recPass($bimi)]
        );
    }

    private function recFail(array $missing): string {
        $list = implode(', ', $missing);
        return <<<REC
CONFIGURATIE EMAIL INCOMPLETA — RISC RIDICAT DE PHISHING SI SPOOFING

Domeniul nu are configurate: {$list}. Aceasta inseamna ca oricine poate trimite emailuri care par sa vina de la adrese @{$this->domain}, pacalind clientii sau partenerii.

1. CONFIGURAREA SPF (Sender Policy Framework)
SPF defineste ce servere mail au voie sa trimita emailuri in numele domeniului dumneavoastra.
Adaugati un record TXT in DNS:
  Nume: @ (sau domeniu.ro)
  Valoare: v=spf1 include:_spf.google.com ~all
(Inlocuiti include: cu furnizorul dumneavoastra de email: SendGrid, Mailchimp, cPanel etc.)
Politici recomandate:
  ~all (softfail) — emailurile neautorizate sunt marcate suspect (START)
  -all (hardfail) — emailurile neautorizate sunt respinse (RECOMANDAT dupa testare)
Evitati +all sau ?all — permit oricui sa trimita in numele domeniului.

2. CONFIGURAREA DKIM (DomainKeys Identified Mail)
DKIM adauga o semnatura digitala criptografica fiecarui email trimis, dovedind ca nu a fost alterat.
Generarea cheilor DKIM:
- cPanel: Email → Email Deliverability → Manage → Enable DKIM
- Google Workspace: Admin Console → Apps → Google Workspace → Gmail → Authenticate Email
- Microsoft 365: Defender Portal → Policies → Email Authentication → DKIM
Adaugati record-urile TXT generate in DNS (selector._domainkey.domeniu.ro).

3. CONFIGURAREA DMARC (Domain-based Message Authentication)
DMARC defineste ce trebuie sa faca serverele receptoare cu emailurile care esueaza SPF si DKIM.
Adaugati record TXT:
  Nume: _dmarc
  Valoare: v=DMARC1; p=none; rua=mailto:dmarc@domeniu.ro; ruf=mailto:dmarc@domeniu.ro; fo=1
Incepeti cu p=none pentru monitorizare, treceti la p=quarantine dupa 2-4 saptamani, apoi p=reject.
rua= primiti rapoarte zilnice agregate despre emailurile trimise in numele domeniului.
ruf= primiti rapoarte forensice pentru emailuri esuate.

4. TESTARE SI VALIDARE
Dupa configurare, validati cu:
- MXToolbox (mxtoolbox.com/spf.aspx) — verifica SPF
- DMARC Analyzer (dmarcanalyzer.com) — verifica DMARC
- Mail-tester (mail-tester.com) — scor complet 10/10 email deliverability
- Google Postmaster Tools — monitorizare reputatie domeniu

PRIORITATE: CRITICA pentru protectia clientilor si reputatia brandului.
REC;
    }

    private function recWarning(array $missing, array $weak): string {
        $parts = [];

        if (in_array('spf_permissive', $weak) || in_array('spf_softfail', $weak)) {
            $parts[] = <<<SPF
IMBUNATATIREA POLITICII SPF
Politica SPF curenta este prea permisiva. Tranzitia recomandata:
1. Auditati toti expeditorii de email autorizati (CRM, newsletter, facturare, helpdesk)
2. Listati-i explicit in SPF: v=spf1 include:_spf.google.com include:sendgrid.net ip4:1.2.3.4 -all
3. Schimbati din ~all in -all pentru hardfail dupa testare de 2 saptamani
Atentie: inainte de -all, verificati ca TOATE serverele autorizate sunt incluse in SPF, altfel emailurile legitime pot fi respinse.
SPF;
        }

        if (in_array('dmarc_none', $weak)) {
            $parts[] = <<<DMARC
ESCALADAREA POLITICII DMARC DE LA p=none LA p=quarantine/p=reject
p=none inseamna ca DMARC este in modul de monitorizare — emailurile frauduloase NU sunt blocate.
Planul de migrare recomandat:
- Saptamanile 1-4: mentineti p=none, analizati rapoartele rua
- Saptamanile 5-8: treceti la p=quarantine; pct=10 (10% din emailuri esuate merg in spam)
- Luna 3: p=quarantine; pct=100 (toate emailurile esuate in spam)
- Luna 4-6: p=reject (emailurile frauduloase sunt respinse complet)
Rapoartele rua sunt esentiale pentru aceasta migrare — configurati-le daca nu exista.
DMARC;
        }

        if (in_array('dmarc_no_rua', $weak)) {
            $parts[] = <<<RUA
ACTIVAREA RAPOARTELOR DMARC (rua)
Rapoartele agregate DMARC va informeaza zilnic despre toate emailurile trimise in numele domeniului, inclusiv cele frauduloase.
Adaugati la record-ul DMARC existent:
  ; rua=mailto:dmarc-reports@domeniu.ro
Sau folositi un serviciu specializat: Postmark DMARC (free), Dmarcian, Valimail.
Aceste rapoarte sunt esentiale pentru a detecta tentative de phishing si pentru a valida corectitudinea SPF/DKIM.
RUA;
        }

        return implode("\n\n---\n\n", $parts) ?: 'Completati configuratia email pentru conformitate deplina.';
    }

    private function recPass(string $bimi): string {
        $bimiTip = $bimi ? '' : <<<BIMIBLOCK

6. IMPLEMENTAREA BIMI (Brand Indicators for Message Identification)
BIMI afiseaza logo-ul brandului dumneavoastra in clientii email compatibili (Gmail, Apple Mail, Yahoo).
Cerinte: DMARC p=reject sau p=quarantine activ + SVG logo inregistrat (optional VMC certificat).
Record DNS:
  Nume: default._bimi
  Valoare: v=BIMI1; l=https://domeniu.ro/logo-bimi.svg; a=
BIMIBLOCK;

        return <<<REC
CONFIGURATIE EMAIL EXCELENTA — RECOMANDARI AVANSATE

1. MONITORIZARE DMARC CONTINUA
Analizati rapoartele rua saptamanal. Utilizati un serviciu precum:
- Postmark DMARC Digests (gratuit)
- Dmarcian sau Valimail (platite, cu dashboard vizual)
Cautati in rapoarte: surse necunoscute care trimit email in numele domeniului.

2. ROTATIA CHEILOR DKIM
Cheile DKIM trebuie rotate periodic (recomandat la 12 luni) pentru a limita impactul unei compromitete.
Procedura: generati un selector nou (ex: 20240101), publicati-l in DNS, configurati serverul sa semneze cu noul selector, asteptati propagarea DNS (24-48h), dezactivati selectorul vechi.

3. MTA-STS (Mail Transfer Agent Strict Transport Security)
MTA-STS forteaza serverele care va trimit email sa foloseasca TLS, prevenind interceptarea.
Adaugati fisier https://mta-sts.domeniu.ro/.well-known/mta-sts.txt si record DNS:
  _mta-sts TXT "v=STSv1; id=20240101"

4. TLS-RPT (TLS Reporting)
Similar DMARC, TLS-RPT raporteaza problemele TLS in livrarea emailurilor:
  _smtp._tls TXT "v=TLSRPTv1; rua=mailto:tls-reports@domeniu.ro"

5. GOOGLE POSTMASTER TOOLS
Inregistrati domeniul la Google Postmaster Tools (postmaster.google.com) pentru a monitoriza:
- Reputatia IP si domeniului
- Rata de spam
- Autentificarea email (SPF/DKIM/DMARC)
{$bimiTip}
REC;
    }
}
