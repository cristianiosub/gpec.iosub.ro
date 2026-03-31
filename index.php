<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/config.php';
requireLogin();
$user = currentUser();
?><!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>GPeC Security Health Check</title>
<style>
:root{
  --y:#F5B800;--yd:#D9A100;--yl:#FFFBEA;
  --dark:#111827;--dark2:#1E2A3A;
  --pass:#166534;--pass-bg:#DCFCE7;--pass-mid:#16A34A;
  --warn:#92400E;--warn-bg:#FEF3C7;--warn-mid:#D97706;
  --fail:#991B1B;--fail-bg:#FEE2E2;--fail-mid:#DC2626;
  --saas:#374151;--saas-bg:#F3F4F6;
  --text:#111827;--sub:#6B7280;--border:#E5E7EB;--bg:#F9FAFB;
  --card:#FFFFFF;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px;line-height:1.5}

/* ── HEADER ────────────────────────────────── */
.hdr{background:linear-gradient(135deg,#1E3A8A 0%,#2563EB 100%);border-bottom:none;box-shadow:0 2px 12px rgba(37,99,235,.35);position:sticky;top:0;z-index:100}
.hdr-in{max-width:860px;margin:0 auto;display:flex;align-items:center;height:54px;padding:0 16px;gap:8px}
.logo{display:flex;align-items:center;gap:10px;flex:1;text-decoration:none;min-width:0}
.logo-mark{width:32px;height:32px;min-width:32px;background:rgba(255,255,255,.18);border-radius:8px;display:flex;align-items:center;justify-content:center;color:#fff;border:1px solid rgba(255,255,255,.25)}
.logo-mark svg{display:block}
.logo-title{font-size:14px;font-weight:700;color:#fff;white-space:nowrap;letter-spacing:-.2px}
.logo-title b{color:#FDE68A;font-weight:800}
.logo-sub{font-size:10px;color:rgba(255,255,255,.65);letter-spacing:.1px}
.hdr-nav{display:flex;align-items:center;gap:2px;flex-shrink:0}
.hdr-user{font-size:11px;color:rgba(255,255,255,.6);padding:0 8px 0 4px;white-space:nowrap;display:none}
.hl{display:inline-flex;align-items:center;gap:5px;color:rgba(255,255,255,.88);font-size:12px;font-weight:600;text-decoration:none;padding:6px 10px;border-radius:6px;transition:color .15s,background .15s;background:none;border:none;cursor:pointer;white-space:nowrap}
.hl:hover{color:#fff;background:rgba(255,255,255,.15)}
.hl svg{flex-shrink:0}
.hl-logout{color:rgba(255,255,255,.75)}
.hl-logout:hover{color:#FCA5A5;background:rgba(0,0,0,.2)}

/* ── MAIN WRAP ─────────────────────────────── */
.wrap{max-width:860px;margin:0 auto;padding:20px 14px 60px}

/* ── SEARCH BOX ────────────────────────────── */
.search-card{background:var(--card);border-radius:14px;padding:24px 22px;border:1px solid var(--border);margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.search-card h1{font-size:20px;font-weight:700;margin-bottom:4px;letter-spacing:-.3px}
.search-card p{font-size:13px;color:var(--sub);margin-bottom:18px;max-width:560px;line-height:1.55}
.search-row{display:flex;gap:0;border:1.5px solid var(--border);border-radius:10px;overflow:hidden;background:#fff;transition:border-color .15s;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.search-row:focus-within{border-color:var(--y);box-shadow:0 0 0 3px rgba(245,184,0,.12)}
.search-input{flex:1;padding:12px 14px;border:none;font-size:15px;outline:none;background:transparent;color:var(--text);min-width:0}
.search-input::placeholder{color:#9CA3AF}
.search-btn{background:var(--y);color:var(--dark);border:none;padding:0 20px;font-size:13px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:7px;white-space:nowrap;transition:background .15s;flex-shrink:0}
.search-btn:hover{background:var(--yd)}
.search-btn:active{filter:brightness(.95)}
.search-btn:disabled{background:#E5E7EB;color:#9CA3AF;cursor:not-allowed}
.search-btn svg{flex-shrink:0}
.prog-wrap{display:none;margin-top:14px}
.prog-track{height:3px;background:#E5E7EB;border-radius:2px;overflow:hidden}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--y),var(--yd));border-radius:2px;transition:width .3s;width:0}
.prog-lbl{font-size:11px;color:var(--sub);margin-top:6px;text-align:center}

/* ── SCORE CARD ─────────────────────────────── */
.score-card{display:none;background:var(--card);border-radius:14px;padding:20px 22px;border:1px solid var(--border);margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.score-layout{display:flex;flex-direction:column;gap:18px}
.score-top{display:flex;align-items:center;gap:18px}
.score-ring{width:80px;height:80px;min-width:80px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:4px solid;font-weight:800}
.s-num{font-size:26px;line-height:1}
.s-max{font-size:10px;opacity:.6}
.sd-excellent{border-color:var(--y);color:var(--yd);background:var(--yl)}
.sd-ok{border-color:#2563EB;color:#1D4ED8;background:#EFF6FF}
.sd-risk{border-color:var(--warn-mid);color:var(--warn-mid);background:var(--warn-bg)}
.sd-critical{border-color:var(--fail-mid);color:var(--fail-mid);background:var(--fail-bg)}
.score-info{flex:1;min-width:0}
.s-domain{font-size:18px;font-weight:800;word-break:break-all;letter-spacing:-.3px}
.s-grade{font-size:12px;font-weight:600;color:var(--sub);margin:3px 0 10px}
.s-pills{display:flex;gap:6px;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700}
.pl-p{background:var(--pass-bg);color:var(--pass)}
.pl-w{background:var(--warn-bg);color:var(--warn)}
.pl-f{background:var(--fail-bg);color:var(--fail)}
.score-btns{display:flex;flex-direction:column;gap:7px}
.sbtn{display:flex;align-items:center;justify-content:center;gap:7px;border:none;border-radius:8px;padding:10px 16px;font-size:13px;font-weight:600;cursor:pointer;transition:filter .15s;text-align:center}
.sbtn:hover{filter:brightness(.93)}
.sbtn-y{background:var(--y);color:var(--dark)}
.sbtn-dark{background:var(--dark);color:#fff}

/* ── RESULT CARDS ───────────────────────────── */
.results{display:flex;flex-direction:column;gap:6px}
.card{background:var(--card);border-radius:10px;overflow:hidden;border:1px solid var(--border)}
.card-hdr{display:grid;grid-template-columns:auto 1fr auto auto;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;user-select:none;transition:filter .15s}
.card-hdr:hover{filter:brightness(.97)}
.ch-pass{background:var(--pass-mid);color:#fff}
.ch-warning{background:var(--warn-mid);color:#fff}
.ch-fail{background:var(--fail-mid);color:#fff}
.ch-saas{background:var(--saas);color:#fff}
.ch-pending{background:#9CA3AF;color:#fff}
.c-num{font-size:10px;font-weight:800;padding:2px 7px;background:rgba(0,0,0,.15);border-radius:20px;white-space:nowrap;letter-spacing:.2px}
.c-info{min-width:0}
.c-name{font-size:13px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.c-desc{font-size:11px;opacity:.65;display:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:1px}
.c-right{display:flex;flex-direction:column;align-items:flex-end;gap:3px;flex-shrink:0}
.c-stars{display:flex;gap:1px}
.star{font-size:11px}
.sf{color:#FCD34D}
.se{color:rgba(255,255,255,.22)}
.c-status{font-size:10px;font-weight:800;padding:1px 7px;border-radius:6px;background:rgba(255,255,255,.2);letter-spacing:.4px}
.c-arr{font-size:11px;opacity:.5;transition:transform .2s;flex-shrink:0}
.c-arr.open{transform:rotate(180deg)}
.card-body{display:none}
.card-body.open{display:block}
.cb{padding:14px;border-top:1px solid var(--border)}
.cb-summary{font-size:13px;font-weight:500;padding:9px 12px;background:var(--bg);border-radius:7px;border-left:3px solid var(--border);margin-bottom:12px;line-height:1.55}
.cb-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--sub);margin-bottom:6px}
.dlist{list-style:none}
.dlist li{font-size:12px;color:#374151;padding:3px 0 3px 12px;position:relative;border-bottom:1px solid #F3F4F6;line-height:1.45}
.dlist li:last-child{border-bottom:none}
.dlist li::before{content:'·';position:absolute;left:2px;color:#9CA3AF;font-size:16px;line-height:1.1}
.copybox{background:#F9FAFB;border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-top:12px}
.ch2{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:7px;flex-wrap:wrap}
.cl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--sub)}
.bcopy{background:none;border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:11px;font-weight:600;cursor:pointer;color:#6B7280;transition:all .15s}
.bcopy:hover{background:var(--yl);border-color:var(--y);color:var(--yd)}
.bcopy.ok{background:var(--pass-bg);border-color:var(--pass-mid);color:var(--pass)}
.ct{font-size:13px;line-height:1.65;color:#374151}
.stars-row{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--sub);border-top:1px solid var(--border);padding-top:8px;margin-top:8px;flex-wrap:wrap}
.stars-row strong{color:var(--text)}
.recbox{background:var(--yl);border:1.5px solid rgba(245,184,0,.5);border-radius:8px;padding:12px 14px;margin-top:10px}
.rh{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:7px;flex-wrap:wrap}
.rl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--yd)}
.rt{font-size:12px;line-height:1.75;color:#4B3000;white-space:pre-wrap}
.saas-msg{background:var(--saas-bg);border-radius:7px;padding:11px 13px;font-size:13px;color:var(--saas)}
.saas-msg strong{display:block;font-size:13px;font-weight:700;margin-bottom:3px;color:var(--text)}

/* ── MODAL (history) ────────────────────────── */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:200;align-items:flex-end;justify-content:center}
.overlay.open{display:flex}
.modal{background:#fff;border-radius:16px 16px 0 0;padding:20px 16px 32px;width:100%;max-width:560px;max-height:78vh;overflow-y:auto}
.modal-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.modal h3{font-size:15px;font-weight:700}
.modal-x{background:none;border:none;font-size:22px;cursor:pointer;color:#9CA3AF;padding:0 2px;line-height:1}
.hi{display:flex;align-items:center;padding:10px 12px;border:1px solid var(--border);border-radius:9px;margin-bottom:7px;cursor:pointer;gap:12px;transition:all .15s}
.hi:hover{border-color:var(--y);background:var(--yl)}
.hi-domain{font-weight:700;font-size:14px;flex:1;word-break:break-all}
.hi-date{font-size:11px;color:var(--sub);margin-top:2px}
.hi-score{font-size:18px;font-weight:800;flex-shrink:0}

/* ── RESPONSIVE ─────────────────────────────── */
@media(min-width:540px){
  .hdr-user{display:inline}
  .c-desc{display:block}
}
@media(min-width:680px){
  .score-layout{flex-direction:row;align-items:flex-start}
  .score-btns{flex-shrink:0;width:220px}
  .sbtn{width:100%}
  .cb{padding:16px 18px}
}
@media(min-width:860px){
  .hdr-in{padding:0 20px}
  .wrap{padding:24px 20px 80px}
  .search-card{padding:28px 28px}
}

/* ── PRINT ──────────────────────────────────── */
@media print{
  .hdr,.search-card,.score-btns,.bcopy,.overlay,.c-arr{display:none!important}
  .card-body{display:block!important}
  .card{break-inside:avoid;border:1px solid #E5E7EB}
  .wrap{max-width:100%;padding:0}
  body{background:#fff}
}
</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-in">
    <a class="logo" href="index">
      <div class="logo-mark">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div>
        <div class="logo-title"><b>GPeC</b> Security Health Check</div>
        <div class="logo-sub">Audit de securitate pentru magazine online</div>
      </div>
    </a>
    <nav class="hdr-nav">
      <span class="hdr-user"><?= htmlspecialchars($user['username'] ?? '') ?></span>
      <a class="hl" href="admin">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
        Admin
      </a>
      <a class="hl hl-logout" href="login?logout=1" title="Ieșire">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </a>
    </nav>
  </div>
</header>

<main class="wrap">
  <div class="search-card">
    <h1>Verificare securitate domeniu</h1>
    <p>Introdu domeniul magazinului. Toolul rulează 10 verificări automate conform criteriilor GPeC și generează comentarii + recomandări gata de copiat.</p>
    <div class="search-row">
      <input class="search-input" id="domInput" type="text" placeholder="magazin.ro" autocomplete="off" spellcheck="false" inputmode="url">
      <button class="search-btn" id="btnScan" onclick="startScan()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        Scanează
      </button>
    </div>
    <div class="prog-wrap" id="progWrap">
      <div class="prog-track"><div class="prog-bar" id="progBar"></div></div>
      <div class="prog-lbl" id="progLbl">Inițializare…</div>
    </div>
  </div>

  <div class="score-card" id="scoreCard">
    <div class="score-layout">
      <div class="score-top">
        <div class="score-ring" id="scoreDial">
          <div class="s-num" id="scoreNum">—</div>
          <div class="s-max">/ 100</div>
        </div>
        <div class="score-info">
          <div class="s-domain" id="scoreDomain"></div>
          <div class="s-grade" id="scoreGrade"></div>
          <div class="s-pills" id="scorePills"></div>
        </div>
      </div>
      <div class="score-btns">
        <button class="sbtn sbtn-y" onclick="copyAllComments()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          Comentariile GPeC
        </button>
        <button class="sbtn sbtn-y" onclick="copyAllRecs()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          Recomandările
        </button>
        <button class="sbtn sbtn-dark" onclick="window.print()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
          Export PDF
        </button>
      </div>
    </div>
  </div>

  <div class="results" id="results"></div>
</main>

<script>
const LABELS={
  '#1':'Folosirea unui server dedicat, fără alte site-uri sau servicii web disponibile la aceeași adresă IP în afară de porturile 80, 443, 21, 22.',
  '#2':'Lipsa incidentelor de securitate (malware, phishing).',
  '#3':'Lipsa incidentelor de raportare de spam.',
  '#4':'HTTPS implementat în tot site-ul.',
  '#5':'Configurație SSL corectă.',
  '#6':'Accesul din exterior la servicii critice (MySQL, FTP, SSH) este restricționat prin firewall.',
  '#7':'Platforma CMS și extensiile sunt actualizate.',
  '#8':'Serviciile de e-mail folosesc protocoale securizate (SMTP/IMAP SSL/StartTLS).',
  '#9':'Evitarea listării publice a directoarelor de pe site.',
  '#10':'Blocarea încercărilor repetate de accesare ilegală a unui cont (brute force).',
};
const SHORT={'#1':'Server Dedicat','#2':'Malware / Phishing','#3':'Reputație Spam','#4':'HTTPS Full','#5':'SSL Config','#6':'Porturi Critice','#7':'CMS & Extensii','#8':'Email Security','#9':'Directory Listing','#10':'Brute Force'};
const CHECKS=['dedicated_server','malware','spam_reputation','https_full','ssl_config','critical_ports','cms_updates','email_security','directory_listing','brute_force'];
const GPEC_IDS=['#1','#2','#3','#4','#5','#6','#7','#8','#9','#10'];

let scanId=null,currentDomain=null,resultMap={},done=0;

function stars(n,t=5){return Array.from({length:t},(_,i)=>`<span class="star ${i<n?'sf':'se'}">★</span>`).join('')}
function gradeClass(s){return s>=90?'sd-excellent':s>=70?'sd-ok':s>=50?'sd-risk':'sd-critical'}
function gradeText(s){
  if(s>=90)return '✅ Excelent — site securizat';
  if(s>=70)return '🟡 Bun — aspecte de îmbunătățit';
  if(s>=50)return '⚠️ Risc — vulnerabilități detectate';
  return '🔴 Critic — vulnerabilități majore';
}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

async function startScan(){
  const domain=document.getElementById('domInput').value.trim();
  if(!domain){document.getElementById('domInput').focus();return}
  document.getElementById('btnScan').disabled=true;
  document.getElementById('progWrap').style.display='block';
  document.getElementById('scoreCard').style.display='none';
  document.getElementById('results').innerHTML='';
  resultMap={};done=0;
  currentDomain=domain.replace(/^https?:\/\//,'').replace(/\/.*/,'');
  GPEC_IDS.forEach(id=>{document.getElementById('results').insertAdjacentHTML('beforeend',pendingCard(id))});
  const fd=new FormData();fd.append('action','create_scan');fd.append('domain',domain);
  try{
    const r=await fetch('api.php',{method:'POST',body:fd});
    const d=await r.json();
    if(!d.success)throw new Error(d.error);
    scanId=d.id;
  }catch(e){
    document.getElementById('progLbl').textContent='Eroare: '+e.message;
    document.getElementById('btnScan').disabled=false;
    return;
  }
  let i=0;
  const tasks=CHECKS.map((check,idx)=>()=>runCheck(scanId,check,GPEC_IDS[idx]));
  const workers=Array.from({length:3},async()=>{while(i<tasks.length){const t=tasks[i++];await t()}});
  await Promise.all(workers);
  document.getElementById('btnScan').disabled=false;
}

async function runCheck(sid,check,gpecId){
  const fd=new FormData();
  fd.append('action','run_check');fd.append('scan_id',sid);fd.append('check',check);
  try{
    const r=await fetch('api.php',{method:'POST',body:fd});
    const d=await r.json();
    if(!d.success)throw new Error(d.error);
    placeResult(gpecId,d.result);
  }catch(e){
    placeResult(gpecId,{gpec_id:gpecId,check_name:check,status:'fail',stars_suggested:1,
      summary:'Eroare la verificare: '+e.message,
      details:['Eroare rețea sau timeout. Verificare manuală recomandată.'],
      comment_ro:`Verificarea ${gpecId} nu s-a putut realiza. Se recomandă verificare manuală.`,
      raw_data:{recommendation_ro:'Verificarea automată a eșuat. Vă rugăm să efectuați o verificare manuală sau să reîncercați.'}});
  }
}

function placeResult(gpecId,r){
  resultMap[gpecId]=r;done++;
  const old=document.getElementById('card-'+gpecId.replace('#',''));
  if(old)old.outerHTML=renderCard(r);
  if(r.status==='fail')setTimeout(()=>openCard('card-'+gpecId.replace('#','')),60);
  const pct=Math.round(done/CHECKS.length*100);
  document.getElementById('progBar').style.width=pct+'%';
  document.getElementById('progLbl').textContent=`${done}/${CHECKS.length} — ${SHORT[r.gpec_id]||r.check_name}`;
  if(done===CHECKS.length)showScore();
}

function renderCard(r){
  const cid='card-'+r.gpec_id.replace('#','');
  const name=SHORT[r.gpec_id]||r.check_name;
  const label=LABELS[r.gpec_id]||r.check_name;
  const stext={pass:'PASS',warning:'WARN',fail:'FAIL',saas:'N/A'}[r.status]||r.status.toUpperCase();
  const details=Array.isArray(r.details)?r.details:[];
  const rec=r.raw_data?.recommendation_ro||'';
  const isSaas=r.status==='saas';
  let body='';
  if(isSaas){
    body=`<div class="cb"><div class="saas-msg"><strong>Platforma SaaS — audit direct nerealizabil</strong>${esc(r.summary)}</div></div>`;
  }else{
    body=`<div class="cb">
      <div class="cb-summary">${esc(r.summary)}</div>
      <div class="cb-title">Detalii tehnice</div>
      <ul class="dlist">${details.map(d=>`<li>${esc(d)}</li>`).join('')}</ul>
      <div class="copybox">
        <div class="ch2"><span class="cl">Comentariu GPeC</span><button class="bcopy" onclick="doCopy('cmt-${cid}',this)">Copiază</button></div>
        <div class="ct" id="cmt-${cid}">${esc(r.comment_ro)}</div>
        <div class="stars-row">Rating sugerat: <strong>${r.stars_suggested}/5</strong> ${stars(r.stars_suggested)}</div>
      </div>
      ${rec?`<div class="recbox">
        <div class="rh"><span class="rl">Recomandare pentru merchant</span><button class="bcopy" onclick="doCopy('rec-${cid}',this)">Copiază</button></div>
        <div class="rt" id="rec-${cid}">${esc(rec)}</div>
      </div>`:''}
    </div>`;
  }
  return `<div class="card" id="${cid}">
    <div class="card-hdr ch-${r.status}" onclick="toggleCard('${cid}')">
      <span class="c-num">${r.gpec_id}</span>
      <div class="c-info"><div class="c-name">${esc(name)}</div><div class="c-desc">${esc(label)}</div></div>
      <div class="c-right"><span class="c-stars">${stars(r.stars_suggested)}</span><span class="c-status">${stext}</span></div>
      <span class="c-arr" id="arr-${cid}">▾</span>
    </div>
    <div class="card-body" id="body-${cid}">${body}</div>
  </div>`;
}

function pendingCard(gpecId){
  const cid='card-'+gpecId.replace('#','');
  return `<div class="card" id="${cid}">
    <div class="card-hdr ch-pending">
      <span class="c-num">${gpecId}</span>
      <div class="c-info"><div class="c-name">${esc(SHORT[gpecId]||gpecId)}</div><div class="c-desc">${esc((LABELS[gpecId]||'').substring(0,90))}</div></div>
      <div class="c-right"></div>
      <span class="c-status" style="font-size:10px;padding:2px 7px;border-radius:6px;background:rgba(255,255,255,.2)">…</span>
    </div>
  </div>`;
}

function toggleCard(cid){
  const b=document.getElementById('body-'+cid),a=document.getElementById('arr-'+cid);
  if(!b)return;
  b.classList.toggle('open');if(a)a.classList.toggle('open');
}
function openCard(cid){
  const b=document.getElementById('body-'+cid),a=document.getElementById('arr-'+cid);
  if(b&&!b.classList.contains('open')){b.classList.add('open');if(a)a.classList.add('open')}
}

async function doCopy(elId,btn){
  const el=document.getElementById(elId);if(!el)return;
  try{
    await navigator.clipboard.writeText(el.textContent);
    btn.textContent='Copiat ✓';btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='Copiază';btn.classList.remove('ok')},2000);
  }catch(e){}
}

async function copyAllComments(){
  const text=GPEC_IDS.map(id=>{const r=resultMap[id];if(!r)return null;
    return `${r.gpec_id} — ${LABELS[r.gpec_id]||r.check_name}\nRating: ${r.stars_suggested}/5\n${r.comment_ro}`;
  }).filter(Boolean).join('\n\n---\n\n');
  if(!text)return;
  try{await navigator.clipboard.writeText(text);event.target.textContent='Copiate ✓';setTimeout(()=>event.target.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Comentariile GPeC',2500)}catch(e){}
}

async function copyAllRecs(){
  const text=GPEC_IDS.map(id=>{const r=resultMap[id];if(!r)return null;const rec=r.raw_data?.recommendation_ro||'';if(!rec)return null;
    return `${r.gpec_id} — ${LABELS[r.gpec_id]||r.check_name}\n\n${rec}`;
  }).filter(Boolean).join('\n\n═══════════════\n\n');
  if(!text)return;
  try{await navigator.clipboard.writeText(text);event.target.textContent='Copiate ✓';setTimeout(()=>event.target.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg> Recomandările',2500)}catch(e){}
}

function showScore(){
  const vals=Object.values(resultMap);
  const sc={pass:0,warning:0,fail:0,saas:0};
  vals.forEach(r=>sc[r.status]=(sc[r.status]||0)+1);
  const aud=vals.filter(r=>r.status!=='saas').length;
  const score=aud?Math.round((sc.pass*10+sc.warning*5)/(aud*10)*100):0;
  document.getElementById('scoreCard').style.display='block';
  document.getElementById('scoreDial').className='score-ring '+gradeClass(score);
  document.getElementById('scoreNum').textContent=score;
  document.getElementById('scoreDomain').textContent=currentDomain||'';
  document.getElementById('scoreGrade').textContent=gradeText(score);
  document.getElementById('scorePills').innerHTML=
    `<span class="pill pl-p">PASS: ${sc.pass}</span>
     <span class="pill pl-w">WARN: ${sc.warning}</span>
     <span class="pill pl-f">FAIL: ${sc.fail}</span>
     ${sc.saas?`<span class="pill" style="background:#F3F4F6;color:#374151">N/A: ${sc.saas}</span>`:''}`;
  document.getElementById('scoreCard').scrollIntoView({behavior:'smooth'});
  document.getElementById('progLbl').textContent=`Scanare finalizată — scor: ${score}/100`;
}

document.getElementById('domInput').addEventListener('keydown',e=>{if(e.key==='Enter')startScan()});
</script>
</body>
</html>
