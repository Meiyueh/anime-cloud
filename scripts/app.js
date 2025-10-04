// ===== LocalStorage helpers =====
const readLS = (k, def) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : def; } catch { return def; } };
const writeLS = (k, v) => localStorage.setItem(k, JSON.stringify(v));

// ===== Constants =====
const KEYS = {
  USERS: 'animecloud_users',
  AUTH: 'animecloud_auth',
  UPLOADS: 'animecloud_uploads',
  FEEDBACK: 'animecloud_feedback',
  THEME: 'ac_theme'
};

// ===== DOM helpers =====
const $ = sel => document.querySelector(sel);

// ===== Toasts =====
(function ensureToastWrap(){
  if (!document.getElementById('toast-wrap')) {
    const d = document.createElement('div'); d.id = 'toast-wrap'; document.body.appendChild(d);
  }
})();
function toast(msg, type='ok', timeout=2600){
  const w = document.getElementById('toast-wrap');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  w.appendChild(t);
  setTimeout(()=>{ t.style.opacity = 0; t.style.transform='translateY(8px)'; setTimeout(()=>t.remove(), 200); }, timeout);
}

// ===== Users / Auth =====
function readUsers(){ return readLS(KEYS.USERS, {}); }
function writeUsers(u){ writeLS(KEYS.USERS, u); }
function ensureSeedAdmin(){
  const u = readUsers();
  if (!u['admin@localanim']) {
    u['admin@localanim'] = {
      email:'admin@localanim', password:'12345', role:'admin',
      createdAt: Date.now(),
      profile: { nickname: 'Admin', avatar: null, primaryTitle: 'ADMIN', secondaryTitle: null, frame: null }
    };
    writeUsers(u);
  }
}
function register(email, password){
  email = (email||'').trim().toLowerCase();
  if (!email || !password) return false;
  const u = readUsers();
  if (u[email]) return false;
  u[email] = {
    email, password, role:'user', createdAt: Date.now(),
    profile: { nickname: email.split('@')[0], avatar: null, primaryTitle: 'USER', secondaryTitle: null, frame: null }
  };
  writeUsers(u); return true;
}
function login(email, password){
  const u = readUsers(); const e = (email||'').trim().toLowerCase();
  if (!u[e] || u[e].password !== password) return false;
  const primaryTitle = (u[e].role === 'admin') ? 'ADMIN' : (u[e].role === 'uploader' ? 'UPLOADER' : 'USER');
  if (!u[e].profile) u[e].profile = { nickname: e.split('@')[0], avatar:null, primaryTitle, secondaryTitle:null, frame:null };
  u[e].profile.primaryTitle = primaryTitle; writeUsers(u);
  writeLS(KEYS.AUTH, { email:e, role:u[e].role, at: Date.now() }); return true;
}
function logout(){ localStorage.removeItem(KEYS.AUTH); location.href='index.html'; }
function auth(){ return readLS(KEYS.AUTH, {}); }
function isAdmin(){ return auth().role === 'admin'; }
function getUser(email){ if (!email) return null; return readUsers()[email] || null; }
function updateUser(email, patch){
  const users = readUsers(); if (!users[email]) return;
  users[email] = { ...users[email], ...patch };
  writeUsers(users);
}

// ===== Profile helpers =====
function getProfile(email){
  const u = getUser(email); if (!u) return null;
  if (!u.profile) { u.profile = { nickname: email.split('@')[0], avatar:null, primaryTitle:'USER', secondaryTitle:null, frame:null }; updateUser(email,{profile:u.profile}); }
  return u.profile;
}
function setNickname(email, nickname){
  const u = getUser(email); if (!u) return;
  u.profile = u.profile || {};
  u.profile.nickname = nickname || u.profile.nickname;
  updateUser(email, { profile: u.profile });
}
function setAvatar(email, dataUrl){
  const u = getUser(email); if (!u) return;
  u.profile = u.profile || {};
  u.profile.avatar = dataUrl;
  updateUser(email, { profile: u.profile });
}
function setSecondaryTitle(email, title){
  const u = getUser(email); if (!u) return;
  u.profile = u.profile || {};
  u.profile.secondaryTitle = title || null;
  updateUser(email, { profile: u.profile });
}
function computeMilestoneFrame(uploadCount){
  if (uploadCount >= 100) return 'gold';
  if (uploadCount >= 50) return 'silver';
  if (uploadCount >= 10) return 'bronze';
  return null;
}
function userUploadCount(email){
  return getUploads().filter(u => u.user === email).length;
}
function unlockedTitles(email){
  const n = userUploadCount(email);
  const t = [];
  if (n >= 10) t.push('Veterán (10+)');
  if (n >= 50) t.push('Mistr Uploader (50+)');
  if (n >= 100) t.push('Legenda (100+)');
  return t;
}

// ===== Navbar & Theme =====
function setTheme(theme){ document.documentElement.setAttribute('data-theme', theme); localStorage.setItem(KEYS.THEME, theme); }
function initTheme(){
  const t = localStorage.getItem(KEYS.THEME) || 'dark'; setTheme(t);
  const btn = document.getElementById('nav-theme');
  if (btn) btn.addEventListener('click', ()=>{
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    setTheme(cur === 'dark' ? 'light' : 'dark');
  });
}
function initNavbar(){
  ensureSeedAdmin(); initTheme();
  const a = auth();
  const navs = {
    login: $('#nav-login'), admin: $('#nav-admin'), upload: $('#nav-upload'),
    feedback: $('#nav-feedback'), account: $('#nav-account')
  };
  if (a.email){
    navs.upload && navs.upload.classList.remove('hidden');
    navs.feedback && navs.feedback.classList.remove('hidden');
    navs.account && navs.account.classList.remove('hidden');
    if (navs.admin) isAdmin()? navs.admin.classList.remove('hidden') : navs.admin.classList.add('hidden');
    if (navs.login) navs.login.classList.add('hidden');
  } else {
    ['upload','feedback','account','admin'].forEach(k => navs[k] && navs[k].classList.add('hidden'));
    if (navs.login){ navs.login.classList.remove('hidden'); navs.login.textContent='Přihlášení'; navs.login.href='login.html'; }
  }
}
function guardAuthOnPage(loginHref='login.html'){ const a = auth(); if (!a.email) location.href=loginHref; }

// ===== Upload records =====
function getUploads(){ return readLS(KEYS.UPLOADS, []); }
function setUploads(a){ writeLS(KEYS.UPLOADS, a); }
function addUploadRecord(r){ const a = getUploads(); a.push(r); setUploads(a); }
function getUploadCountByQuality(slug, ep, q){
  return getUploads().filter(u => u.slug===slug && u.episode===ep && u.quality===q).length;
}

// ===== Anime data =====
async function fetchAnime(path='data/anime.json'){ const r = await fetch(path, {cache:'no-cache'}); return await r.json(); }
function populateSelectWithPlaceholder(sel, text='— vyber z možností —'){ sel.innerHTML=''; const op=document.createElement('option'); op.value=''; op.disabled=true; op.selected=true; op.textContent=text; sel.appendChild(op); }
function populateEpisodesSelect(sel, count){ populateSelectWithPlaceholder(sel, '— vyber díl —'); for(let i=1;i<=count;i++){ const o=document.createElement('option'); o.value=String(i); o.textContent=`Díl ${i}`; sel.appendChild(o); } }
function extOrDefault(name, defExt){ const m=/(?:\.)([a-z0-9]+)$/i.exec(name||''); const e=m?m[1].toLowerCase():''; return e||defExt; }

// ===== Feedback (offline store) =====
function saveFeedback(item){
  const f = readLS(KEYS.FEEDBACK, []);
  const threadMsg = {
    id: (item.ts || Date.now()) + '_0',
    role: 'user',
    author: item.user || item.name || 'anonym',
    text: item.message || '',
    ts: item.ts || Date.now()
  };
  const rec = {
    id: item.id || ('tkt_' + (item.ts || Date.now())),
    user: item.user || null,
    name: item.name || null,
    category: item.category || 'other',
    priority: item.priority || 'normal',
    status: item.status || 'open',
    ts: item.ts || Date.now(),
    messages: [ threadMsg ]
  };
  f.push(rec);
  writeLS(KEYS.FEEDBACK, f);
  return rec.id;
}
function getFeedback(){ return readLS(KEYS.FEEDBACK, []); }
function getTicketById(id){ return getFeedback().find(x=>x.id===id) || null; }
function updateFeedback(id, patch){
  const arr = getFeedback();
  const idx = arr.findIndex(x => x.id === id);
  if (idx >= 0) {
    arr[idx] = {...arr[idx], ...patch};
    writeLS(KEYS.FEEDBACK, arr);
  }
}
function addTicketMessage(id, {role, author, text}){
  const arr = getFeedback();
  const idx = arr.findIndex(x => x.id === id);
  if (idx < 0) return false;
  if (['resolved','approved','rejected'].includes(arr[idx].status)) return false;
  arr[idx].messages = arr[idx].messages || [];
  arr[idx].messages.push({
    id: id + '_' + (arr[idx].messages.length+1),
    role: role, author: author, text: text, ts: Date.now()
  });
  writeLS(KEYS.FEEDBACK, arr);
  return true;
}

// ===== Utils =====
function showMsg(el, text, type='ok'){ if(!el) return; el.textContent=text; el.className=`msg ${type}`; }
function fmtBytes(bytes){
  if (!bytes && bytes !== 0) return '';
  const k = 1024, sizes = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes)/Math.log(k));
  return parseFloat((bytes/Math.pow(k,i)).toFixed(2)) + ' ' + sizes[i];
}

// ===== Export App =====
window.App = {
  // UI
  initNavbar, guardAuthOnPage, showMsg, toast, setTheme,
  // Auth
  register, login, logout, auth, isAdmin, getUser, updateUser,
  // Profile
  getProfile, setNickname, setAvatar, setSecondaryTitle, computeMilestoneFrame, userUploadCount, unlockedTitles,
  // Anime
  fetchAnime, populateSelectWithPlaceholder, populateEpisodesSelect, extOrDefault,
  // Uploads
  getUploadCountByQuality, addUploadRecord, getUploads, setUploads,
  // Feedback
  saveFeedback, getFeedback, updateFeedback, addTicketMessage, getTicketById,
  // Utils
  fmtBytes
};
