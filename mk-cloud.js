/* مكتبي الإلكتروني — طبقة Supabase
   حسابات المكاتب (معزولة) + مزامنة البيانات بين الأجهزة + دخول أوفلاين.
   تعمل فقط إذا ضُبط mk-config.js؛ وإلا يبقى التطبيق بوضعه المحلي القديم. */
(function () {
  'use strict';
  const CFG = window.MK_CONFIG || {};
  const ENABLED = !!(CFG.url && CFG.anonKey);
  if (!ENABLED) { console.info('[mk] Supabase غير مضبوط — الوضع المحلي'); return; }

  const DOMAIN = '@maktaby.app';
  const COLLS = ['attachments','bailiffs','cases','clients','docs','events','fin_entries','invoices',
    'ld_cases','ld_checklist','notes','poas','sessions','tasks','workdays'];
  const META = ['dq_office_profile', 'dq_doc_categories'];
  const $ = id => document.getElementById(id);
  const _setItem = Storage.prototype.setItem;
  let applying = false;

  const LS = {
    get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { _setItem.call(localStorage, k, JSON.stringify(v)); }
  };
  const uerr = m => { const e = new Error(m); e.user = true; return e; };
  const netErr = () => { const e = new Error('network'); e.network = true; return e; };
  const validUser = u => /^[a-z0-9._-]{3,30}$/.test(u);
  const arDigits = s => String(s || '').replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));

  let session = LS.get('mk_session', null);
  let me = null;               // الحساب الحالي (نفس شكل dqCurrentAccount)
  let expired = false, lastError = '', pushing = false, syncing = false;
  let pollTimer = null, pushTimer = null;

  /* ---------------- HTTP ---------------- */
  async function api(path, { method = 'GET', body, token, prefer } = {}) {
    const headers = { apikey: CFG.anonKey, 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    else if (String(CFG.anonKey).startsWith('eyJ')) headers.Authorization = 'Bearer ' + CFG.anonKey;
    if (prefer) headers.Prefer = prefer;
    let res;
    try {
      res = await fetch(CFG.url.replace(/\/+$/, '') + path,
        { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) { throw netErr(); }
    const text = await res.text(); let data = null;
    if (text) { try { data = JSON.parse(text); } catch { data = text; } }
    if (!res.ok) {
      const msg = (data && (data.msg || data.message || data.error_description || data.error)) || ('HTTP ' + res.status);
      const e = new Error(msg); e.status = res.status; e.data = data; throw e;
    }
    return data;
  }
  function saveSession(r) {
    const exp = r.expires_at || Math.floor(Date.now() / 1000) + (r.expires_in || 3600);
    session = { access_token: r.access_token, refresh_token: r.refresh_token, expires_at: exp,
      user_id: (r.user && r.user.id) || (session && session.user_id) };
    LS.set('mk_session', session); expired = false;
  }
  async function token() {
    if (!session) throw uerr('لا توجد جلسة. سجّل الدخول وأنت متصل بالإنترنت.');
    if (session.expires_at * 1000 - Date.now() > 60000) return session.access_token;
    if (!navigator.onLine) throw netErr();
    try {
      const r = await api('/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: session.refresh_token } });
      saveSession(r); return session.access_token;
    } catch (e) {
      if (e.status === 400 || e.status === 401 || e.status === 403) { expired = true; setStatus(); }
      throw e;
    }
  }
  async function rest(path, opts = {}) { const t = await token(); return api(path, { ...opts, token: t }); }
  const rpc = (name, args) => rest('/rest/v1/rpc/' + name, { method: 'POST', body: args || {} });

  function friendly(e) {
    if (e && e.user) return e.message;
    if (e && e.network) return 'تعذر الاتصال بالإنترنت.';
    const m = String((e && e.message) || e);
    const map = { forbidden: 'غير مسموح لك بهذه العملية.', not_found: 'الحساب غير موجود.', office_inactive: 'المكتب موقوف.',
      bad_role: 'دور غير صالح.', client_required: 'اربط حساب الموكل بسجل العميل.', bad_username: 'اسم الدخول غير صالح.',
      invalid_target: 'تعذر ربط الحساب الجديد. أعد المحاولة.', profile_exists: 'الحساب موجود بالفعل.',
      username_mismatch: 'اسم الدخول لا يطابق الحساب.' };
    for (const k in map) if (m.includes(k)) return map[k];
    return m;
  }

  /* ---------------- تشفير الدخول الأوفلاين (PBKDF2) ---------------- */
  const b64e = u8 => btoa(String.fromCharCode.apply(null, Array.from(u8)));
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function derive(pw, salt, iter) {
    if (!(window.crypto && crypto.subtle)) throw uerr('المتصفح لا يدعم التشفير المطلوب (يلزم رابط https).');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64d(salt), iterations: iter }, key, 256);
    return b64e(new Uint8Array(bits));
  }
  async function saveOffline(username, password, prof, off) {
    const all = LS.get('mk_offline_auth', {});
    const salt = b64e(crypto.getRandomValues(new Uint8Array(16))), iter = 150000;
    all[username] = { salt, iter, hash: await derive(password, salt, iter), profile: prof,
      office: off ? { id: off.id, name: off.name } : null, savedAt: Date.now() };
    LS.set('mk_offline_auth', all);
  }
  function removeOffline(username) { const a = LS.get('mk_offline_auth', {}); delete a[username]; LS.set('mk_offline_auth', a); }

  /* ---------------- الحساب/المكتب ---------------- */
  const officeId = () => (me && me.role !== 'owner' && me.officeId) || null;
  function toAccount(p) {
    const x = p.extra || {};
    return { id: p.user_id, name: p.full_name, username: p.username, role: p.role,
      permissions: p.role === 'owner' ? DQ_MODULES.map(m => m[0]) : (Array.isArray(p.permissions) ? p.permissions : []),
      clientId: p.client_id || null, active: p.active !== false, officeId: p.office_id || null,
      regNo: x.regNo || '', nationalId: x.nationalId || '', regGrade: x.regGrade || '', createdAt: p.created_at };
  }

  /* ---------------- عزل بيانات الأجهزة بين المكاتب ---------------- */
  const readRaw = k => { try { const v = JSON.parse(localStorage.getItem('dq_' + k)); return Array.isArray(v) ? v : []; } catch { return []; } };
  const hasLocalData = () => COLLS.some(c => readRaw(c).length) || META.some(k => localStorage.getItem(k));
  function wipeLocalData() {
    Object.keys(localStorage).filter(k => k.startsWith('dq_') && k !== 'dq_theme').forEach(k => localStorage.removeItem(k));
    try { if (typeof FileStore !== 'undefined') { if (FileStore.db) FileStore.db.close(); FileStore.db = null; } indexedDB.deleteDatabase('dq_files'); } catch { }
    LS.set('mk_queue', {});
  }
  function queueAll() {
    COLLS.forEach(c => readRaw(c).forEach(it => { if (it && it.id) enqueue(c, it.id, it, false); }));
    META.forEach(k => { const v = localStorage.getItem(k); if (v != null) enqueue('_meta', k, { v }, false); });
  }
  function switchOfficeData(off) {
    const cur = localStorage.getItem('mk_data_office');
    if (cur === off.id) return true;
    const q = LS.get('mk_queue', {});
    if (cur && Object.keys(q).length) throw uerr('توجد تغييرات غير مرفوعة لمكتب آخر على هذا الجهاز. اتصل بالإنترنت وسجّل الدخول بحساب ذلك المكتب أولًا لرفعها.');
    if (cur) wipeLocalData();
    else if (hasLocalData()) {
      if (!confirm('توجد بيانات على هذا الجهاز من الإصدار المحلي.\nموافق = رفعها إلى مكتب «' + off.name + '».\nإلغاء = عدم الدخول الآن (تبقى بياناتك كما هي).')) throw uerr('لم يتم الدخول. خُذ نسخة احتياطية أو اعتمد رفع البيانات.');
      _setItem.call(localStorage, 'mk_data_office', off.id); LS.set('mk_queue', {});
      LS.set('mk_office', { id: off.id, name: off.name }); me && (me.officeId = off.id);
      queueAll(); return true;
    }
    _setItem.call(localStorage, 'mk_data_office', off.id);
    localStorage.removeItem('mk_cursor_' + off.id);
    return true;
  }

  /* ---------------- طابور التغييرات ---------------- */
  function enqueue(c, id, data, deleted) {
    const q = LS.get('mk_queue', {});
    q[c + '|' + id] = { c, id, data: deleted ? {} : data, deleted: !!deleted, ts: Date.now() + Math.random() };
    LS.set('mk_queue', q);
  }
  function diffQueue(c, oldArr, newArr) {
    const om = new Map(oldArr.filter(x => x && x.id).map(x => [x.id, JSON.stringify(x)]));
    const seen = new Set();
    newArr.forEach(x => {
      if (!x || !x.id) return; seen.add(x.id);
      if (om.get(x.id) !== JSON.stringify(x)) enqueue(c, x.id, x, false);
    });
    om.forEach((_, id) => { if (!seen.has(id)) enqueue(c, id, {}, true); });
    schedulePush(); setStatus();
  }
  function hookStorage() {
    const prevSet = DB.set;
    DB.set = function (key, data) {
      const tracked = COLLS.includes(key) && officeId() && !applying;
      if (tracked && Array.isArray(data)) data.forEach(x => { if (x && typeof x === 'object' && !x.id) x.id = DB.uid(); });
      const old = tracked ? readRaw(key) : null;
      const r = prevSet.call(DB, key, data);
      if (tracked) diffQueue(key, old, Array.isArray(data) ? data : []);
      return r;
    };
    Storage.prototype.setItem = function (k, v) {
      _setItem.call(this, k, v);
      if (this === localStorage && !applying && META.includes(k) && officeId()) { enqueue('_meta', k, { v: String(v) }, false); schedulePush(); setStatus(); }
    };
  }

  /* ---------------- الرفع والسحب ---------------- */
  const schedulePush = () => { clearTimeout(pushTimer); pushTimer = setTimeout(() => push(), 1500); };
  async function push() {
    if (pushing || !me || !officeId() || !navigator.onLine || !session || session.user_id !== me.id) return;
    pushing = true;
    try {
      const items = Object.values(LS.get('mk_queue', {}));
      for (let i = 0; i < items.length; i += 100) {
        const chunk = items.slice(i, i + 100), oid = officeId();
        const rows = chunk.map(it => ({ office_id: oid, collection: it.c, id: it.id, data: it.deleted ? {} : it.data, deleted: it.deleted }));
        await rest('/rest/v1/records?on_conflict=office_id,collection,id', { method: 'POST', body: rows, prefer: 'resolution=merge-duplicates,return=minimal' });
        const q2 = LS.get('mk_queue', {});
        chunk.forEach(it => { const k = it.c + '|' + it.id; if (q2[k] && q2[k].ts === it.ts) delete q2[k]; });
        LS.set('mk_queue', q2);
      }
      lastError = '';
    } catch (e) { onSyncError(e); } finally { pushing = false; setStatus(); }
  }
  function applyRows(rows) {
    const q = LS.get('mk_queue', {}); let changed = false;
    const by = {};
    rows.forEach(r => { (by[r.collection] = by[r.collection] || []).push(r); });
    applying = true;
    try {
      Object.keys(by).forEach(c => {
        if (c === '_meta') {
          by[c].forEach(r => { if (q['_meta|' + r.id] || !META.includes(r.id) || r.deleted) return;
            const v = r.data && r.data.v; if (v != null && localStorage.getItem(r.id) !== v) { _setItem.call(localStorage, r.id, v); changed = true; } });
          return;
        }
        if (!COLLS.includes(c)) return;
        let arr = readRaw(c); const idx = new Map(arr.map((x, i) => [x && x.id, i])); let dirty = false;
        by[c].forEach(r => {
          if (q[c + '|' + r.id]) return;                    // تغيير محلي لم يُرفع بعد: نحتفظ به
          const i = idx.get(r.id);
          if (r.deleted) { if (i !== undefined) { arr[i] = null; dirty = true; } }
          else if (i !== undefined) { if (JSON.stringify(arr[i]) !== JSON.stringify(r.data)) { arr[i] = r.data; dirty = true; } }
          else { arr.push(r.data); idx.set(r.id, arr.length - 1); dirty = true; }
        });
        if (dirty) { arr = arr.filter(Boolean); _setItem.call(localStorage, 'dq_' + c, JSON.stringify(arr)); changed = true; }
      });
    } finally { applying = false; }
    return changed;
  }
  async function pull() {
    const oid = officeId(); if (!oid || !navigator.onLine || !session || session.user_id !== me.id) return;
    let cursor = localStorage.getItem('mk_cursor_' + oid) || '1970-01-01T00:00:00Z', changed = false;
    try {
      for (let guard = 0; guard < 200; guard++) {
        const rows = await rest('/rest/v1/records?office_id=eq.' + oid + '&updated_at=gte.' + encodeURIComponent(cursor) +
          '&order=updated_at.asc,collection.asc,id.asc&limit=1000&select=collection,id,data,deleted,updated_at');
        if (!rows.length) break;
        if (applyRows(rows)) changed = true;
        const last = rows[rows.length - 1].updated_at;
        if (rows.length < 1000 || last === cursor) { cursor = last; break; }
        cursor = last;
      }
      _setItem.call(localStorage, 'mk_cursor_' + oid, cursor); lastError = '';
      if (changed) rerender();
    } catch (e) { onSyncError(e); }
  }
  async function syncMembers() {
    const oid = officeId(); if (!oid || !navigator.onLine || !session || session.user_id !== me.id) return;
    try {
      const rows = await rest('/rest/v1/profiles?office_id=eq.' + oid + '&select=*&order=created_at.asc');
      const accts = rows.map(toAccount);
      applying = true; _setItem.call(localStorage, 'dq_local_accounts', JSON.stringify(accts)); applying = false;
      const mine = accts.find(a => a.id === me.id);
      if (!mine || mine.active === false) { alert('تم إيقاف حسابك أو حذفه من قبل مدير المكتب.'); removeOffline(me.username); dqLogout(); return; }
      const permsChanged = JSON.stringify(mine.permissions) !== JSON.stringify(me.permissions) || mine.role !== me.role;
      Object.assign(me, mine);
      if (typeof dqCurrentAccount !== 'undefined' && dqCurrentAccount) { Object.assign(dqCurrentAccount, mine); if (permsChanged) refreshNav(); }
    } catch (e) { onSyncError(e); }
  }
  async function syncAll() {
    if (syncing || !me || !officeId()) return; syncing = true;
    try { await push(); await pull(); await syncMembers(); } finally { syncing = false; setStatus(); }
  }
  function onSyncError(e) {
    if (e && e.network) { lastError = ''; return; }
    if (e && (e.status === 401 || e.status === 403) && /jwt|expired|token/i.test(e.message || '')) expired = true;
    lastError = (e && e.message) || 'خطأ';
    console.warn('[mk sync]', e && e.message, e && e.stack);
  }
  function rerender() {
    const a = document.activeElement;
    if (a && /INPUT|TEXTAREA|SELECT/.test(a.tagName)) return;
    const p = document.querySelector('.page.active');
    if (p && typeof showPage === 'function') { try { showPage(p.id.replace('page-', '')); } catch { } }
  }
  function refreshNav() {
    document.querySelectorAll('.nav-item[data-page]').forEach(b => { b.style.display = dqHasPerm(b.dataset.page) ? 'flex' : 'none'; });
    document.querySelectorAll('.nav-section').forEach(sec => {
      let n = sec.nextElementSibling, any = false;
      while (n && !n.classList.contains('nav-section')) { if (n.classList.contains('nav-item') && n.style.display !== 'none') any = true; n = n.nextElementSibling; }
      sec.style.display = any ? 'block' : 'none';
    });
    const acc = $('dqAccountsNav'); if (acc) acc.style.display = ['owner', 'manager'].includes(me.role) ? 'flex' : 'none';
  }

  /* ---------------- مؤشر الحالة ---------------- */
  function ensurePill() {
    if ($('mkPill')) return;
    const d = document.createElement('div'); d.id = 'mkPill';
    d.style.cssText = 'position:fixed;bottom:12px;left:12px;z-index:90;background:rgba(11,31,51,.93);color:#fff;font-size:12px;padding:6px 11px;border-radius:999px;cursor:pointer;direction:rtl;box-shadow:0 2px 10px rgba(0,0,0,.25)';
    d.onclick = () => { if (expired) alert('انتهت الجلسة. اخرج ثم سجّل الدخول وأنت متصل بالإنترنت لإكمال المزامنة.'); else syncAll(); };
    document.body.appendChild(d);
  }
  function setStatus() {
    const d = $('mkPill'); if (!d) return;
    if (!me || !officeId()) { d.style.display = 'none'; return; }
    d.style.display = 'block';
    const n = Object.keys(LS.get('mk_queue', {})).length;
    d.textContent = expired ? '🔒 سجّل الدخول متصلًا لإكمال المزامنة'
      : !navigator.onLine ? '📴 غير متصل' + (n ? ' · ' + n + ' بانتظار الرفع' : '')
      : lastError ? '⚠️ تعذرت المزامنة' + (n ? ' (' + n + ')' : '')
      : n ? '⏳ جارٍ الرفع (' + n + ')' : '☁️ متزامن';
  }
  function startSync() {
    stopSync(); ensurePill(); setStatus();
    pollTimer = setInterval(() => { if (!document.hidden) syncAll(); }, 20000);
    syncAll();
  }
  function stopSync() { clearInterval(pollTimer); clearTimeout(pushTimer); pollTimer = null; }
  window.addEventListener('online', () => { setStatus(); syncAll(); });
  window.addEventListener('offline', setStatus);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) syncAll(); });

  /* ---------------- شاشة الدخول ---------------- */
  const origInit = window.dqInitAuth, origSubmit = window.dqSubmitAuth, origEnter = window.dqEnterApp, origLogout = window.dqLogout;
  const F = (id, label, extra) => '<div class="form-group"><label>' + label + '</label><input id="' + id + '" ' + extra + ' /></div>';
  function gate(mode) {
    const link = (m, t) => '<div style="text-align:center;margin-top:12px"><a href="#" onclick="mkGate(\'' + m + '\');return false">' + t + '</a></div>';
    if (mode === 'register') {
      dqSetGate('إنشاء حساب مدير مكتب', 'سيُنشأ مكتب جديد بياناته وحساباته منفصلة تمامًا عن باقي المكاتب، وحسابك هو حساب المدير. هذه الخطوة تحتاج إنترنت.',
        F('mkOfficeName', 'اسم المكتب', 'required placeholder="مثال: مكتب الأستاذ ..."') +
        F('dqAuthName', 'اسم المدير', 'required autocomplete="name"') +
        F('dqAuthUsername', 'اسم الدخول (إنجليزي: حروف وأرقام)', 'required dir="ltr" autocapitalize="none" autocomplete="username" placeholder="مثال: ahmed.law"') +
        F('dqAuthPassword', 'كلمة المرور (8 أحرف على الأقل)', 'type="password" required autocomplete="new-password"') +
        F('dqAuthPassword2', 'تأكيد كلمة المرور', 'type="password" required autocomplete="new-password"') +
        link('login', 'لدي حساب بالفعل — تسجيل الدخول'), 'إنشاء المكتب');
      $('dqAuthForm').dataset.mode = 'mk-register';
    } else {
      dqSetGate('تسجيل الدخول', 'أدخل اسم الدخول وكلمة المرور. يعمل الدخول بدون إنترنت على الأجهزة التي سجّلت منها الدخول مسبقًا.',
        F('dqAuthUsername', 'اسم الدخول', 'required dir="ltr" autocapitalize="none" autocomplete="username"') +
        F('dqAuthPassword', 'كلمة المرور', 'type="password" required autocomplete="current-password"') +
        link('register', 'إنشاء مكتب جديد (مدير مكتب)'), 'دخول');
      $('dqAuthForm').dataset.mode = 'mk-login';
    }
  }
  window.mkGate = gate;
  window.dqInitAuth = function () {
    gate(Object.keys(LS.get('mk_offline_auth', {})).length ? 'login' : 'register');
  };
  window.dqSubmitAuth = async function (ev) {
    ev.preventDefault();
    const mode = $('dqAuthForm').dataset.mode;
    if (mode !== 'mk-login' && mode !== 'mk-register') return origSubmit(ev);
    const btn = $('dqAuthSubmit'), label = btn.textContent; btn.disabled = true; btn.textContent = 'جارٍ المعالجة…';
    try { if (mode === 'mk-register') await register(); else await login(); }
    catch (e) { if (!(e && (e.user || e.network))) console.error(e); alert(friendly(e)); }
    finally { btn.disabled = false; btn.textContent = label; }
    return false;
  };

  async function login() {
    const username = ($('dqAuthUsername').value || '').trim().toLowerCase(), password = $('dqAuthPassword').value || '';
    if (!validUser(username) || !password) throw uerr('أدخل اسم الدخول وكلمة المرور.');
    let r;
    try { r = await api('/auth/v1/token?grant_type=password', { method: 'POST', body: { email: username + DOMAIN, password } }); }
    catch (e) {
      if (e.network) return offlineLogin(username, password);
      if (e.status === 400 || e.status === 401 || e.status === 422) throw uerr('بيانات الدخول غير صحيحة.');
      throw e;
    }
    await finishLogin(r, username, password);
  }
  async function offlineLogin(username, password) {
    const rec = LS.get('mk_offline_auth', {})[username];
    if (!rec) throw uerr('لا يمكن الدخول بدون إنترنت لأول مرة على هذا الجهاز. اتصل بالإنترنت وسجّل الدخول مرة واحدة.');
    if (await derive(password, rec.salt, rec.iter) !== rec.hash) throw uerr('بيانات الدخول غير صحيحة.');
    await enter(rec.profile, rec.office, true);
  }
  async function register() {
    const office = ($('mkOfficeName').value || '').trim(), name = ($('dqAuthName').value || '').trim();
    const username = ($('dqAuthUsername').value || '').trim().toLowerCase();
    const pw = $('dqAuthPassword').value || '', pw2 = $('dqAuthPassword2').value || '';
    if (office.length < 2 || !name) throw uerr('أكمل اسم المكتب واسم المدير.');
    if (!validUser(username)) throw uerr('اسم الدخول: حروف إنجليزية صغيرة وأرقام ونقطة وشرطة فقط (من 3 إلى 30).');
    if (pw.length < 8) throw uerr('كلمة المرور 8 أحرف على الأقل.');
    if (pw !== pw2) throw uerr('كلمتا المرور غير متطابقتين.');
    if (!navigator.onLine) throw uerr('إنشاء مكتب جديد يحتاج اتصالًا بالإنترنت.');
    const email = username + DOMAIN; let r;
    try { r = await api('/auth/v1/signup', { method: 'POST', body: { email, password: pw } }); }
    catch (e) {
      if (e.network) throw e;
      if (e.status === 422 || /registered|already/i.test(e.message)) {
        try { r = await api('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password: pw } }); }
        catch { throw uerr('اسم الدخول مستخدم بالفعل، اختر اسمًا آخر.'); }
      } else throw e;
    }
    if (!r || !r.access_token) throw uerr('إعداد Supabase: عطّل خيار «Confirm email» من Authentication ← Providers ← Email ثم أعد المحاولة.');
    saveSession(r);
    const exist = await api('/rest/v1/profiles?user_id=eq.' + r.user.id + '&select=user_id', { token: r.access_token });
    if (exist.length) throw uerr('هذا الحساب موجود بالفعل. استخدم «تسجيل الدخول».');
    await api('/rest/v1/rpc/create_office', { method: 'POST', token: r.access_token,
      body: { p_office_name: office, p_full_name: name, p_username: username, p_permissions: DQ_MODULES.map(m => m[0]) } });
    await finishLogin(r, username, pw);
  }
  async function finishLogin(r, username, password) {
    saveSession(r);
    const tok = r.access_token, uid = r.user.id;
    const prof = (await api('/rest/v1/profiles?user_id=eq.' + uid + '&select=*', { token: tok }))[0];
    if (!prof) throw uerr('هذا الحساب غير مكتمل. إن كنت مدير مكتب جديدًا فاستخدم «إنشاء مكتب جديد» بنفس البيانات.');
    if (prof.active === false) { removeOffline(username); throw uerr('هذا الحساب موقوف. تواصل مع مدير المكتب.'); }
    let office = null;
    if (prof.role !== 'owner') {
      office = (await api('/rest/v1/offices?id=eq.' + prof.office_id + '&select=*', { token: tok }))[0];
      if (!office || office.active === false) { removeOffline(username); throw uerr('المكتب موقوف. تواصل مع مالك النظام.'); }
    }
    await saveOffline(username, password, prof, office);
    await enter(prof, office, false);
  }
  async function enter(prof, office, offline) {
    const acct = toAccount(prof);
    me = acct;
    if (office) {
      switchOfficeData(office);
      LS.set('mk_office', { id: office.id, name: office.name });
      acct.officeId = office.id;
    }
    dqCurrentAccount = Object.assign({}, acct);
    if (office && !offline) {
      $('dqAuthMessage').textContent = 'جارٍ تحميل بيانات المكتب…';
      try { await Promise.race([syncAll(), new Promise(res => setTimeout(res, 15000))]); } catch { }
    }
    dqEnterApp();
    if (office) startSync();
  }

  window.dqEnterApp = function () {
    origEnter();
    if (dqCurrentAccount && dqCurrentAccount.role === 'owner') {
      document.querySelectorAll('.nav-item[data-page]').forEach(b => { b.style.display = b.dataset.page === 'accounts' ? 'flex' : 'none'; });
      document.querySelectorAll('.nav-section').forEach(s => { s.style.display = 'none'; });
      showPage('accounts');
    }
  };
  window.dqLogout = function () {
    if (me && officeId()) { syncAll().catch(() => { }); }
    stopSync(); me = null; origLogout(); setStatus();
  };

  /* ---------------- إدارة الحسابات (المدير) ---------------- */
  const _rda = window.renderDQAccounts;
  window.renderDQAccounts = function () {
    const u = dqCurrentAccount;
    if (u && u.role === 'owner') return renderOwner();
    _rda.apply(this, arguments);
    if (!u || u.role !== 'manager') return;
    const sel = $('dqAccRole');
    if (sel && !sel.querySelector('option[value="client"]')) {
      const o = document.createElement('option'); o.value = 'client'; o.textContent = 'موكل'; sel.appendChild(o);
      const ed = dqAccounts().find(x => x.id === dqEditingAccountId);
      if (ed) sel.value = ed.role;
      dqRenderClientLink((ed && ed.clientId) || ''); dqRenderPermEditor((ed && ed.permissions) || dqDefaultPerms(sel.value));
    }
    if (dqEditingAccountId) {
      const un = $('dqAccUsername'); if (un) un.disabled = true;
      const pw = $('dqAccPassword'); if (pw) { pw.required = false; const g = pw.closest('.form-group'); if (g) g.style.display = 'none'; }
    }
    document.querySelectorAll('.dq-user-row').forEach(row => {
      if (row.querySelector('.mk-del')) return;
      const m = /dqEditAccount\('([^']+)'\)/.exec(row.innerHTML); if (!m) return;
      const box = row.lastElementChild; if (!box) return;
      const b = document.createElement('button'); b.className = 'btn btn-danger btn-sm mk-del'; b.textContent = 'حذف';
      b.onclick = () => dqDeleteAccount(m[1]); box.appendChild(b);
    });
  };
  window.dqSaveAccount = async function (id) {
    const g = i => ($(i) || {}).value || '', cur = dqCurrentAccount;
    if (!cur || cur.role !== 'manager') return alert('إدارة الحسابات لمدير المكتب فقط.');
    const name = g('dqAccName').trim(), username = g('dqAccUsername').trim().toLowerCase(), password = g('dqAccPassword'), role = g('dqAccRole') || 'lawyer';
    if (!name || !username) return alert('أدخل الاسم واسم الدخول.');
    if (!validUser(username)) return alert('اسم الدخول: حروف إنجليزية صغيرة وأرقام ونقطة وشرطة فقط (من 3 إلى 30).');
    if (!['lawyer', 'client'].includes(role)) return alert('يمكنك إنشاء حسابات المحامين والموكلين فقط.');
    if (!id && password.length < 8) return alert('كلمة المرور يجب ألا تقل عن 8 أحرف.');
    const clientId = role === 'client' ? g('dqAccClientId') : '';
    if (role === 'client' && !clientId) return alert('اربط حساب الموكل بسجل العميل الخاص به.');
    const nid = arDigits(g('dqLawNid')).replace(/\s/g, '');
    if (role === 'lawyer' && nid && !/^\d{14}$/.test(nid)) return alert('الرقم القومي يجب أن يكون 14 رقمًا.');
    if (!navigator.onLine) return alert('إنشاء الحسابات وتعديلها يحتاج اتصالًا بالإنترنت.');
    const perms = Array.from(document.querySelectorAll('.dqPermCheck:checked')).map(c => c.value);
    const extra = role === 'lawyer' ? { regNo: g('dqLawNo').trim(), nationalId: nid, regGrade: g('dqLawGrade') } : {};
    try {
      let newId = id;
      if (!id) {
        let r;
        try { r = await api('/auth/v1/signup', { method: 'POST', body: { email: username + DOMAIN, password } }); }
        catch (e) { if (!e.network && (e.status === 422 || /registered|already/i.test(e.message))) return alert('اسم الدخول مستخدم بالفعل، اختر اسمًا آخر.'); throw e; }
        if (!r || !r.access_token) return alert('إعداد Supabase: عطّل خيار «Confirm email» ثم أعد المحاولة.');
        newId = r.user.id;
        await rpc('add_member', { p_user_id: newId, p_username: username, p_full_name: name, p_role: role, p_permissions: perms, p_client_id: clientId || null, p_extra: extra });
      } else {
        const ex = dqAccounts().find(x => x.id === id) || {};
        await rpc('update_member', { p_user_id: id, p_full_name: name, p_permissions: perms, p_client_id: clientId || null, p_extra: extra, p_active: ex.active !== false });
      }
      if (role === 'lawyer') {
        const nt = v => String(v || '').trim().toLocaleLowerCase('ar'); const ts = DB.get('tasks'); let ch = false;
        ts.forEach(t => { if (!t.assignedAccountId && t.assignee && (nt(t.assignee) === nt(name) || nt(t.assignee).includes(nt(name)) || nt(name).includes(nt(t.assignee)))) { t.assignedAccountId = newId; t.assignee = name; t.updatedAt = new Date().toISOString(); ch = true; } });
        if (ch) DB.set('tasks', ts);
      }
      try { const lg = JSON.parse(localStorage.getItem('dq_activity_log') || '[]'); lg.unshift({ id: DB.uid(), at: new Date().toISOString(), accountId: cur.id, accountName: cur.name, role: cur.role, section: 'accounts', operation: id ? 'تعديل حساب' : 'إنشاء حساب', targetName: name }); localStorage.setItem('dq_activity_log', JSON.stringify(lg.slice(0, 1000))); } catch { }
      await syncMembers(); dqEditingAccountId = null; renderDQAccounts();
      alert(id ? 'تم حفظ التعديلات.' : 'تم إنشاء الحساب. سلّم اسم الدخول وكلمة المرور لصاحبه؛ يستطيع تغيير كلمة المرور بعد الدخول.');
    } catch (e) { console.error(e); alert(friendly(e)); }
  };
  window.dqToggleAccount = async function (id) {
    const u = dqAccounts().find(x => x.id === id); if (!u) return;
    if (!navigator.onLine) return alert('هذه العملية تحتاج اتصالًا بالإنترنت.');
    try {
      await rpc('update_member', { p_user_id: id, p_full_name: u.name, p_permissions: u.permissions, p_client_id: u.clientId || null,
        p_extra: { regNo: u.regNo || '', nationalId: u.nationalId || '', regGrade: u.regGrade || '' }, p_active: u.active === false });
      await syncMembers(); renderDQAccounts();
    } catch (e) { alert(friendly(e)); }
  };
  window.dqDeleteAccount = async function (id) {
    if (!confirm('حذف هذا الحساب نهائيًا؟ لن تُحذف بيانات القضايا.')) return;
    if (!navigator.onLine) return alert('هذه العملية تحتاج اتصالًا بالإنترنت.');
    try { await rpc('delete_member', { p_user_id: id }); await syncMembers(); renderDQAccounts(); } catch (e) { alert(friendly(e)); }
  };
  window.dqResetAccountPassword = function () {
    alert('لا يستطيع المدير رؤية كلمة مرور أحد أو تغييرها مباشرة (حماية للحسابات).\nإذا نسي أحدهم كلمة المرور: احذف حسابه وأنشئه من جديد، أو يغيّرها هو من الإعدادات بعد دخوله.');
  };
  window.dqChangeOwnPassword = async function () {
    if (!dqCurrentAccount) return;
    const oldP = ($('dqOwnOldPassword') || {}).value || '', newP = ($('dqOwnNewPassword') || {}).value || '';
    if (newP.length < 8) return alert('كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف.');
    if (!navigator.onLine) return alert('تغيير كلمة المرور يحتاج اتصالًا بالإنترنت.');
    try {
      let r;
      try { r = await api('/auth/v1/token?grant_type=password', { method: 'POST', body: { email: dqCurrentAccount.username + DOMAIN, password: oldP } }); }
      catch (e) { if (e.network) throw e; return alert('كلمة المرور الحالية غير صحيحة.'); }
      await api('/auth/v1/user', { method: 'PUT', token: r.access_token, body: { password: newP } });
      saveSession(r);
      const a = LS.get('mk_offline_auth', {})[dqCurrentAccount.username];
      await saveOffline(dqCurrentAccount.username, newP, a ? a.profile : toRaw(dqCurrentAccount), a && a.office);
      $('dqOwnOldPassword').value = ''; $('dqOwnNewPassword').value = '';
      alert('تم تغيير كلمة المرور.');
    } catch (e) { alert(friendly(e)); }
  };
  const toRaw = a => ({ user_id: a.id, office_id: a.officeId, username: a.username, full_name: a.name, role: a.role, permissions: a.permissions, client_id: a.clientId, active: a.active, extra: { regNo: a.regNo, nationalId: a.nationalId, regGrade: a.regGrade } });

  /* ---------------- لوحة المالك: المكاتب ---------------- */
  async function renderOwner() {
    const wrap = $('dqAccountFormWrap'), list = $('dqAccountsList'), log = $('dqActivityLog');
    if (!wrap || !list) return;
    if (log) log.innerHTML = '';
    wrap.innerHTML = '<h3 style="margin-bottom:8px">المكاتب المسجلة</h3><p class="dq-auth-note">كل مكتب معزول عن الآخر، ولا يظهر لك محتوى قضاياه. يمكنك إيقاف مكتب أو إعادة تفعيله.</p>';
    list.innerHTML = '<p>جارٍ التحميل…</p>';
    try {
      const [offs, profs] = await Promise.all([
        rest('/rest/v1/offices?select=*&order=created_at.desc'),
        rest('/rest/v1/profiles?select=office_id,full_name,username,role,active')]);
      const esc = dqEsc;
      list.innerHTML = offs.length ? offs.map(o => {
        const mem = profs.filter(p => p.office_id === o.id), mgr = mem.find(p => p.role === 'manager');
        return '<div class="dq-user-row"><div><strong>' + esc(o.name) + '</strong><div class="dq-user-meta">المدير: ' + esc(mgr ? mgr.full_name + ' (' + mgr.username + ')' : '—') +
          ' · ' + mem.length + ' حساب · ' + (o.active ? 'نشط' : 'موقوف') + ' · ' + new Date(o.created_at).toLocaleDateString('ar-EG') + '</div></div>' +
          '<div><button class="btn btn-outline btn-sm" onclick="mkToggleOffice(\'' + o.id + '\',' + (!o.active) + ')">' + (o.active ? 'إيقاف' : 'تفعيل') + '</button></div></div>';
      }).join('') : '<p style="color:var(--text-muted)">لا توجد مكاتب بعد.</p>';
    } catch (e) { list.innerHTML = '<p>' + dqEsc(friendly(e)) + '</p>'; }
  }
  window.mkToggleOffice = async function (id, active) {
    try { await rpc('set_office_active', { p_office_id: id, p_active: active }); renderOwner(); } catch (e) { alert(friendly(e)); }
  };

  /* ---------------- تشغيل ---------------- */
  hookStorage();
  document.removeEventListener('DOMContentLoaded', origInit);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => window.dqInitAuth());
  else window.dqInitAuth();
  window.MK = { diffQueue, enqueue, applyRows, push, pull, syncAll, derive, saveOffline, offlineLogin };
})();
