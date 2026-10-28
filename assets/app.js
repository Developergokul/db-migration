(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let looping = false, poller = null, tableNames = null;

  async function api(action, body = {}) {
    const res = await fetch('api.php?action=' + action, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': MIG.csrf },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({ error: 'Invalid server response (HTTP ' + res.status + ')' }));
    if (!res.ok || data.error) throw new Error(data.error || 'HTTP ' + res.status);
    return data;
  }

  const fmtBytes = b => {
    if (b == null) return '–';
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(i ? 2 : 0) + ' ' + u[i];
  };
  const fmtTime = s => {
    if (s == null) return '–';
    const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + x + 's';
  };

  /* ---------- credentials ---------- */
  function fillForm(cfg) {
    for (const side of ['local', 'remote']) {
      const box = $(`[data-side=${side}]`);
      for (const el of box.querySelectorAll('input[name]')) {
        if (el.name === 'pass') { el.value = ''; el.placeholder = cfg[side].has_pass ? '•••••••• (saved – leave blank to keep)' : ''; }
        else if (el.type === 'checkbox') el.checked = !!+cfg[side][el.name];
        else el.value = cfg[side][el.name] ?? '';
      }
    }
  }
  function readForm() {
    const out = {};
    for (const side of ['local', 'remote']) {
      out[side] = {};
      for (const el of $(`[data-side=${side}]`).querySelectorAll('input[name]'))
        out[side][el.name] = el.type === 'checkbox' ? el.checked : el.value;
    }
    return out;
  }

  document.querySelectorAll('[data-test]').forEach(btn => btn.addEventListener('click', async () => {
    const side = btn.dataset.test, out = btn.parentElement.querySelector('.test-result');
    out.className = 'test-result muted'; out.textContent = 'Connecting…'; btn.disabled = true;
    try {
      const r = await api('test', { ...readForm(), side });
      out.className = 'test-result ok'; out.textContent = `Connected – MySQL ${r.version}, ${r.tables} tables`;
    } catch (e) { out.className = 'test-result bad'; out.textContent = e.message; }
    btn.disabled = false;
  }));

  $('#saveBtn').addEventListener('click', async () => {
    try { const r = await api('save', readForm()); fillForm(r.config); $('#saveMsg').textContent = 'Saved (encrypted).'; }
    catch (e) { $('#saveMsg').textContent = e.message; }
  });

  /* ---------- table picker ---------- */
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const scope = () => document.querySelector('[name=scope]:checked').value;
  async function loadTables() {
    $('#loadTables').disabled = true;
    try {
      await api('save', readForm());
      const r = await api('tables');
      $('#tableList').innerHTML = r.tables.map(t =>
        `<label data-n="${esc(t.name.toLowerCase())}"><input type="checkbox" class="tb" value="${esc(t.name)}"> ${esc(t.name)}
         <span class="muted">${t.type === 'view' ? 'view' : fmtBytes(t.bytes)}</span></label>`).join('');
      $('#allTables').checked = false; updateCount();
    } catch (e) { showBanner(e.message, 'bad'); }
    $('#loadTables').disabled = false;
  }
  const selected = () => scope() === 'all' ? null : [...document.querySelectorAll('.tb:checked')].map(c => c.value);
  function updateCount() { $('#tableCount').textContent = document.querySelectorAll('.tb:checked').length + ' selected'; }
  document.querySelectorAll('[name=scope]').forEach(r => r.addEventListener('change', () => {
    $('#tablePicker').hidden = scope() === 'all';
    if (scope() === 'selected' && !document.querySelector('.tb')) loadTables();
  }));
  $('#loadTables').addEventListener('click', loadTables);
  $('#allTables').addEventListener('change', e => { document.querySelectorAll('.tablelist .tb').forEach(c => { if (!c.closest('label').hidden) c.checked = e.target.checked; }); updateCount(); });
  $('#tableList').addEventListener('change', updateCount);
  $('#tableFilter').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('#tableList label').forEach(l => l.hidden = !l.dataset.n.includes(q));
  });

  /* ---------- rendering ---------- */
  function showBanner(msg, cls) { const b = $('#banner'); b.hidden = !msg; b.className = 'alert ' + (cls || ''); b.textContent = msg || ''; }

  function render(r) {
    const s = r.stats || {}, st = r.status || 'idle', live = st === 'running' && !r.interrupted;
    $('#pill').textContent = r.interrupted ? 'interrupted' : st;
    $('#pill').className = 'pill ' + (r.interrupted ? 'paused' : st);
    const pct = s.percent ?? 0;
    $('#barFill').style.width = pct + '%'; $('#barText').textContent = pct.toFixed(1) + '%';
    $('#sDone').textContent = fmtBytes(s.bytes_done); $('#sLeft').textContent = fmtBytes(s.bytes_left);
    $('#sTotal').textContent = fmtBytes(s.bytes_total);
    $('#sSpeed').textContent = live && s.speed ? fmtBytes(s.speed) + '/s' : '–';
    $('#sEta').textContent = st === 'completed' ? 'done' : (live ? fmtTime(s.eta) : '–');
    $('#sElapsed').textContent = fmtTime(s.elapsed);
    $('#sTables').textContent = s.tables_total ? `${s.tables_done} / ${s.tables_total}` : '–';
    $('#sCurrent').textContent = live ? (s.current || '–') : '–';
    $('#perTable').innerHTML = (s.tables || []).map(t => `<div class="it"><span>${esc(t[0])}</span><span class="muted">${t[1] === 'done' ? '✔ 100%' : t[2] + '%'}</span></div>`).join('');

    const lg = $('#log'), atEnd = lg.scrollTop + lg.clientHeight >= lg.scrollHeight - 20;
    lg.innerHTML = (r.log || []).map(l => `<div class="${l.l}">${new Date(l.t * 1000).toLocaleTimeString()}  ${esc(l.m)}</div>`).join('');
    if (atEnd) lg.scrollTop = lg.scrollHeight;

    const idle = ['idle', 'completed'].includes(st);
    $('#btnStart').disabled = live;
    $('#btnPause').disabled = !live;
    $('#btnResume').disabled = !(st === 'paused' || st === 'failed' || st === 'cancelled' || r.interrupted);
    $('#btnCancel').disabled = !(st === 'running' || st === 'paused' || st === 'failed');
    if (st === 'completed') showBanner('Migration completed successfully.', 'good');
    else if (st === 'failed') showBanner('Failed: ' + (r.error || 'unknown error') + ' — fix the cause and press Resume to continue from the last batch.', 'bad');
    else if (r.interrupted) showBanner('Transfer was interrupted (browser closed or server stopped). Press Resume to continue from the last committed batch.', 'warn');
    else if (st === 'cancelled') showBanner('Cancelled. Progress is kept – Resume to continue, or tick "Start fresh" and Start to redo everything.', 'warn');
    else showBanner('');
  }

  /* ---------- driver loop: each request does one time-boxed chunk of work ---------- */
  async function loop() {
    if (looping) return; looping = true; stopPoll();
    let errs = 0;
    while (true) {
      let r;
      try { r = await api('step'); errs = 0; }
      catch (e) {
        if (++errs > 8) { showBanner('Connection lost: ' + e.message + ' — press Resume to retry.', 'bad'); break; }
        showBanner('Server not responding, retrying… (' + e.message + ')', 'warn');
        await sleep(Math.min(5000, 600 * errs)); continue;
      }
      render(r);
      if (r.status !== 'running') break;
      if (r.busy) await sleep(1000);
    }
    looping = false; refresh();
  }
  async function refresh() {
    try { const r = await api('status'); render(r); if (r.status === 'running' && !r.interrupted && !looping) startPoll(); } catch (e) { /* ignore */ }
  }
  function startPoll() { if (!poller) poller = setInterval(refresh, 2000); }
  function stopPoll() { clearInterval(poller); poller = null; }

  async function act(name, body) {
    try { const r = await api(name, body); render(r); return r; } catch (e) { showBanner(e.message, 'bad'); }
  }
  $('#btnStart').addEventListener('click', async () => {
    await api('save', readForm()).catch(() => {});
    const sel = selected();
    if (sel && !sel.length) { showBanner('Select at least one table.', 'warn'); return; }
    const r = await act('start', {
      tables: selected(),
      options: { fresh: $('#optFresh').checked, drop: $('#optDrop').checked, views: $('#optViews').checked }
    });
    $('#optFresh').checked = false;
    if (r && r.status === 'running') loop();
  });
  $('#btnPause').addEventListener('click', () => act('pause'));
  $('#btnResume').addEventListener('click', async () => { const r = await act('resume'); if (r && r.status === 'running') loop(); });
  $('#btnCancel').addEventListener('click', () => { if (confirm('Cancel the transfer? Progress is kept and can be resumed later.')) act('cancel'); });

  /* ---------- database comparison ---------- */
  const TYPES = ['table', 'view', 'column', 'index', 'foreign key', 'trigger', 'routine', 'event', 'row count'];
  const STATUS = { only_local: ['Only on local (missing on remote)', 'warn'], only_remote: ['Only on remote (missing on local)', 'bad'], different: ['Different', 'diff'] };
  $('#btnDiff').addEventListener('click', async () => {
    const out = $('#diffOut'), btn = $('#btnDiff');
    btn.disabled = true; out.innerHTML = '<p class="muted">Comparing… this can take a while with row counts on large databases.</p>';
    try {
      await api('save', readForm());
      const r = await api('diff', { counts: $('#diffCounts').checked });
      const i = r.info, f = r.findings;
      let h = `<p class="muted small">Local <b>${esc(i.local)}</b>: ${i.tables_local} tables, ${i.views_local} views, ${i.triggers_local} triggers, ${i.routines_local} routines, ${i.events_local} events &nbsp;·&nbsp; Remote <b>${esc(i.remote)}</b>: ${i.tables_remote} tables, ${i.views_remote} views, ${i.triggers_remote} triggers, ${i.routines_remote} routines, ${i.events_remote} events</p>`;
      if (!f.length) h += '<div class="alert good">No differences found — structure matches' + (i.row_counts ? ' and row counts are equal.' : '.') + '</div>';
      else {
        h += `<div class="alert warn">${f.length} difference${f.length > 1 ? 's' : ''} found.</div>`;
        for (const t of TYPES) {
          const items = f.filter(x => x.type === t); if (!items.length) continue;
          h += `<details open><summary><b>${esc(t)}</b> <span class="muted">(${items.length})</span></summary><div class="difflist">` +
            items.map(x => `<div class="di"><span class="tag ${STATUS[x.status][1]}">${STATUS[x.status][0]}</span><code>${esc(x.name)}</code>${x.detail ? `<div class="muted small">${esc(x.detail)}</div>` : ''}</div>`).join('') +
            '</div></details>';
        }
      }
      out.innerHTML = h; btn.textContent = '↻ Refresh';
    } catch (e) { out.innerHTML = `<div class="alert bad">${esc(e.message)}</div>`; }
    btn.disabled = false;
  });

  $('#btnRefresh').addEventListener('click', async () => { const b = $('#btnRefresh'); b.disabled = true; await refresh(); b.disabled = false; });

  document.querySelectorAll('[data-clear]').forEach(btn => btn.addEventListener('click', async () => {
    const side = btn.dataset.clear;
    if (!confirm(`Clear the saved ${side} database details (host, database, user, password)?`)) return;
    try {
      const r = await api('clear', { side }); fillForm(r.config);
      btn.parentElement.querySelector('.test-result').textContent = ''; $('#saveMsg').textContent = side + ' details cleared.';
      if (side === 'local') { $('#tableList').innerHTML = ''; $('#diffOut').innerHTML = ''; }
    } catch (e) { $('#saveMsg').textContent = e.message; }
  }));
  $('#btnClearJob').addEventListener('click', async () => {
    if (!confirm('Clear the last transfer status and log from this screen? (Saved progress on the remote server is kept; tick "Start fresh" to redo everything.)')) return;
    try { render(await api('clearjob')); } catch (e) { showBanner(e.message, 'bad'); }
  });

  /* ---------- init ---------- */
  api('config').then(r => fillForm(r.config)).catch(e => showBanner(e.message, 'bad'));
  refresh();
})();
