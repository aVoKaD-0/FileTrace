function setStatus(msg) {
  const el = document.getElementById('status');
  if (el) el.textContent = msg || '';

  // Best-effort persist last status
  try {
    chrome.storage?.local?.set({ ft_last_status: String(msg || '') });
  } catch (_) {}
}

function appendLog(msg) {
  const el = document.getElementById('status');
  if (!el) return;
  const ts = new Date().toLocaleTimeString();
  const line = `[${ts}] ${String(msg || '')}`;
  el.textContent = (el.textContent ? (el.textContent + '\n') : '') + line;
  el.scrollTop = el.scrollHeight;
  try {
    chrome.storage?.local?.set({ ft_last_status: String(el.textContent || '') });
  } catch (_) {}
}

function formatBytes(n) {
  if (typeof n !== 'number' || !isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(2)} MB`;
  const gb = mb / 1024;
  return `${gb.toFixed(2)} GB`;
}

function fileNameFromUrl(url) {
  try {
    const u = new URL(String(url || ''));
    const p = (u.pathname || '').split('/').filter(Boolean);
    return p.length ? decodeURIComponent(p[p.length - 1]) : '—';
  } catch (_) {
    return '—';
  }
}

function verdictText(v) {
  const vv = String(v || '').toLowerCase();
  if (vv === 'clean') return 'Безопасно';
  if (vv === 'malicious') return 'Опасно';
  if (vv === 'suspicious') return 'Подозрительно';
  return 'Неизвестно';
}

function logUrlCheckSummary(res) {
  const finalUrl = res?.final_url || res?.url;
  const name = fileNameFromUrl(finalUrl);
  const size = formatBytes(res?.content_length);
  const sha256 = res?.sha256 || res?.file_sha256 || res?.hash_sha256 || null;
  const verdict = verdictText(res?.verdict);
  const canDownload = !!res?.can_download;
  const analysisPossible = canDownload && String(res?.verdict || '').toLowerCase() !== 'malicious';
  const max = formatBytes(res?.max_download_bytes);
  const errs = Array.isArray(res?.policy_errors) ? res.policy_errors : [];

  appendLog(`Файл: ${name}`);
  appendLog(`Размер: ${size} (лимит: ${max})`);
  appendLog(`SHA256: ${sha256 ? String(sha256) : '—'}`);
  appendLog(`Вердикт: ${verdict}`);
  appendLog(`Можно анализировать: ${analysisPossible ? 'Да' : 'Нет'}`);
  if (!analysisPossible && errs.length) {
    for (const e of errs.slice(0, 3)) {
      appendLog(`Причина: ${e}`);
    }
  }
}

function setTicketHint(msg) {
  const el = document.getElementById('ticketHint');
  if (el) el.textContent = msg || '';
}

// CHANGE THIS if your FileTrace address differs
// Tip: keep /analysis here so the tab opens directly in the analysis UI
const BASE_URL = 'http://127.0.0.1:8000/analysis';

async function _persistState() {
  try {
    await chrome.storage.local.set({
      ft_last_ticket: lastTicket || null,
      ft_last_ticket_url: lastTicketUrl || null,
      ft_last_url_input: (document.getElementById('urlInput')?.value || '').trim(),
      ft_active_tab: (document.querySelector('.tab[aria-selected="true"]')?.dataset?.tab || 'filetrace')
    });
  } catch (_) {}
}

async function _restoreState() {
  try {
    const st = await chrome.storage.local.get({
      ft_last_ticket: null,
      ft_last_ticket_url: null,
      ft_last_url_input: '',
      ft_last_status: '',
      ft_active_tab: 'filetrace'
    });
    lastTicket = st.ft_last_ticket;
    lastTicketUrl = st.ft_last_ticket_url;
    const urlEl = document.getElementById('urlInput');
    if (urlEl && st.ft_last_url_input) urlEl.value = st.ft_last_url_input;
    if (st.ft_last_status) setStatus(st.ft_last_status);
    if (lastTicket) setTicketHint('ticket: ' + String(lastTicket).slice(0, 24) + '…');

    switchTab(st.ft_active_tab || 'filetrace');
  } catch (_) {}
}

function switchTab(tabKey) {
  const tabs = Array.from(document.querySelectorAll('.tab'));
  const panels = Array.from(document.querySelectorAll('.panel'));
  for (const t of tabs) {
    const isActive = t.dataset.tab === tabKey;
    t.setAttribute('aria-selected', isActive ? 'true' : 'false');
  }
  for (const p of panels) {
    const isActive = p.dataset.panel === tabKey;
    p.classList.toggle('hidden', !isActive);
  }
  _persistState();
}

function initTabs() {
  for (const btn of document.querySelectorAll('.tab')) {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  }
}

function initDropzone() {
  const dz = document.getElementById('dropzone');
  const input = document.getElementById('fileInput');
  if (!dz || !input) return;

  const updateLabel = () => {
    const f = input.files && input.files[0];
    dz.textContent = f ? f.name : 'Прикрепить файл';
  };

  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      input.click();
    }
  });

  input.addEventListener('change', updateLabel);

  const prevent = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };
  dz.addEventListener('dragenter', (e) => { prevent(e); dz.classList.add('dragover'); });
  dz.addEventListener('dragover', (e) => { prevent(e); dz.classList.add('dragover'); });
  dz.addEventListener('dragleave', (e) => { prevent(e); dz.classList.remove('dragover'); });
  dz.addEventListener('drop', (e) => {
    prevent(e);
    dz.classList.remove('dragover');
    const f = e.dataTransfer?.files?.[0];
    if (!f) return;
    const dt = new DataTransfer();
    dt.items.add(f);
    input.files = dt.files;
    updateLabel();
  });
}

function setBusy(isBusy) {
  const ids = ['btnOpen', 'btnAttach', 'btnCheck', 'btnDownload', 'btnUpload'];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (el) el.disabled = !!isBusy;
  }
}

async function getBaseUrl() {
  return BASE_URL;
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error('Не удалось прочитать файл'));
    r.onload = () => resolve(r.result);
    r.readAsArrayBuffer(file);
  });
}

async function ensureFileTrace(baseUrl) {
  const res = await chrome.runtime.sendMessage({ type: 'ensure_filetrace', baseUrl });
  if (!res?.ok) throw new Error(res?.error || 'Не удалось открыть FileTrace');
  return res;
}

async function callFileTrace(baseUrl, message, opts) {
  const focus = opts?.focus;
  const res = await chrome.runtime.sendMessage({ type: 'filetrace_call', baseUrl, message, focus });
  if (!res?.ok) throw new Error(res?.error || 'Запрос не выполнен');
  return res;
}

let lastTicket = null;
let lastTicketUrl = null;

function readBlobAsBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error('Не удалось прочитать файл'));
    r.onload = () => {
      const s = String(r.result || '');
      // data:application/octet-stream;base64,XXXX
      const comma = s.indexOf(',');
      resolve(comma >= 0 ? s.slice(comma + 1) : s);
    };
    r.readAsDataURL(blob);
  });
}

async function uploadFileChunked(baseUrl, file) {
  const chunkSize = 256 * 1024; // 256KB (more reliable for extension messaging)
  const uploadId = crypto.randomUUID();

  await callFileTrace(baseUrl, {
    type: 'file_upload_begin',
    uploadId,
    filename: file.name,
    size: file.size
  }, { focus: true });

  let offset = 0;
  let index = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, offset + chunkSize);
    const b64 = await readBlobAsBase64(slice);
    await callFileTrace(baseUrl, {
      type: 'file_upload_chunk',
      uploadId,
      index,
      data_b64: b64
    }, { focus: true });
    offset += slice.size;
    index += 1;
    setStatus(`Загрузка: ${Math.min(offset, file.size)}/${file.size} bytes`);
  }

  return await callFileTrace(baseUrl, {
    type: 'file_upload_commit',
    uploadId
  }, { focus: true });
}

document.addEventListener('DOMContentLoaded', async () => {
  setTicketHint('');
  initTabs();
  initDropzone();
  await _restoreState();

  document.getElementById('linkAgreement')?.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const baseUrl = await getBaseUrl();
      const origin = new URL(baseUrl).origin;
      await chrome.tabs.create({ url: origin + '/documents/user_agreement' });
    } catch (err) {
      appendLog('Ошибка: ' + String(err?.message || err));
    }
  });

  document.getElementById('urlInput')?.addEventListener('input', () => {
    _persistState();
  });

  document.getElementById('btnOpen')?.addEventListener('click', async () => {
    try {
      setBusy(true);
      const baseUrl = await getBaseUrl();
      if (!baseUrl) throw new Error('Укажи адрес сайта FileTrace');
      await chrome.tabs.create({ url: baseUrl + '/' });
      appendLog('Открыто: ' + baseUrl);
    } catch (e) {
      appendLog('Ошибка: ' + e.message);
    } finally {
      setBusy(false);
    }
  });

  document.getElementById('btnAttach')?.addEventListener('click', async () => {
    try {
      setBusy(true);
      appendLog('Подключаемся к FileTrace…');
      const baseUrl = await getBaseUrl();
      if (!baseUrl) throw new Error('Укажи адрес сайта FileTrace');
      const ctx = await ensureFileTrace(baseUrl);
      appendLog('Готово. tabId=' + ctx.tabId);
    } catch (e) {
      appendLog('Ошибка: ' + e.message);
    } finally {
      setBusy(false);
    }
  });

  document.getElementById('btnCheck')?.addEventListener('click', async () => {
    try {
      setBusy(true);
      appendLog('Проверяем ссылку…');
      setTicketHint('');
      const baseUrl = await getBaseUrl();
      if (!baseUrl) throw new Error('Укажи адрес сайта FileTrace');
      const url = (document.getElementById('urlInput')?.value || '').trim();
      if (!url) throw new Error('URL не указан');

      const res = await callFileTrace(baseUrl, { type: 'url_check', url }, { focus: false });
      lastTicket = res.ticket || null;
      lastTicketUrl = url;
      await _persistState();
      setTicketHint(lastTicket ? ('ticket: ' + String(lastTicket).slice(0, 24) + '…') : 'ticket: —');
      logUrlCheckSummary(res);
    } catch (e) {
      appendLog('Ошибка: ' + e.message);
    } finally {
      setBusy(false);
    }
  });

  document.getElementById('btnDownload')?.addEventListener('click', async () => {
    try {
      setBusy(true);
      appendLog('Скачиваем и отправляем на анализ…');
      const baseUrl = await getBaseUrl();
      if (!baseUrl) throw new Error('Укажи адрес сайта FileTrace');
      const url = (document.getElementById('urlInput')?.value || '').trim();
      if (!url) throw new Error('URL не указан');

      let ticket = null;
      if (lastTicket && lastTicketUrl === url) {
        ticket = lastTicket;
      } else {
        // Auto-check to obtain ticket
        const chk = await callFileTrace(baseUrl, { type: 'url_check', url }, { focus: false });
        ticket = chk.ticket || null;
        lastTicket = ticket;
        lastTicketUrl = url;
        await _persistState();
        setTicketHint(ticket ? ('ticket: ' + String(ticket).slice(0, 24) + '…') : 'ticket: —');
      }

      if (!ticket) throw new Error('Не удалось получить ticket (проверь, что ссылка разрешена и ты залогинен)');

      const res = await callFileTrace(baseUrl, { type: 'url_download_and_analyze', url, ticket }, { focus: true });
      if (!res?.analysis_id) {
        appendLog(JSON.stringify(res));
        throw new Error('Нет analysis_id в ответе (проверь консоль вкладки FileTrace и статус code)');
      }
      appendLog('OK. analysis_id=' + res.analysis_id);
    } catch (e) {
      appendLog('Ошибка: ' + e.message);
    } finally {
      setBusy(false);
    }
  });

  document.getElementById('btnUpload')?.addEventListener('click', async () => {
    try {
      setBusy(true);
      appendLog('Загружаем файл…');
      const baseUrl = await getBaseUrl();
      if (!baseUrl) throw new Error('Укажи адрес сайта FileTrace');

      const input = document.getElementById('fileInput');
      const file = input?.files?.[0];
      if (!file) throw new Error('Файл не выбран');

      const res = await uploadFileChunked(baseUrl, file);
      appendLog('OK. analysis_id=' + (res?.analysis_id || '—'));
    } catch (e) {
      appendLog('Ошибка: ' + e.message);
    } finally {
      setBusy(false);
    }
  });
});
