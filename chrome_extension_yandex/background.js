async function ensureInjected(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ['content.js']
  });
}

function normalizeBaseUrl(raw) {
  let v = String(raw || '').trim();
  if (!v) return '';
  v = v.replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(v)) {
    v = 'http://' + v;
  }
  return v;
}

function getOrigin(url) {
  try {
    return new URL(url).origin;
  } catch (_) {
    return '';
  }
}

async function findFileTraceTab(baseUrl) {
  const tabs = await chrome.tabs.query({});
  const norm = normalizeBaseUrl(baseUrl);
  const origin = getOrigin(norm);
  for (const t of tabs) {
    const u = String(t.url || '');
    if (!u) continue;
    // Match by origin so redirects (/login, /analysis/...) still count
    if (getOrigin(u) === origin) return t;
  }
  return null;
}

async function openOrFocusFileTraceTab(baseUrl) {
  const norm = normalizeBaseUrl(baseUrl);
  if (!norm) throw new Error('siteBaseUrl is empty');

  const existing = await findFileTraceTab(norm);
  if (existing?.id) {
    await chrome.tabs.update(existing.id, { active: true });
    return existing;
  }

  const created = await chrome.tabs.create({ url: norm + '/' });
  return created;
}

async function openOrFindFileTraceTab(baseUrl, options) {
  const focus = !!(options && options.focus);
  const norm = normalizeBaseUrl(baseUrl);
  if (!norm) throw new Error('siteBaseUrl is empty');

  const existing = await findFileTraceTab(norm);
  if (existing?.id) {
    if (focus) {
      await chrome.tabs.update(existing.id, { active: true });
    }
    return existing;
  }

  const created = await chrome.tabs.create({ url: norm + '/', active: !!focus });
  return created;
}

async function waitTabLoaded(tabId, timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const tab = await chrome.tabs.get(tabId);
    if (tab.status === 'complete') return;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Tab load timeout');
}

async function ensureFileTraceContext(baseUrl) {
  const tab = await openOrFindFileTraceTab(baseUrl, { focus: true });
  if (!tab?.id) throw new Error('No tab id');

  await waitTabLoaded(tab.id);
  await ensureInjected(tab.id);
  return { tabId: tab.id, url: tab.url };
}

async function ensureFileTraceContextWithOptions(baseUrl, options) {
  const focus = options ? options.focus : true;
  const tab = await openOrFindFileTraceTab(baseUrl, { focus: !!focus });
  if (!tab?.id) throw new Error('No tab id');

  await waitTabLoaded(tab.id);
  await ensureInjected(tab.id);
  return { tabId: tab.id, url: tab.url };
}

async function sendToTab(tabId, message) {
  return await chrome.tabs.sendMessage(tabId, message);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === 'ensure_filetrace') {
      const ctx = await ensureFileTraceContextWithOptions(msg.baseUrl, { focus: msg.focus !== false });
      sendResponse({ ok: true, ...ctx });
      return;
    }

    if (msg?.type === 'filetrace_call') {
      const ctx = await ensureFileTraceContextWithOptions(msg.baseUrl, { focus: msg.focus !== false });
      const res = await sendToTab(ctx.tabId, msg.message);
      sendResponse(res);
      return;
    }

    sendResponse({ ok: false, error: 'unknown_message' });
  })().catch((e) => {
    sendResponse({ ok: false, error: String(e?.message || e) });
  });

  return true;
});
