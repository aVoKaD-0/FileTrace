function jsonError(message, extra) {
  return { ok: false, error: message, extra };
}

async function postJson(path, body) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!resp.ok) {
    let err = {};
    try { err = await resp.json(); } catch (_) {}
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return await resp.json();
}

async function postFile(path, filename, arrayBuffer) {
  const fd = new FormData();
  const blob = new Blob([arrayBuffer]);
  fd.append('file', blob, filename);

  const resp = await fetch(path, {
    method: 'POST',
    body: fd
  });

  if (!resp.ok) {
    let err = {};
    try { err = await resp.json(); } catch (_) {}
    throw new Error(err.detail || `HTTP ${resp.status}`);
  }
  return await resp.json();
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (!msg?.type) {
      sendResponse(jsonError('no_type'));
      return;
    }

    if (msg.type === 'url_check') {
      const data = await postJson('/analysis/url/check', { url: msg.url });
      sendResponse({ ok: true, ...data });
      return;
    }

    if (msg.type === 'url_download_and_analyze') {
      const data = await postJson('/analysis/url/download-and-analyze', { url: msg.url });
      if (data?.analysis_id) {
        window.location.href = `/analysis/analysis/${data.analysis_id}`;
      }
      sendResponse({ ok: true, ...data });
      return;
    }

    if (msg.type === 'file_upload') {
      const data = await postFile('/analysis/analyze', msg.filename, msg.data);
      if (data?.analysis_id) {
        window.location.href = `/analysis/analysis/${data.analysis_id}`;
      }
      sendResponse({ ok: true, ...data });
      return;
    }

    sendResponse(jsonError('unknown_type'));
  })().catch((e) => {
    sendResponse(jsonError(String(e?.message || e)));
  });

  return true;
});
