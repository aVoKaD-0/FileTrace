(() => {
  if (globalThis.__filetrace_content_injected) {
    return;
  }
  globalThis.__filetrace_content_injected = true;

function jsonError(message, extra) {
  return { ok: false, error: message, extra };
}

const _uploads = new Map();

function _concatChunksByIndex(chunksByIndex) {
  const indices = Array.from(chunksByIndex.keys()).sort((a, b) => a - b);
  let total = 0;
  for (const i of indices) total += (chunksByIndex.get(i)?.byteLength || 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const i of indices) {
    const c = chunksByIndex.get(i);
    if (!c) continue;
    out.set(new Uint8Array(c), offset);
    offset += c.byteLength;
  }
  return out.buffer;
}

function _hex2(bytes) {
  return Array.from(bytes || []).map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

function _b64ToArrayBuffer(b64) {
  const bin = atob(String(b64 || ''));
  const len = bin.length;
  const u8 = new Uint8Array(len);
  for (let i = 0; i < len; i++) u8[i] = bin.charCodeAt(i);
  return u8.buffer;
}

async function postJson(path, body) {
  const resp = await fetch(path, {
    method: 'POST',
    credentials: 'include',
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
    credentials: 'include',
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

    if (msg.type === 'ping') {
      sendResponse({ ok: true, url: window.location.href });
      return;
    }

    if (msg.type === 'url_check') {
      const data = await postJson('/analysis/url/check', { url: msg.url });
      sendResponse({ ok: true, ...data });
      return;
    }

    if (msg.type === 'url_download_and_analyze') {
      const data = await postJson('/analysis/url/download-and-analyze', { url: msg.url, ticket: msg.ticket || null });
      if (!data?.analysis_id) {
        throw new Error('download_and_analyze_no_analysis_id');
      }
      window.location.href = `/analysis/analysis/${data.analysis_id}`;
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

    if (msg.type === 'file_upload_begin') {
      _uploads.set(msg.uploadId, { filename: msg.filename, chunksByIndex: new Map() });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === 'file_upload_chunk') {
      const sess = _uploads.get(msg.uploadId);
      if (!sess) throw new Error('upload_not_found');
      // Store deterministically by index (messages can be reordered)
      if (msg.data_b64) {
        sess.chunksByIndex.set(Number(msg.index), _b64ToArrayBuffer(msg.data_b64));
      } else {
        // Fallback (older protocol)
        sess.chunksByIndex.set(Number(msg.index), msg.data);
      }
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === 'file_upload_commit') {
      const sess = _uploads.get(msg.uploadId);
      if (!sess) throw new Error('upload_not_found');
      _uploads.delete(msg.uploadId);

      const buf = _concatChunksByIndex(sess.chunksByIndex);
      const head = new Uint8Array(buf.slice(0, 16));
      if (head.byteLength < 2 || head[0] !== 0x4d || head[1] !== 0x5a) {
        throw new Error(`upload_corrupted: head=${_hex2(head)}`);
      }
      const data = await postFile('/analysis/analyze', sess.filename, buf);
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

})();
