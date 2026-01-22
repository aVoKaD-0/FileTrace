async function ensureInjected(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
  } catch (e) {
    throw e;
  }
}

async function sendToTab(tabId, message) {
  return await chrome.tabs.sendMessage(tabId, message);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === 'ensure_injected') {
      await ensureInjected(msg.tabId);
      sendResponse({ ok: true });
      return;
    }

    if (msg?.type === 'to_content') {
      const tabId = msg.tabId;
      await ensureInjected(tabId);
      const res = await sendToTab(tabId, msg.message);
      sendResponse(res);
      return;
    }

    sendResponse({ ok: false, error: 'unknown_message' });
  })().catch((e) => {
    sendResponse({ ok: false, error: String(e?.message || e) });
  });

  return true;
});
