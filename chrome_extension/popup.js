async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function setStatus(msg) {
  const el = document.getElementById('status');
  if (el) el.textContent = msg || '';
}

async function loadBaseUrl() {
  const { siteBaseUrl } = await chrome.storage.sync.get({ siteBaseUrl: '' });
  const el = document.getElementById('siteBaseUrl');
  if (el) el.value = siteBaseUrl;
}

async function saveBaseUrl() {
  const el = document.getElementById('siteBaseUrl');
  const v = (el?.value || '').trim();
  await chrome.storage.sync.set({ siteBaseUrl: v });
  return v;
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error('Не удалось прочитать файл'));
    r.onload = () => resolve(r.result);
    r.readAsArrayBuffer(file);
  });
}

async function ensureInjected(tabId) {
  await chrome.runtime.sendMessage({ type: 'ensure_injected', tabId });
}

async function sendToContent(tabId, message) {
  return await chrome.runtime.sendMessage({ type: 'to_content', tabId, message });
}

document.addEventListener('DOMContentLoaded', async () => {
  await loadBaseUrl();

  document.getElementById('siteBaseUrl')?.addEventListener('change', async () => {
    await saveBaseUrl();
  });

  document.getElementById('btnOpen')?.addEventListener('click', async () => {
    const baseUrl = await saveBaseUrl();
    if (!baseUrl) {
      setStatus('Укажи адрес сайта FileTrace.');
      return;
    }
    await chrome.tabs.create({ url: baseUrl });
  });

  document.getElementById('btnCheck')?.addEventListener('click', async () => {
    try {
      setStatus('Проверяем ссылку…');
      const tab = await getActiveTab();
      if (!tab?.id) throw new Error('Нет активной вкладки');
      await ensureInjected(tab.id);
      const url = (document.getElementById('urlInput')?.value || '').trim();
      if (!url) throw new Error('URL не указан');
      const res = await sendToContent(tab.id, { type: 'url_check', url });
      setStatus(JSON.stringify(res, null, 2));
    } catch (e) {
      setStatus('Ошибка: ' + e.message);
    }
  });

  document.getElementById('btnDownload')?.addEventListener('click', async () => {
    try {
      setStatus('Скачиваем и отправляем на анализ…');
      const tab = await getActiveTab();
      if (!tab?.id) throw new Error('Нет активной вкладки');
      await ensureInjected(tab.id);
      const url = (document.getElementById('urlInput')?.value || '').trim();
      if (!url) throw new Error('URL не указан');
      const res = await sendToContent(tab.id, { type: 'url_download_and_analyze', url });
      setStatus('OK. analysis_id=' + (res?.analysis_id || '—'));
    } catch (e) {
      setStatus('Ошибка: ' + e.message);
    }
  });

  document.getElementById('btnUpload')?.addEventListener('click', async () => {
    try {
      setStatus('Загружаем файл…');
      const tab = await getActiveTab();
      if (!tab?.id) throw new Error('Нет активной вкладки');
      await ensureInjected(tab.id);

      const input = document.getElementById('fileInput');
      const file = input?.files?.[0];
      if (!file) throw new Error('Файл не выбран');

      const buf = await readFileAsArrayBuffer(file);
      const res = await sendToContent(tab.id, {
        type: 'file_upload',
        filename: file.name,
        data: buf
      });
      setStatus('OK. analysis_id=' + (res?.analysis_id || '—'));
    } catch (e) {
      setStatus('Ошибка: ' + e.message);
    }
  });
});
