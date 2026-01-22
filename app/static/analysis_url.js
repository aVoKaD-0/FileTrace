console.log("analysis_url.js loaded");

window.ftAnalysisInitUrl = function (ctx) {
    if (!ctx.urlInput || !ctx.urlCheckBtn || !ctx.urlDownloadBtn) return;

    let lastMeta = null;
    let lastVerdict = null;
    let lastTicket = null;

    function setStatus(text, kind) {
        if (ctx.resultsSection) ctx.resultsSection.style.display = 'block';
        if (ctx.analysisStatusEl) {
            ctx.analysisStatusEl.textContent = text;
            if (kind === 'ok') ctx.analysisStatusEl.style.color = 'var(--success-color)';
            else if (kind === 'warn') ctx.analysisStatusEl.style.color = 'var(--warning-color)';
            else if (kind === 'err') ctx.analysisStatusEl.style.color = 'var(--error-color)';
            else ctx.analysisStatusEl.style.color = '';
        }
        if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'inline-block';
    }

    function stopSpinner() {
        if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'none';
    }

    function updateProgress(percent) {
        if (ctx.progressBar) ctx.progressBar.style.display = 'block';
        if (ctx.progress) ctx.progress.style.width = `${percent}%`;
    }

    function showMetaCard(meta, verdict) {
        if (!ctx.urlMetaCard) return;
        ctx.urlMetaCard.style.display = 'block';

        if (ctx.urlFinalEl) ctx.urlFinalEl.textContent = meta?.final_url || meta?.url || '—';
        if (ctx.urlContentTypeEl) ctx.urlContentTypeEl.textContent = meta?.content_type || '—';

        const size = meta?.content_length;
        if (ctx.urlContentLengthEl) {
            ctx.urlContentLengthEl.textContent = (typeof size === 'number' && Number.isFinite(size)) ? `${size} bytes` : '—';
        }
        if (ctx.urlLastModifiedEl) ctx.urlLastModifiedEl.textContent = meta?.last_modified || '—';

        if (ctx.urlVerdictEl) {
            ctx.urlVerdictEl.textContent = verdict?.verdict || '—';
            if (verdict?.verdict === 'clean') ctx.urlVerdictEl.style.color = 'var(--success-color)';
            else if (verdict?.verdict === 'suspicious') ctx.urlVerdictEl.style.color = 'var(--warning-color)';
            else if (verdict?.verdict === 'malicious') ctx.urlVerdictEl.style.color = 'var(--error-color)';
            else ctx.urlVerdictEl.style.color = '';
        }

        if (ctx.urlHintsEl) {
            const reasons = Array.isArray(verdict?.reasons) ? verdict.reasons : [];
            const maxBytes = meta?.max_download_bytes;
            const maxLine = (typeof maxBytes === 'number' && Number.isFinite(maxBytes)) ? `Макс. размер: ${maxBytes} bytes.` : '';
            const policyErrors = Array.isArray(meta?.policy_errors) ? meta.policy_errors : [];
            const policyLine = policyErrors.length ? `Ограничения: ${policyErrors.join('; ')}` : '';
            const reasonsLine = reasons.length ? `Причины: ${reasons.join(', ')}` : '';
            ctx.urlHintsEl.textContent = [maxLine, policyLine, reasonsLine].filter(Boolean).join(' ');
        }
    }

    function getUrl() {
        return (ctx.urlInput.value || '').trim();
    }

    async function doCheck() {
        const url = getUrl();
        if (!url) return;

        ctx.urlDownloadBtn.disabled = true;
        updateProgress(0);
        setStatus('Проверяем ссылку…', 'warn');

        try {
            updateProgress(10);
            const metaResp = await fetch('/analysis/url/meta', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            if (!metaResp.ok) {
                const err = await metaResp.json().catch(() => ({}));
                throw new Error(err.detail || `Ошибка meta: ${metaResp.status}`);
            }
            lastMeta = await metaResp.json();
            updateProgress(40);
            setStatus('Проверяем репутацию…', 'warn');

            const checkResp = await fetch('/analysis/url/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            if (!checkResp.ok) {
                const err = await checkResp.json().catch(() => ({}));
                throw new Error(err.detail || `Ошибка check: ${checkResp.status}`);
            }
            lastVerdict = await checkResp.json();
            lastTicket = lastVerdict?.ticket || null;
            updateProgress(70);

            // merge policy fields from check into meta for display
            const mergedMeta = { ...lastMeta, ...lastVerdict };
            showMetaCard(mergedMeta, lastVerdict);

            const canDownload = !!lastVerdict?.can_download;

            if (lastVerdict?.verdict === 'malicious') {
                setStatus('Ссылка признана опасной. Скачивание заблокировано.', 'err');
                ctx.urlDownloadBtn.disabled = true;
            } else if (!canDownload) {
                const errs = Array.isArray(lastVerdict?.policy_errors) ? lastVerdict.policy_errors.join('; ') : 'Скачивание запрещено';
                setStatus(errs, 'err');
                ctx.urlDownloadBtn.disabled = true;
            } else {
                setStatus('Проверка завершена. Можно скачать и отправить на анализ.', 'ok');
                ctx.urlDownloadBtn.disabled = false;
            }
            updateProgress(100);
            stopSpinner();
        } catch (e) {
            console.error(e);
            setStatus('Ошибка при проверке ссылки: ' + e.message, 'err');
            stopSpinner();
        }
    }

    async function doDownloadAndAnalyze() {
        const url = getUrl();
        if (!url) return;

        ctx.urlDownloadBtn.disabled = true;
        updateProgress(0);
        setStatus('Скачиваем файл…', 'warn');

        try {
            updateProgress(20);
            const resp = await fetch('/analysis/url/download-and-analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, ticket: lastTicket })
            });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.detail || `Ошибка: ${resp.status}`);
            }
            const data = await resp.json();
            updateProgress(100);
            setStatus('Файл скачан и отправлен на анализ. Открываем страницу анализа…', 'ok');
            stopSpinner();
            window.location.href = `/analysis/analysis/${data.analysis_id}`;
        } catch (e) {
            console.error(e);
            setStatus('Ошибка при скачивании/отправке: ' + e.message, 'err');
            stopSpinner();
            ctx.urlDownloadBtn.disabled = false;
        }
    }

    ctx.urlCheckBtn.addEventListener('click', doCheck);
    ctx.urlDownloadBtn.addEventListener('click', doDownloadAndAnalyze);

    ctx.urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') doCheck();
    });
};
