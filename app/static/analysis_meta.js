console.log("analysis_meta.js loaded");

window.ftAnalysisInitMeta = function(ctx) {
    async function loadAnalysisMeta(analysisId) {
        const card = document.getElementById('analysisMetaCard');
        if (!card) return;

        try {
            const res = await fetch(`/analysis/meta/${analysisId}`);
            if (!res.ok) return;
            const data = await res.json();

            const setText = (id, value) => {
                const el = document.getElementById(id);
                if (el) el.textContent = (value !== undefined && value !== null && value !== '') ? String(value) : '—';
            };

            setText('metaFilename', data.filename);
            setText('metaTimestamp', data.timestamp);
            setText('metaSha256', data.sha256);
            setText('metaPipeline', data.pipeline_version);
            setText('metaDangerCount', Number.isFinite(Number(data.danger_count)) ? Number(data.danger_count) : 0);

            let verdict = '—';
            if (data.status === 'completed' || data.status === 'error') {
                verdict = data.is_threat ? 'Угроза' : 'Не угроза';
            } else if (data.status === 'running') {
                verdict = 'Анализ выполняется';
            } else if (data.status === 'queued') {
                verdict = 'В очереди';
            }
            setText('metaVerdict', verdict);

            card.style.display = 'block';
        } catch (e) {
            console.error('Ошибка загрузки метаданных анализа:', e);
        }
    }

    if (typeof window.analysisId !== 'undefined' && window.analysisId) {
        loadAnalysisMeta(window.analysisId);
    }
};
