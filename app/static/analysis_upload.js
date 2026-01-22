console.log("analysis_upload.js loaded");

window.ftAnalysisInitUpload = function(ctx) {
    if (!ctx.dropZone || !ctx.fileInput) return;

    ctx.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        ctx.dropZone.classList.add('drag-over');
    });

    ctx.dropZone.addEventListener('dragleave', () => {
        ctx.dropZone.classList.remove('drag-over');
    });

    ctx.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        ctx.dropZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    ctx.dropZone.addEventListener('click', () => {
        ctx.fileInput.click();
    });

    ctx.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    function updateProgress(percent) {
        if (ctx.progress) ctx.progress.style.width = `${percent}%`;
    }

    async function handleFile(file) {
        if (ctx.progressBar) ctx.progressBar.style.display = 'block';
        updateProgress(0);
        if (ctx.resultsSection) ctx.resultsSection.style.display = 'block';
        if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'inline-block';
        if (ctx.analysisStatusEl) ctx.analysisStatusEl.textContent = 'Загрузка файла...';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/analysis/analyze', {
                method: 'POST',
                body: formData,
                headers: ctx.token ? {'Authorization': `Bearer ${ctx.token}`} : {}
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `Ошибка: ${response.status}`);
            }

            const data = await response.json();
            const runId = data.analysis_id;
            if (ctx.analysisStatusEl) ctx.analysisStatusEl.textContent = 'Файл загружен. Открываем страницу анализа...';
            updateProgress(100);
            if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'none';

            window.location.href = `/analysis/analysis/${runId}`;
        } catch (error) {
            console.error('Error uploading file:', error);
            if (ctx.analysisStatusEl) {
                ctx.analysisStatusEl.textContent = 'Ошибка при загрузке файла: ' + error.message;
                ctx.analysisStatusEl.style.color = 'var(--error-color)';
            }
            if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'none';
        }
    }
};
