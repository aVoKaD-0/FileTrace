console.log("analysis_results.js loaded");

window.ftAnalysisInitResults = function(ctx) {
    const analysisId = ctx.analysisId;

    function updateStatus(status) {
        const statusElement = document.getElementById('analysisStatus');
        if (!statusElement) return;
        statusElement.textContent = `Статус: ${status}`;
        if (status === 'completed') {
            statusElement.style.color = 'var(--success-color)';
            if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'none';
        } else if (status === 'running' || status === 'queued') {
            statusElement.style.color = 'var(--warning-color)';
            if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'inline-block';
        } else {
            statusElement.style.color = 'var(--error-color)';
            if (ctx.statusSpinner) ctx.statusSpinner.style.display = 'none';
        }
    }

    async function showResults(analysisId) {
        try {
            const response = await fetch(`/analysis/results/${analysisId}`, {
                headers: ctx.token ? { 'Authorization': `Bearer ${ctx.token}` } : {}
            });
            if (!response.ok) {
                if (response.status === 404) {
                    const fileEl = document.getElementById('fileActivityContent');
                    if (fileEl) fileEl.textContent = 'Нет данных по файловой активности.';
                    if (ctx.dockerOutputContent) ctx.dockerOutputContent.textContent = 'Нет логов Docker.';
                    const etlEl = document.getElementById('etlOutputContent');
                    if (etlEl) etlEl.textContent = 'Нет данных ETL результатов.';
                    updateStatus('Нет данных');

                    const dockerLoader = document.getElementById('dockerOutputLoader');
                    if (dockerLoader) dockerLoader.style.display = 'none';
                    const fileLoader = document.getElementById('fileActivityLoader');
                    if (fileLoader) fileLoader.style.display = 'none';
                    const etlLoader = document.getElementById('etlOutputLoader');
                    if (etlLoader) etlLoader.style.display = 'none';
                    return;
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            window.analysisStatus = data.status;
            updateStatus(data.status);

            const fileEl = document.getElementById('fileActivityContent');
            if (fileEl) {
                if (typeof data.file_activity === 'string' && data.file_activity.length > 0) {
                    fileEl.textContent = data.file_activity;
                } else {
                    fileEl.textContent = 'Нет данных по файловой активности.';
                }
            }

            if (ctx.dockerOutputContent) {
                ctx.dockerOutputContent.textContent = data.docker_output ? data.docker_output : 'Нет логов Docker.';
            }

            const dockerLoader = document.getElementById('dockerOutputLoader');
            if (dockerLoader) dockerLoader.style.display = 'none';

            const fileLoader = document.getElementById('fileActivityLoader');
            if (fileLoader) fileLoader.style.display = 'none';
        } catch (error) {
            console.error('Ошибка при получении результатов анализа:', error);
            if (ctx.analysisStatusEl) {
                ctx.analysisStatusEl.textContent = 'Ошибка при получении результатов анализа: ' + error.message;
                ctx.analysisStatusEl.style.color = 'var(--error-color)';
            }
            const dockerLoader = document.getElementById('dockerOutputLoader');
            if (dockerLoader) dockerLoader.style.display = 'none';
            const fileLoader = document.getElementById('fileActivityLoader');
            if (fileLoader) fileLoader.style.display = 'none';
            const etlLoader = document.getElementById('etlOutputLoader');
            if (etlLoader) etlLoader.style.display = 'none';
        }
    }

    async function loadEtlChunk(analysisId, initialLoad = false) {
        const loader = document.getElementById('etlOutputLoader');
        const tableBody = document.querySelector('#cleanTreeTable tbody');
        if (!tableBody) return null;

        try {
            if (initialLoad && loader) {
                loader.style.display = 'block';
            }

            const response = await fetch(`/analysis/clean-tree/${analysisId}`);

            if (response.status === 404) {
                ctx.cleanTreeLoaded = true;
                ctx.cleanTreeRowCount = 0;
                tableBody.innerHTML = '';
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 5;
                cell.textContent = 'Данных нет.';
                row.appendChild(cell);
                tableBody.appendChild(row);
                updateEtlLoadButtons(analysisId, 0, 0, 'Вердикт: данных для анализа нет.', 0);
                return null;
            }

            if (!response.ok) {
                throw new Error(`Ошибка HTTP! status: ${response.status}`);
            }

            const data = await response.json();

            ctx.cleanTreeLoaded = true;
            const rows = Array.isArray(data.rows) ? data.rows : [];
            ctx.cleanTreeRowCount = rows.length;

            const totalRows = Number.isFinite(Number(data.total_rows)) ? Number(data.total_rows) : ctx.cleanTreeRowCount;
            const dangerCountTotal = Number.isFinite(Number(data.danger_count)) ? Number(data.danger_count) : 0;

            let benignOnly = true;
            tableBody.innerHTML = '';

            if (rows.length === 0) {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 5;
                cell.textContent = 'Нет данных очищенного лога.';
                row.appendChild(cell);
                tableBody.appendChild(row);
            } else {
                rows.forEach(r => {
                    const tr = document.createElement('tr');

                    if (r.threat_level || r.threat_msg) {
                        tr.classList.add('threat-row');
                        const level = String(r.threat_level || '').toLowerCase();
                        if (level.includes('critical')) {
                            tr.classList.add('threat-critical');
                        } else if (level.includes('high')) {
                            tr.classList.add('threat-high');
                        } else if (level.includes('warning')) {
                            tr.classList.add('threat-warning');
                        }
                    }

                    let dangerText = '';
                    if (r.threat_msg) {
                        const parts = String(r.threat_msg).split(':');
                        if (parts.length > 1) {
                            dangerText = parts.slice(1).join(':').trim();
                        } else {
                            dangerText = r.threat_msg;
                        }
                    } else if (r.threat_level) {
                        dangerText = r.threat_level;
                    }

                    const isDanger = !!(r.threat_level || r.threat_msg);
                    if (isDanger) {
                        const desc = dangerText || '';
                        const isBenign = desc.includes('Использование PowerShell') || desc.includes('Сетевая активность');
                        if (!isBenign) {
                            benignOnly = false;
                        }
                    }

                    const cells = [
                        r.index,
                        r.event,
                        r.type,
                        r.details,
                        dangerText
                    ];

                    cells.forEach((value, idx) => {
                        const td = document.createElement('td');
                        if (idx === 3) {
                            td.classList.add('details-cell');
                        }
                        if (idx === 4 && dangerText) {
                            td.classList.add('danger-cell');
                        }
                        td.textContent = value !== undefined && value !== null ? value : '';
                        tr.appendChild(td);
                    });

                    if (r.threat_msg) {
                        tr.title = r.threat_msg;
                    }

                    tableBody.appendChild(tr);
                });
            }

            let verdict = 'Вердикт: анализ завершён.';
            if (dangerCountTotal === 0) {
                verdict = benignOnly ? 'Вердикт: явных опасных действий не обнаружено.' : 'Вердикт: опасных действий не обнаружено (но есть подозрительные признаки).';
            } else if (benignOnly) {
                verdict = `Вердикт: найдено ${dangerCountTotal} подозрительных действий (в основном benign).`;
            } else {
                verdict = `Вердикт: найдено ${dangerCountTotal} опасных действий.`;
            }

            updateEtlLoadButtons(analysisId, ctx.cleanTreeRowCount, dangerCountTotal, verdict, totalRows);
            return data;
        } catch (error) {
            console.error('Ошибка при загрузке clean_tree:', error);
            updateEtlLoadButtons(analysisId, 0, 0, 'Вердикт: не удалось получить данные для анализа.', 0);
            return null;
        } finally {
            if (loader) {
                loader.style.display = 'none';
            }
        }
    }

    function updateEtlLoadButtons(analysisId, rowCount, dangerCount, verdictText, totalRowCount) {
        const container = document.getElementById('etlOutput');
        if (!container) return;

        let buttonArea = document.getElementById('etlButtonArea');
        if (!buttonArea) return;

        buttonArea.innerHTML = "";

        const remainingCount = document.createElement('div');
        remainingCount.id = 'etlRemainingCount';
        remainingCount.style.marginBottom = '10px';
        remainingCount.style.fontWeight = 'bold';
        const totalInfo = (Number.isFinite(Number(totalRowCount)) && Number(totalRowCount) > rowCount)
            ? ` (показано ${rowCount} из ${totalRowCount})`
            : '';
        remainingCount.textContent = `Строк в таблице: ${rowCount}${totalInfo}`;
        buttonArea.appendChild(remainingCount);

        const dangerInfo = document.createElement('div');
        dangerInfo.id = 'etlDangerCount';
        dangerInfo.style.marginBottom = '10px';
        dangerInfo.textContent = `Опасных действий: ${dangerCount}`;
        buttonArea.appendChild(dangerInfo);

        if (verdictText) {
            const verdictDiv = document.createElement('div');
            verdictDiv.id = 'etlVerdict';
            verdictDiv.textContent = verdictText;
            buttonArea.appendChild(verdictDiv);
        }

        const buttonsContainer = document.createElement('div');
        buttonsContainer.style.display = 'flex';
        buttonsContainer.style.gap = '10px';
        buttonsContainer.style.flexWrap = 'wrap';
        buttonArea.appendChild(buttonsContainer);

        const downloadTraceCsvBtn = document.createElement('button');
        downloadTraceCsvBtn.id = 'downloadTraceCsvBtn';
        downloadTraceCsvBtn.textContent = 'Скачать trace.csv';
        downloadTraceCsvBtn.className = 'btn btn-secondary';
        downloadTraceCsvBtn.style.minWidth = '180px';
        downloadTraceCsvBtn.addEventListener('click', function() {
            window.location.href = `/analysis/download-trace-csv/${analysisId}`;
        });
        buttonsContainer.appendChild(downloadTraceCsvBtn);

        const downloadThreatReportBtn = document.createElement('button');
        downloadThreatReportBtn.id = 'downloadThreatReportBtn';
        downloadThreatReportBtn.textContent = 'Скачать threat_report.json';
        downloadThreatReportBtn.className = 'btn btn-outline-danger';
        downloadThreatReportBtn.style.minWidth = '220px';
        downloadThreatReportBtn.addEventListener('click', function() {
            window.location.href = `/analysis/download-threat-report/${analysisId}`;
        });
        buttonsContainer.appendChild(downloadThreatReportBtn);
    }

    function setupAnalysisWebSocket(analysisId) {
        if (!analysisId) return;

        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';

        if (window.analysisWs && (window.analysisWs.readyState === WebSocket.OPEN || window.analysisWs.readyState === WebSocket.CONNECTING)) {
            return;
        }

        window.analysisWs = new WebSocket(`${protocol}://${window.location.host}/analysis/ws/${analysisId}`);

        window.analysisWs.onmessage = function(event) {
            let data;
            try {
                data = JSON.parse(event.data);
            } catch (e) {
                return;
            }

            if (data.event === 'docker_log') {
                if (ctx.dockerOutputContent) {
                    const msg = String(data.message || '');

                    const suppressedPrefixes = [
                        'docker build stdout:',
                        'docker build stderr:',
                        'docker run stdout:',
                        'docker run stderr:',
                    ];

                    const suppressedLoose = [
                        'Step ',
                        '--->',
                        'Sending build context to Docker daemon',
                        'Running in ',
                        'Removed intermediate container ',
                        'Successfully built ',
                        'Successfully tagged ',
                    ];

                    const suppressedContains = [
                        'Handles  NPM(K)',
                        'ProcessName',
                    ];

                    const stripped = msg.trimStart();
                    const isSuppressed = suppressedPrefixes.some(p => msg.startsWith(p)) ||
                        suppressedLoose.some(p => stripped.startsWith(p)) ||
                        suppressedContains.some(s => msg.includes(s));

                    if (isSuppressed) {
                        return;
                    }

                    let safe = msg;
                    safe = safe.replace(/\boutput_dir\s*=\s*[^\s\)]+/ig, 'output_dir=<redacted>');
                    safe = safe.replace(/\bbase_dir\s*=\s*[^\s\)]+/ig, 'base_dir=<redacted>');
                    safe = safe.replace(/\b[A-Za-z]:\\[^\s"']+/g, '<redacted_path>');

                    const prefix = ctx.dockerOutputContent.textContent && !ctx.dockerOutputContent.textContent.endsWith('\n') ? '\n' : '';
                    ctx.dockerOutputContent.textContent += prefix + safe;
                }
            } else if (data.status) {
                const prevStatus = window.analysisStatus;
                window.analysisStatus = data.status;
                updateStatus(data.status);

                if (prevStatus && prevStatus !== data.status) {
                    const reloadKey = `ft_reloaded_${analysisId}_${data.status}`;
                    if (!sessionStorage.getItem(reloadKey)) {
                        sessionStorage.setItem(reloadKey, '1');
                        window.location.reload();
                    }
                }
            }
        };
    }

    function setupEtlTabClickHandler(analysisId) {
        const etlTab = document.querySelector('a[href="#etlOutput"]');
        if (etlTab) {
            etlTab.addEventListener('click', function() {
                const tableBody = document.querySelector('#cleanTreeTable tbody');
                if (tableBody && tableBody.children.length === 0 && !ctx.cleanTreeLoaded) {
                    loadEtlChunk(analysisId, true);
                }
            });
        }
    }

    function loadInitialData(analysisId) {
        setupEtlTabClickHandler(analysisId);

        if (window.analysisStatus === 'completed') {
            const etlTab = document.querySelector('a[href="#etlOutput"]');
            const isEtlTabActive = etlTab?.classList.contains('active');
            if (isEtlTabActive) {
                loadEtlChunk(analysisId, true);
            }
        }
    }

    if (typeof analysisId !== "undefined" && analysisId) {
        showResults(analysisId);
        loadInitialData(analysisId);
        setupAnalysisWebSocket(analysisId);
    }
};
