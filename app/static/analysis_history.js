console.log("analysis_history.js loaded");

window.ftAnalysisInitHistory = function(ctx) {
    function renderHistoryItems(history) {
        const historyContainer = document.querySelector('.history-container');
        if (!historyContainer) return;

        if (history && history.length) {
            historyContainer.innerHTML = '';
            history.forEach(item => {
                const historyItem = document.createElement('div');
                historyItem.classList.add('history-item');
                if (item.status === 'running') {
                    historyItem.classList.add('running');
                }
                historyItem.setAttribute('data-analysis-id', item.analysis_id);

                const queueInfo = (item.status === 'queued' && item.active_position && item.active_total)
                    ? `Очередь: ${item.active_position} из ${item.active_total} (ожидание ~${item.eta_minutes || 0} мин)`
                    : '';

                historyItem.innerHTML = `
                        <div class="history-item-header">
                            <span class="filename">${item.filename}</span>
                            <span class="timestamp">${item.timestamp}</span>
                        </div>
                        <div class="history-item-details">
                            <div class="status-indicator ${item.status}">${item.status}</div>
                            <div class="queue-info">${queueInfo}</div>
                            <button class="btn btn-sm btn-outline-secondary view-results-btn">Просмотреть результаты</button>
                        </div>
                    `;
                historyContainer.appendChild(historyItem);
            });
            document.querySelectorAll('.view-results-btn').forEach(btn => {
                btn.addEventListener('click', function(e) {
                    const analysisId = e.target.closest('.history-item').dataset.analysisId;
                    window.location.href = '/analysis/analysis/' + analysisId;
                });
            });
        } else {
            historyContainer.innerHTML = '<p>История анализов пуста</p>';
        }
    }

    async function updateHistory() {
        try {
            const response = await fetch('/analysis/history');
            if (!response.ok) {
                throw new Error('Ошибка при получении истории');
            }
            const data = await response.json();
            renderHistoryItems(data.history);
        } catch (error) {
            console.error('Ошибка обновления истории:', error);
        }
    }

    if (ctx.refreshHistoryBtn) {
        ctx.refreshHistoryBtn.addEventListener('click', updateHistory);
    }

    function updateCurrentAnalysisQueue(history, analysisId) {
        const el = document.getElementById('metaQueueInfo');
        if (!el) return;

        const item = (history || []).find(x => String(x.analysis_id) === String(analysisId));
        if (!item) {
            el.textContent = '';
            return;
        }

        if (item.status === 'queued' && item.active_position && item.active_total) {
            el.textContent = `Очередь: ${item.active_position} из ${item.active_total}. Примерное ожидание: ~${item.eta_minutes || 0} мин.`;
        } else if (item.status === 'running' && item.active_position && item.active_total) {
            el.textContent = `Выполняется: слот ${item.active_position} из ${item.active_total}.`;
        } else {
            el.textContent = '';
        }
    }

    function setupHistoryWebSocket() {
        if (!document.querySelector('.history-container')) return;

        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const wsUrl = `${protocol}://${window.location.host}/analysis/ws-history`;
        let socket;

        function connect() {
            socket = new WebSocket(wsUrl);
            socket.onmessage = function(event) {
                try {
                    const payload = JSON.parse(event.data);
                    if (payload && payload.event === 'history' && payload.history) {
                        renderHistoryItems(payload.history);
                        if (typeof window.analysisId !== 'undefined' && window.analysisId) {
                            updateCurrentAnalysisQueue(payload.history, window.analysisId);
                        }
                    }
                } catch (e) {
                    console.error('Ошибка обработки ws-history:', e);
                }
            };
            socket.onclose = function() {
                setTimeout(connect, 1000);
            };
        }

        connect();
    }

    setupHistoryWebSocket();
};
