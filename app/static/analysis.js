console.log("script.js loaded");

document.addEventListener('DOMContentLoaded', function() {
    const analysisId = window.analysisId;
    console.log("Global analysisId:", (typeof analysisId !== "undefined") ? analysisId : "undefined");

    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const progressBar = document.getElementById('progressBar');
    const progress = document.getElementById('progress');
    const resultsSection = document.getElementById('resultsSection');
    const analysisStatus = document.getElementById('analysisStatus');
    const dockerOutputContent = document.getElementById('dockerOutputContent');
    const statusSpinner = document.getElementById('statusSpinner');
    const refreshHistoryBtn = document.getElementById('refreshHistory');
    const token = localStorage.getItem('access_token');
    let fileActivityOffset = 0;
    const FILE_ACTIVITY_LIMIT = 500;
    let fileActivityTotal = 0;

    // Глобальные переменные для постраничной загрузки ETL данных
    let etlOffset = 0;
    const ETL_CHUNK_LIMIT = 200;
    let etlTotal = 0;

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });

    dropZone.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });

    async function handleFile(file) {
        console.log("Начало обработки файла:", file);
        progressBar.style.display = 'block';
        progress.style.width = '0%';
        resultsSection.style.display = 'block';
        statusSpinner.style.display = 'inline-block';
        analysisStatus.textContent = 'Загрузка файла...';
        console.log("все работает")

        const formData = new FormData();
        formData.append('file', file);

        try {
            console.log("Отправка файла...")
            const response = await fetch('/analysis/analyze', {
                method: 'POST',
                body: formData,
                headers: token ? {'Authorization': `Bearer ${token}`} : {}
            });
            console.log("Файл отправлен")

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `Ошибка: ${response.status}`);
            }

            const data = await response.json();
            const runId = data.analysis_id;
            analysisStatus.textContent = 'Файл загружен. Открываем страницу анализа...';
            updateProgress(100);
            statusSpinner.style.display = 'none';

            console.log("Переходим на страницу /analysis/" + runId);
            window.location.href = `/analysis/analysis/${runId}`;
        } catch (error) {
            console.error('Error uploading file:', error);
            analysisStatus.textContent = 'Ошибка при загрузке файла: ' + error.message;
            analysisStatus.style.color = 'var(--error-color)';
            statusSpinner.style.display = 'none';
        }
    }

    function updateProgress(percent) {
        progress.style.width = `${percent}%`;
    }

    async function updateHistory() {
        try {
            const response = await fetch('/history');
            if (!response.ok) {
                throw new Error('Ошибка при получении истории');
            }
            const data = await response.json();
            const historyContainer = document.querySelector('.history-container');
            if (data.history && data.history.length) {
                historyContainer.innerHTML = '';
                data.history.forEach(item => {
                    const historyItem = document.createElement('div');
                    historyItem.classList.add('history-item');
                    if (item.status === 'running') {
                        historyItem.classList.add('running');
                    }
                    historyItem.setAttribute('data-analysis-id', item.analysis_id);
                    historyItem.innerHTML = `
                        <div class="history-item-header">
                            <span class="filename">${item.filename}</span>
                            <span class="timestamp">${item.timestamp}</span>
                        </div>
                        <div class="history-item-details">
                            <div class="status-indicator ${item.status}">${item.status}</div>
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
        } catch (error) {
            console.error('Ошибка обновления истории:', error);
        }
    }

    if (refreshHistoryBtn) {
        refreshHistoryBtn.addEventListener('click', updateHistory);
    }

    document.querySelectorAll('.view-results-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            const analysisId = e.target.closest('.history-item').dataset.analysisId;
            window.location.href = '/analysis/analysis/' + analysisId;
        });
    });

    async function showResults(analysisId) {
        console.log("Показываем результаты анализа:", analysisId);
        try {
            const response = await fetch(`/analysis/results/${analysisId}`, {
                headers: token ? { 'Authorization': `Bearer ${token}` } : {}
            });
            console.log("Запрос отправлен")
            if (!response.ok) {
                console.log("Ошибка при получении результатов анализа:", response.status);
                if (response.status === 404) {
                    document.getElementById('fileActivityContent').textContent = 'Нет данных по файловой активности.';
                    document.getElementById('dockerOutputContent').textContent = 'Нет логов Docker.';
                    document.getElementById('etlOutputContent').textContent = 'Нет данных ETL результатов.';
                    updateStatus('Нет данных');
                    
                    // Скрываем индикаторы загрузки
                    const dockerLoader = document.getElementById('dockerOutputLoader');
                    if (dockerLoader) dockerLoader.style.display = 'none';
            
                    const fileLoader = document.getElementById('fileActivityLoader');
                    if (fileLoader) fileLoader.style.display = 'none';
                    
                    const etlLoader = document.getElementById('etlOutputLoader');
                    if (etlLoader) etlLoader.style.display = 'none';
                    
                    return;
                } else {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
            }
            const data = await response.json();
            console.log("Получены результаты:", data);

            updateStatus(window.analysisStatus);
    
            console.log("Обработка file_activity как строки");
            console.log(data.file_activity);
            if (typeof data.file_activity === 'string' && data.file_activity.length > 0) {
                document.getElementById('fileActivityContent').textContent = data.file_activity;
            } else {
                document.getElementById('fileActivityContent').textContent = 'Нет данных по файловой активности.';
            }

            console.log("Обработка docker_output как строки");
    
            if (data.docker_output) {
                dockerOutputContent.textContent = data.docker_output;
            } else {
                dockerOutputContent.textContent = 'Нет логов Docker.';
            }
            
            // Скрываем индикаторы загрузки
            const dockerLoader = document.getElementById('dockerOutputLoader');
            if (dockerLoader) dockerLoader.style.display = 'none';
    
            const fileLoader = document.getElementById('fileActivityLoader');
            if (fileLoader) fileLoader.style.display = 'none';
            
            // Для ETL результатов не скрываем индикатор загрузки здесь,
            // это будет делать функция loadEtlChunk при загрузке данных
        } catch (error) {
            console.error('Ошибка при получении результатов анализа:', error);
            analysisStatus.textContent = 'Ошибка при получении результатов анализа: ' + error.message;
            analysisStatus.style.color = 'var(--error-color)';
            
            // Скрываем индикаторы загрузки в случае ошибки
            const dockerLoader = document.getElementById('dockerOutputLoader');
            if (dockerLoader) dockerLoader.style.display = 'none';
    
            const fileLoader = document.getElementById('fileActivityLoader');
            if (fileLoader) fileLoader.style.display = 'none';
            
            const etlLoader = document.getElementById('etlOutputLoader');
            if (etlLoader) etlLoader.style.display = 'none';
        }
    }

    function updateStatus(status) {
        const statusElement = document.getElementById('analysisStatus');
        console.log("Обновление статуса анализа:", status);
        statusElement.textContent = `Статус: ${status}`;
        if (status === 'completed') {
            statusElement.style.color = 'var(--success-color)';
            statusSpinner.style.display = 'none';
        } else if (status === 'running') {
            statusElement.style.color = 'var(--warning-color)';
            statusSpinner.style.display = 'inline-block';
        } else {
            statusElement.style.color = 'var(--error-color)';
            statusSpinner.style.display = 'none';
        }
    }

    async function loadNextChunk(analysisId, limitOverride) {
        try {
            const limit = limitOverride !== undefined ? limitOverride : FILE_ACTIVITY_LIMIT;
            const response = await fetch(`analysis/results/${analysisId}/chunk?offset=${fileActivityOffset}&limit=${limit}`, {
                headers: token ? { 'Authorization': `Bearer ${token}` } : {}
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            const pre = document.getElementById('fileActivityContent');
            const existingContent = pre.textContent;
            const newContent = JSON.stringify(data.chunk, null, 4);
            pre.textContent = existingContent + "\n" + newContent;
            fileActivityOffset += data.chunk.length;
            updateLoadMoreButton(analysisId);
        } catch (error) {
            console.error('Ошибка при загрузке чанка:', error);
        }
    }

    function downloadFullFile(analysisId) {
        window.location.assign(`analysis/download/${analysisId}`);
    }

    function updateLoadMoreButton(analysisId) {
        const container = document.getElementById('fileActivityContainer');
        let buttonArea = document.getElementById('buttonArea');
        if (!buttonArea) {
            buttonArea = document.createElement('div');
            buttonArea.id = 'buttonArea';
            buttonArea.style.display = 'flex';
            buttonArea.style.gap = '10px';
            buttonArea.style.marginTop = '10px';
            container.appendChild(buttonArea);
        }
        buttonArea.innerHTML = "";

        if (fileActivityTotal > fileActivityOffset) {
            const loadMoreBtn = document.createElement('button');
            loadMoreBtn.id = 'loadMoreBtn';
            loadMoreBtn.textContent = 'Загрузить ещё';
            loadMoreBtn.className = 'btn btn-secondary';
            loadMoreBtn.addEventListener('click', function() {
                loadNextChunk(analysisId);
            });
            buttonArea.appendChild(loadMoreBtn);

            const loadAllBtn = document.createElement('button');
            loadAllBtn.id = 'loadAllBtn';
            loadAllBtn.textContent = 'Загрузить всё';
            loadAllBtn.className = 'btn btn-primary';
            loadAllBtn.addEventListener('click', function() {
                downloadFullFile(analysisId);
            });
            buttonArea.appendChild(loadAllBtn);
        }
        const remaining = fileActivityTotal - fileActivityOffset;
        const remainingSpan = document.getElementById('remainingCount');
        if (remainingSpan) {
            remainingSpan.textContent = "Осталось элементов: " + remaining;
        }
    }
    var x = window.A;
    console.log(x);

    // Функция для форматирования JSON строк в более читабельный вид
    function tryFormatJSON(text) {
        try {
            // Пытаемся распарсить строку как JSON
            const jsonObj = JSON.parse(text);
            // Если успешно, возвращаем отформатированный JSON с отступами
            return JSON.stringify(jsonObj, null, 2);
        } catch (e) {
            // Если не удалось распарсить как JSON, возвращаем исходный текст
            return text;
        }
    }

    // Функция для загрузки ETL данных
    async function loadEtlChunk(analysisId, initialLoad = false) {
        console.log(`Загрузка ETL чанка: offset=${etlOffset}, limit=${ETL_CHUNK_LIMIT}`);
        try {
            // Показываем индикатор загрузки только при первой загрузке
            if (initialLoad) {
                document.getElementById('etlOutputLoader').style.display = 'block';
            }
            
            const response = await fetch(`/analysis/etl-chunk/${analysisId}?offset=${etlOffset}&limit=${ETL_CHUNK_LIMIT}`);
            if (!response.ok) {
                throw new Error(`Ошибка HTTP! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log("Получены ETL данные:", data);
            
            const etlContent = document.getElementById('etlOutputContent');
            
            // При первой загрузке очищаем контент
            if (initialLoad) {
                etlContent.innerHTML = '';
            }
            
            // Добавляем полученные строки с форматированием JSON
            if (data.chunk && data.chunk.length > 0) {
                // Обрабатываем каждую строку отдельно
                let formattedHtml = '';
                
                data.chunk.forEach(line => {
                    try {
                        // Пытаемся распарсить строку как JSON
                        const jsonObj = JSON.parse(line);
                        // Преобразуем в отформатированный JSON с отступами
                        const formattedJson = JSON.stringify(jsonObj, null, 2);
                        // Создаем блок кода с подсветкой синтаксиса
                        const codeBlock = document.createElement('code');
                        codeBlock.className = 'language-json';
                        codeBlock.textContent = formattedJson;
                        // Применяем подсветку синтаксиса
                        hljs.highlightElement(codeBlock);
                        // Добавляем к итоговому HTML
                        formattedHtml += `<div class="json-block">${codeBlock.outerHTML}</div>`;
                    } catch (e) {
                        // Если не JSON, просто добавляем строку
                        formattedHtml += `<div>${line}</div>`;
                    }
                });
                
                if (initialLoad || etlContent.innerHTML === 'Нет данных ETL результатов.') {
                    etlContent.innerHTML = formattedHtml;
                } else {
                    etlContent.innerHTML += formattedHtml;
                }
                
                etlOffset += data.chunk.length;
                etlTotal = data.total;
            } else if (initialLoad) {
                etlContent.textContent = 'Нет данных ETL результатов.';
            }
            
            // Скрываем индикатор загрузки
            document.getElementById('etlOutputLoader').style.display = 'none';
            
            // Обновляем интерфейс для загрузки следующих порций
            updateEtlLoadButtons(analysisId);
            
            return data;
        } catch (error) {
            console.error('Ошибка при загрузке ETL данных:', error);
            document.getElementById('etlOutputLoader').style.display = 'none';
            
            const etlContent = document.getElementById('etlOutputContent');
            if (initialLoad) {
                etlContent.textContent = `Ошибка при загрузке ETL данных: ${error.message}`;
            }
            
            return null;
        }
    }

    // Функция для обновления кнопок загрузки ETL данных
    function updateEtlLoadButtons(analysisId) {
        const container = document.getElementById('etlOutput');
        let buttonArea = document.getElementById('etlButtonArea');
        
        if (!buttonArea) {
            buttonArea = document.createElement('div');
            buttonArea.id = 'etlButtonArea';
            buttonArea.style.display = 'flex';
            buttonArea.style.flexDirection = 'column';
            buttonArea.style.gap = '10px';
            buttonArea.style.marginTop = '15px';
            buttonArea.style.padding = '10px';
            buttonArea.style.backgroundColor = '#f8f9fa';
            buttonArea.style.borderRadius = '5px';
            container.appendChild(buttonArea);
        }
        
        buttonArea.innerHTML = "";
        
        // Отображаем информацию об оставшихся строках
        const remainingCount = document.createElement('div');
        remainingCount.id = 'etlRemainingCount';
        remainingCount.style.marginBottom = '10px';
        remainingCount.style.fontWeight = 'bold';
        remainingCount.textContent = `Загружено строк: ${etlOffset} из ${etlTotal}`;
        buttonArea.appendChild(remainingCount);
        
        // Создаем контейнер для кнопок, чтобы можно было их выровнять в ряд
        const buttonsContainer = document.createElement('div');
        buttonsContainer.style.display = 'flex';
        buttonsContainer.style.gap = '10px';
        buttonsContainer.style.flexWrap = 'wrap';
        buttonArea.appendChild(buttonsContainer);
        
        // Добавляем кнопки только если есть еще данные для загрузки
        if (etlTotal > etlOffset) {
            const loadMoreBtn = document.createElement('button');
            loadMoreBtn.id = 'loadMoreEtlBtn';
            loadMoreBtn.textContent = 'Загрузить ещё 200 строк';
            loadMoreBtn.className = 'btn btn-secondary';
            loadMoreBtn.style.minWidth = '200px';
            loadMoreBtn.addEventListener('click', function() {
                loadEtlChunk(analysisId, false);
            });
            buttonsContainer.appendChild(loadMoreBtn);
        }
        
        // Добавляем кнопку скачивания полного JSON файла
        const downloadJsonBtn = document.createElement('button');
        downloadJsonBtn.id = 'downloadJsonBtn';
        downloadJsonBtn.textContent = 'Скачать полный JSON файл';
        downloadJsonBtn.className = 'btn btn-primary';
        downloadJsonBtn.style.minWidth = '200px';
        downloadJsonBtn.addEventListener('click', function() {
            window.location.href = `/analysis/download-json/${analysisId}`;
        });
        buttonsContainer.appendChild(downloadJsonBtn);
        
        // Добавляем кнопку скачивания оригинального ETL файла
        const downloadEtlBtn = document.createElement('button');
        downloadEtlBtn.id = 'downloadEtlBtn';
        downloadEtlBtn.textContent = 'Скачать оригинальный ETL файл';
        downloadEtlBtn.className = 'btn btn-info';
        downloadEtlBtn.style.minWidth = '200px';
        downloadEtlBtn.addEventListener('click', function() {
            window.location.href = `/analysis/download-etl/${analysisId}?format=etl`;
        });
        buttonsContainer.appendChild(downloadEtlBtn);
    }

    // Функция для проверки статуса конвертации ETL и запуска процесса при необходимости
    async function checkEtlConversionStatus(analysisId) {
        try {
            const etlContent = document.getElementById('etlOutputContent');
            const etlLoader = document.getElementById('etlOutputLoader');
            
            // Показываем индикатор загрузки
            etlLoader.style.display = 'block';
            etlContent.textContent = 'Проверка статуса ETL данных...';
            
            // Запрашиваем статус конвертации
            const response = await fetch(`/analysis/etl-json/${analysisId}`);
            const data = await response.json();
            
            if (response.status === 404) {
                // ETL файл не найден
                etlLoader.style.display = 'none';
                etlContent.textContent = 'ETL файл не найден. Анализ может быть не завершен.';
                return false;
            }
            
            if (data.status === 'converted') {
                // ETL уже конвертирован в JSON, можно загружать чанки
                etlLoader.style.display = 'none';
                etlContent.textContent = 'ETL данные готовы. Загрузка...';
                return true;
            } else if (data.status === 'not_converted') {
                // Требуется конвертация
                etlContent.textContent = 'Выполняется конвертация ETL данных. Это может занять некоторое время...';
                
                // Запускаем асинхронную конвертацию
                const conversionResponse = await fetch(`/analysis/convert-etl/${analysisId}`, {
                    method: 'POST'
                });
                
                const conversionData = await conversionResponse.json();
                
                if (conversionData.status === 'processing') {
                    // Конвертация запущена, устанавливаем обработчик событий WebSocket
                    setupEtlConversionWebSocket(analysisId);
                    return false;
                } else if (conversionData.status === 'completed') {
                    // Конвертация уже была выполнена ранее
                    etlLoader.style.display = 'none';
                    etlContent.textContent = 'ETL данные готовы. Загрузка...';
                    return true;
                } else {
                    etlLoader.style.display = 'none';
                    etlContent.textContent = `Ошибка: ${conversionData.error || 'Неизвестная ошибка при конвертации ETL'}`;
                    return false;
                }
            } else {
                // Неизвестный статус
                etlLoader.style.display = 'none';
                etlContent.textContent = `Неизвестный статус ETL данных: ${data.status}`;
                return false;
            }
        } catch (error) {
            console.error('Ошибка при проверке статуса ETL:', error);
            const etlLoader = document.getElementById('etlOutputLoader');
            etlLoader.style.display = 'none';
            
            const etlContent = document.getElementById('etlOutputContent');
            etlContent.textContent = `Ошибка при проверке статуса ETL данных: ${error.message}`;
            return false;
        }
    }
    
    // Функция для настройки обработчика WebSocket сообщений о конвертации
    function setupEtlConversionWebSocket(analysisId) {
        if (typeof analysisId === 'undefined' || !analysisId) {
            console.error('ID анализа не определен');
            return;
        }
        
        // Проверяем, нет ли уже активного соединения
        if (window.etlWs && window.etlWs.readyState === WebSocket.OPEN) {
            console.log('WebSocket соединение для ETL уже установлено');
            return;
        }
        
        // Создаем WebSocket соединение для конвертации ETL
        window.etlWs = new WebSocket(`ws://${window.location.host}/analysis/ws/${analysisId}`);
        
        window.etlWs.onopen = function() {
            console.log('WebSocket соединение для ETL установлено');
        };
        
        window.etlWs.onmessage = function(event) {
            const data = JSON.parse(event.data);
            console.log('Получено сообщение WebSocket для ETL:', data);
            
            if (data.event === 'etl_converted') {
                // ETL конвертирован успешно, загружаем чанки
                console.log('ETL успешно конвертирован');
                const etlLoader = document.getElementById('etlOutputLoader');
                etlLoader.style.display = 'none';
                
                const etlContent = document.getElementById('etlOutputContent');
                etlContent.textContent = 'ETL данные готовы. Загрузка...';
                
                // Загружаем данные
                loadEtlChunk(analysisId, true);
                
                // Закрываем соединение, оно больше не нужно
                window.etlWs.close();
            } else if (data.event === 'etl_conversion_error') {
                // Ошибка при конвертации
                console.error('Ошибка при конвертации ETL:', data.message);
                const etlLoader = document.getElementById('etlOutputLoader');
                etlLoader.style.display = 'none';
                
                const etlContent = document.getElementById('etlOutputContent');
                etlContent.textContent = `Ошибка при конвертации ETL: ${data.message}`;
                
                // Закрываем соединение
                window.etlWs.close();
            }
        };
        
        window.etlWs.onclose = function() {
            console.log('WebSocket соединение для ETL закрыто');
        };
        
        window.etlWs.onerror = function(error) {
            console.error('Ошибка WebSocket для ETL:', error);
            const etlLoader = document.getElementById('etlOutputLoader');
            etlLoader.style.display = 'none';
            
            const etlContent = document.getElementById('etlOutputContent');
            etlContent.textContent = 'Ошибка соединения при конвертации ETL';
        };
    }

    // Функция инициализации загрузки ETL данных
    async function initEtlDataLoad(analysisId) {
        // Сбрасываем смещение при первой загрузке
        etlOffset = 0;
        etlTotal = 0;
        
        // Проверяем статус конвертации ETL и при необходимости запускаем процесс
        const isReady = await checkEtlConversionStatus(analysisId);
        
        // Если ETL готов, загружаем данные
        if (isReady) {
            // Загружаем первую порцию данных
            loadEtlChunk(analysisId, true);
        }
    }

    // Функция обработки клика по табу ETL данных
    function setupEtlTabClickHandler(analysisId) {
        const etlTab = document.querySelector('a[href="#etlOutput"]');
        if (etlTab) {
            etlTab.addEventListener('click', function() {
                // Если данные еще не загружены, инициируем загрузку
                const etlContent = document.getElementById('etlOutputContent');
                if (etlContent.textContent === 'Нет данных ETL результатов.' || etlTotal === 0) {
                    initEtlDataLoad(analysisId);
                }
            });
        }
    }

    // Обновляем функцию showResults для инициализации загрузки ETL данных
    function loadInitialData(analysisId) {
        // Настраиваем обработчик событий для табов
        setupEtlTabClickHandler(analysisId);
        
        // Если текущий статус "completed", автоматически загружаем ETL данные
        if (window.analysisStatus === 'completed') {
            // Проверяем, активен ли таб ETL результатов
            const etlTab = document.querySelector('a[href="#etlOutput"]');
            const isEtlTabActive = etlTab?.classList.contains('active');
            
            // Если таб ETL активен или это первая загрузка, инициируем загрузку ETL данных
            if (isEtlTabActive || document.getElementById('etlOutputContent').textContent === '') {
                initEtlDataLoad(analysisId);
            }
        }
    }

    if (typeof analysisId !== "undefined" && analysisId) {
        console.log("Загружаем результаты анализа:", analysisId);
        showResults(analysisId);
        loadInitialData(analysisId);
        // setInterval(() => {
        //     updateDockerLogs(analysisId);
        // }, 5000);
    }

    // async function updateDockerLogs(analysisId) {
    //     try {
    //         const response = await fetch(`/results/${analysisId}`, {
    //             headers: token ? { 'Authorization': `Bearer ${token}` } : {}
    //         });
    //         if (!response.ok) {
    //             console.error("Ошибка при получении логов докера:", response.status);
    //             return;
    //         }
    //         const data = await response.json();
    //         if (data.docker_output) {
    //             dockerOutputContent.textContent = data.docker_output;
    //         } else {
    //             dockerOutputContent.textContent = 'Нет логов Docker.';
    //         }
    //         updateStatus("completed");
    //         const dockerLoader = document.getElementById('dockerOutputLoader');
    //         if (dockerLoader) dockerLoader.style.display = 'none';
    //     } catch (error) {
    //         console.error("Ошибка при обновлении логов докера:", error);
    //     }
    // }


    if (analysisId) {
        const ws = new WebSocket(`ws://${window.location.host}/analysis/ws/${analysisId}`);
        ws.onopen = function() {
            console.log("WebSocket connection established");
        };
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.status === 'completed') {
                location.reload();  
            }
        };
        ws.onclose = function() {
            console.log("WebSocket connection closed");
        };
        ws.onerror = function(error) {
            console.error("WebSocket Error:", error);
        };
    }

    document.getElementById('profileIcon').addEventListener('click', function() {
        const logoutBtn = document.getElementById('logoutBtnProfile');
        const changePasswordBtn = document.getElementById('changePasswordBtn');
        if (logoutBtn.style.display === 'none') {
            logoutBtn.style.display = 'block';
            changePasswordBtn.style.display = 'block';
        } else {
            logoutBtn.style.display = 'none';
            changePasswordBtn.style.display = 'none';
        }
    });

    document.getElementById('logoutBtnProfile').addEventListener('click', function() {
        console.log('Выход из аккаунта');
        fetch('/users/logout', {
            method: 'POST',
            credentials: 'include'
        }).then(response => {
            if (response.ok) {
                window.location.href = '/'; 
            }
        });
    });

    document.getElementById('changePasswordBtn').addEventListener('click', function() {
        window.location.href = '/users/reset-password';
    });
});