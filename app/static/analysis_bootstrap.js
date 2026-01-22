console.log("analysis_bootstrap.js loaded");

document.addEventListener('DOMContentLoaded', function() {
    const analysisId = window.analysisId;

    const ctx = {
        analysisId,
        dropZone: document.getElementById('dropZone'),
        fileInput: document.getElementById('fileInput'),
        progressBar: document.getElementById('progressBar'),
        progress: document.getElementById('progress'),
        resultsSection: document.getElementById('resultsSection'),
        analysisStatusEl: document.getElementById('analysisStatus'),
        dockerOutputContent: document.getElementById('dockerOutputContent'),
        statusSpinner: document.getElementById('statusSpinner'),
        refreshHistoryBtn: document.getElementById('refreshHistory'),
        token: localStorage.getItem('access_token'),
        fileActivityOffset: 0,
        FILE_ACTIVITY_LIMIT: 500,
        fileActivityTotal: 0,
        etlOffset: 0,
        ETL_CHUNK_LIMIT: 200,
        etlTotal: 0,
        cleanTreeLoaded: false,
        cleanTreeRowCount: 0,
    };

    window.ftAnalysisCtx = ctx;

    if (typeof window.ftAnalysisInitUpload === 'function') {
        window.ftAnalysisInitUpload(ctx);
    }
    if (typeof window.ftAnalysisInitHistory === 'function') {
        window.ftAnalysisInitHistory(ctx);
    }
    if (typeof window.ftAnalysisInitMeta === 'function') {
        window.ftAnalysisInitMeta(ctx);
    }
    if (typeof window.ftAnalysisInitResults === 'function') {
        window.ftAnalysisInitResults(ctx);
    }
    if (typeof window.ftAnalysisInitProfile === 'function') {
        window.ftAnalysisInitProfile(ctx);
    }
});
