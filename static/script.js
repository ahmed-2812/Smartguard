/* ============================================================
   SmartGuard - script.js
   ============================================================ */

(function () {
    'use strict';

    /* ---- Dark mode ---- */
    const STORAGE_KEY = 'sg-theme';
    const html = document.documentElement;

    // SVG paths for the two icons
    const MOON_PATH = 'M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z';
    const SUN_PATH  = 'M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4.22 1.47a1 1 0 011.42 1.42l-.7.7a1 1 0 11-1.42-1.42l.7-.7zM18 9a1 1 0 110 2h-1a1 1 0 110-2h1zM5.78 3.47a1 1 0 00-1.42 1.42l.7.7a1 1 0 001.42-1.42l-.7-.7zM3 9a1 1 0 100 2H2a1 1 0 100-2h1zm1.22 5.78a1 1 0 011.42 0l.7.7a1 1 0 01-1.42 1.42l-.7-.7a1 1 0 010-1.42zM10 16a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zm5.78-1.22a1 1 0 010 1.42l-.7.7a1 1 0 01-1.42-1.42l.7-.7a1 1 0 011.42 0zM10 6a4 4 0 100 8 4 4 0 000-8z';

    function applyTheme(theme) {
        html.setAttribute('data-theme', theme);
        const icon  = document.getElementById('theme-icon');
        const label = document.getElementById('theme-label');
        if (!icon || !label) return;
        const path = icon.querySelector('path');
        if (theme === 'dark') {
            if (path) path.setAttribute('d', SUN_PATH);
            label.textContent = 'Light';
        } else {
            if (path) path.setAttribute('d', MOON_PATH);
            label.textContent = 'Dark';
        }
    }

    // Load saved preference, falling back to OS preference
    const saved = localStorage.getItem(STORAGE_KEY);
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(saved || (prefersDark ? 'dark' : 'light'));

    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            localStorage.setItem(STORAGE_KEY, next);
            applyTheme(next);
        });
    }

    /* ---- Tab switching (index page) ---- */
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanels = {
        upload: document.getElementById('tab-upload'),
        paste:  document.getElementById('tab-paste'),
    };

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const target = btn.dataset.tab;
            Object.entries(tabPanels).forEach(([key, panel]) => {
                if (!panel) return;
                panel.classList.toggle('hidden', key !== target);
            });
        });
    });

    /* ---- Drag-and-drop ---- */
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileNameLabel = document.getElementById('file-name-label');

    if (dropZone) {
        ['dragenter', 'dragover'].forEach(evt =>
            dropZone.addEventListener(evt, e => { e.preventDefault(); dropZone.classList.add('dragover'); })
        );
        ['dragleave', 'drop'].forEach(evt =>
            dropZone.addEventListener(evt, e => { e.preventDefault(); dropZone.classList.remove('dragover'); })
        );
        dropZone.addEventListener('drop', e => {
            const files = e.dataTransfer.files;
            if (files.length) handleFileSelect(files[0]);
        });
        dropZone.addEventListener('click', e => {
            // avoid triggering click on label children
            if (e.target.tagName !== 'LABEL') fileInput && fileInput.click();
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) handleFileSelect(fileInput.files[0]);
        });
    }

    function handleFileSelect(file) {
        if (!file.name.endsWith('.rs')) {
            showError('Only .rs (Rust) files are accepted.');
            return;
        }
        if (fileNameLabel) fileNameLabel.textContent = file.name;
        // Store on the input element for form submission
        if (fileInput) {
            const dt = new DataTransfer();
            dt.items.add(file);
            fileInput.files = dt.files;
        }
    }

    /* ---- Form submission ---- */
    const form = document.getElementById('analyze-form');
    const analyzeBtn = document.getElementById('analyze-btn');
    const btnText = analyzeBtn ? analyzeBtn.querySelector('.btn-text') : null;
    const btnSpinner = document.getElementById('btn-spinner');

    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();
            clearError();

            const activeTab = document.querySelector('.tab-btn.active');
            const tab = activeTab ? activeTab.dataset.tab : 'upload';

            const formData = new FormData();

            if (tab === 'upload') {
                if (!fileInput || !fileInput.files.length) {
                    showError('Please select a .rs file to upload.');
                    return;
                }
                formData.append('file', fileInput.files[0]);
            } else {
                const codeInput = document.getElementById('code-input');
                const code = codeInput ? codeInput.value.trim() : '';
                if (!code) {
                    showError('Please paste some Rust code before analysing.');
                    return;
                }
                formData.append('code', code);
            }

            setLoading(true);

            try {
                const resp = await fetch('/analyze', { method: 'POST', body: formData });
                const data = await resp.json();

                if (!resp.ok) {
                    showError(data.error || 'An unknown error occurred.');
                    setLoading(false);
                    return;
                }

                // Store results and redirect
                sessionStorage.setItem('sg_findings', JSON.stringify(data.findings));
                sessionStorage.setItem('sg_summary', JSON.stringify(data.summary));
                window.location.href = '/results';
            } catch (err) {
                showError('Network error: ' + err.message);
                setLoading(false);
            }
        });
    }

    /* ---- Results page: filter buttons ---- */
    const filterBtns = document.querySelectorAll('.filter-btn');
    const findingCards = document.querySelectorAll('.finding-card');

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const sev = btn.dataset.sev;
            findingCards.forEach(card => {
                const show = sev === 'ALL' || card.dataset.severity === sev;
                card.style.display = show ? '' : 'none';
            });
        });
    });

    /* ---- Helpers ---- */
    function showError(msg) {
        const banner = document.getElementById('error-banner');
        if (banner) { banner.textContent = msg; banner.classList.remove('hidden'); }
    }

    function clearError() {
        const banner = document.getElementById('error-banner');
        if (banner) banner.classList.add('hidden');
    }

    function setLoading(loading) {
        if (!analyzeBtn) return;
        analyzeBtn.disabled = loading;
        if (btnText) btnText.textContent = loading ? 'Analysing...' : 'Analyze Contract';
        if (btnSpinner) btnSpinner.classList.toggle('hidden', !loading);
    }
})();
