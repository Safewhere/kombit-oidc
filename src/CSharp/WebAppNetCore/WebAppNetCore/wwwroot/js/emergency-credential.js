(() => {
    'use strict';
    const root = document.getElementById('emergency');
    if (!root) return;
    const base = root.dataset.base;
    const csrf = root.querySelector('input[name="__RequestVerificationToken"]').value;
    const message = (text, tone = '') => { const status = document.getElementById('message'); status.textContent = text; status.dataset.tone = tone; };
    const element = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text != null) node.textContent = text; return node; };
    const badge = (status, text) => { const node = element('span', 'em-badge', text); node.dataset.status = status; return node; };
    document.querySelectorAll('time[data-local]').forEach(time => { const date = new Date(time.getAttribute('datetime')); if (!isNaN(date)) time.textContent = date.toLocaleString(); });
    const decode = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0));
    const encode = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const traceKey = 'oidc-emergency-issuer-results-v1';
    let callHistory = [];
    try { const saved = JSON.parse(sessionStorage.getItem(traceKey) || '[]'); if (Array.isArray(saved)) callHistory = saved.slice(-40).filter(x => typeof x === 'string').map(x => x.slice(0, 600)); } catch (_) { }
    function renderIssuerCalls() {
        const list = document.getElementById('issuer-call-results');
        if (!list) return;
        list.replaceChildren();
        for (const text of callHistory.slice().reverse()) { const item = document.createElement('li'); item.textContent = text; list.append(item); }
        if (!callHistory.length) { const item = document.createElement('li'); item.className = 'em-empty'; item.textContent = 'No calls recorded in this tab yet. Perform preparation, renewal, or removal to see Identify results.'; list.append(item); }
    }
    function recordIssuerCalls(response) {
        try {
            const header = response.headers.get('X-Emergency-Issuer-Calls');
            const stamp = new Date().toLocaleTimeString();
            if (!header) callHistory.push(stamp + ' \u2014 No issuer diagnostics received (older server or request rejected before the handler).');
            else {
                const calls = JSON.parse(atob(header));
                if (!Array.isArray(calls)) return;
                if (!calls.length) callHistory.push(stamp + ' \u2014 Local request: HTTP ' + response.status + '; no Identify endpoint called.');
                for (const call of calls.slice(-8)) callHistory.push((stamp + ' \u2014 ' + call.method + ' ' + call.endpoint + ' \u2014 ' + (call.status == null ? 'no HTTP status' : 'HTTP ' + call.status) + ' \u2014 ' + call.milliseconds + ' ms \u2014 ' + call.summary).slice(0, 600));
            }
            callHistory = callHistory.slice(-40);
            try { sessionStorage.setItem(traceKey, JSON.stringify(callHistory)); } catch (_) { }
            renderIssuerCalls();
        } catch (_) { /* Diagnostics must never interrupt authentication. */ }
    }
    const clearTrace = document.getElementById('clear-issuer-diagnostics');
    if (clearTrace) clearTrace.addEventListener('click', () => { callHistory = []; try { sessionStorage.removeItem(traceKey); } catch (_) { } renderIssuerCalls(); });
    renderIssuerCalls();


    function setPreparationState(canPrepare) {
        const login = document.getElementById('normal-login-step');
        const prepare = document.getElementById('prepare-step');
        const button = document.getElementById('prepare');
        if (!login || !prepare || !button) return;
        login.hidden = canPrepare;
        prepare.hidden = !canPrepare;
        button.disabled = !canPrepare;
    }

    async function api(path, body = {}) {
        if (path === "enrollments" || path === "renewals") setPreparationState(false);
        const response = await fetch(base + '/' + path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Emergency-CSRF': csrf }, body: JSON.stringify(body), redirect: 'error' });
        recordIssuerCalls(response);
        const data = response.status === 204 ? {} : await response.json();
        if (!response.ok) { if (data.error === 'new_normal_login_required' || data.error === 'normal_login_required') setPreparationState(false); const failure = new Error(data.error || 'Request failed'); failure.reference = /^[a-f0-9]{32}$/.test(data.reference_id || '') ? data.reference_id : null; throw failure; }
        return data;
    }
    const safe = action => async event => {
        if (event) event.preventDefault();
        try { message('Working\u2026', 'busy'); await action(); if (document.getElementById('message').textContent === 'Working\u2026') message(''); } catch (error) { message(error.message === 'new_normal_login_required' ? 'Emergency preparation needs a fresh normal login. Use the Get a new normal login for preparation or renewal button, then try again.' : error.name === 'NotAllowedError' ? 'Key check cancelled. Preparation is not complete.' : error.message || 'Operation failed.', 'error'); if (error.reference) document.getElementById('message').textContent += ' Reference: ' + error.reference; }
    };
    function bind(id, action, event = 'click') { const element = document.getElementById(id); if (element) element.addEventListener(event, safe(action)); }

    async function deleteStoredBinding(bindingId) {
        const db = await new Promise((resolve, reject) => {
            const request = indexedDB.open('oidc-emergency-v1', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('credentials', { keyPath: 'ec_id' });
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new Error('Browser storage is unavailable.'));
        });
        try {
            await new Promise((resolve, reject) => {
                const transaction = db.transaction('credentials', 'readwrite');
                const cursor = transaction.objectStore('credentials').openCursor();
                cursor.onsuccess = () => {
                    const item = cursor.result;
                    if (!item) return;
                    if (item.value.binding_id === bindingId) item.delete();
                    item.continue();
                };
                transaction.oncomplete = resolve;
                transaction.onerror = transaction.onabort = () => reject(new Error('Key removed from the server, but browser cleanup failed. Retry browser cleanup before using emergency login.'));
            });
        } finally { db.close(); }
    }

    async function database() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('oidc-emergency-v1', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('credentials', { keyPath: 'ec_id' });
            request.onsuccess = () => resolve(request.result); request.onerror = () => reject(new Error('Browser storage is unavailable.'));
        });
    }
    async function stored(write, record) {
        const db = await database();
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction('credentials', write ? 'readwrite' : 'readonly');
                const store = tx.objectStore('credentials');
                const request = write ? store.put(record) : store.getAll();
                tx.oncomplete = () => resolve(request.result); tx.onerror = tx.onabort = () => reject(new Error('Browser storage failed. Credential is not ready.'));
            });
        } finally { db.close(); }
    }
    function assertionOptions(options) {
        options.challenge = decode(options.challenge);
        options.allowCredentials.forEach(credential => credential.id = decode(credential.id));
        return options;
    }
    function assertionResponse(credential) {
        return { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { clientDataJSON: encode(credential.response.clientDataJSON), authenticatorData: encode(credential.response.authenticatorData), signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null }, clientExtensionResults: credential.getClientExtensionResults() };
    }
    async function possession(record, login) {
        const prefix = login ? 'login' : 'possession';
        const challenge = await api(prefix + '/options', { emergency_credential: record.emergency_credential });
        const credential = await navigator.credentials.get({ publicKey: assertionOptions(challenge.publicKey) });
        const result = await api(prefix + '/complete', { transaction_id: challenge.transaction_id, credential: assertionResponse(credential) });
        if (login) { location.assign(result.redirect); return; }
        message('Ready. This browser and key can be used for emergency login.', 'success');
        await list();
    }
    async function saveAndActivate(record) {
        const durable = navigator.storage && navigator.storage.persist ? await navigator.storage.persist() : false;
        document.getElementById('storage-warning').textContent = durable ? 'Persistent storage granted. Clearing site data still removes preparation.' : 'Persistent storage was not granted. Browser cleanup or eviction can remove preparation.';
        await stored(true, record);
        const readBack = (await stored(false)).find(item => item.ec_id === record.ec_id);
        if (!readBack || readBack.emergency_credential !== record.emergency_credential) throw new Error('Storage read-back failed. Credential is not ready.');
        message('Stored, pending possession. Check your key again to activate.', 'busy');
        await possession(readBack, false);
    }
    bind('prepare', async () => {
        let enrollment;
        try {
            enrollment = await api('enrollments');
            const options = enrollment.publicKey;
            options.challenge = decode(options.challenge); options.user.id = decode(options.user.id);
            (options.excludeCredentials || []).forEach(credential => credential.id = decode(credential.id));
            const credential = await navigator.credentials.create({ publicKey: options });
            const record = await api('enrollments/' + encodeURIComponent(enrollment.enrollment_id) + '/complete', { credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response: { clientDataJSON: encode(credential.response.clientDataJSON), attestationObject: encode(credential.response.attestationObject), transports: credential.response.getTransports ? credential.response.getTransports() : [] }, clientExtensionResults: credential.getClientExtensionResults() } });
            enrollment = null;
            await saveAndActivate(record);
        } finally {
            if (enrollment) { try { await api('enrollments/' + encodeURIComponent(enrollment.enrollment_id) + '/cancel'); } catch (_) { } }
        }
    });
    function button(text, action, className) { const button = element('button', className, text); button.type = 'button'; button.addEventListener('click', safe(action)); return button; }
    const statusLabels = { active: 'Active', pending: 'Pending confirmation', blocked: 'Blocked', expired: 'Expired' };
    async function list() {
        const ul = document.getElementById('credentials');
        if (!ul) return;
        const records = await stored(false);
        const status = root.dataset.mode === 'prepare' ? await api('status') : null;
        if (status) setPreparationState(status.can_prepare === true);
        ul.replaceChildren();
        for (const record of records) {
            const entry = status && status.credentials.find(item => item.ec_id === record.ec_id);
            if (status && !entry) continue;
            const expired = record.expires_at * 1000 <= Date.now();
            if (root.dataset.mode === 'login' && (expired || (await api('login/status', { emergency_credential: record.emergency_credential })).active !== true)) continue;
            const row = element('li', 'em-credential');
            const head = element('div', 'em-credential-head');
            head.append(element('span', 'em-credential-name', 'Key \u2026' + record.binding_id.slice(-6)));
            if (entry) head.append(badge(entry.status, statusLabels[entry.status] || entry.status));
            else head.append(badge('active', 'Active'));
            if (entry && entry.status === 'active' && entry.renew_soon) head.append(badge('renew', 'Renew soon'));
            row.append(head, element('p', 'em-credential-meta', 'Expires ' + new Date(record.expires_at * 1000).toLocaleString() + (entry ? '' : ' \u00b7 the server checks status on use')));
            const actions = element('div', 'em-actions');
            if (root.dataset.mode === 'login') {
                if (!expired) actions.append(button('Log in with this key', () => possession(record, true), 'em-primary'));
            } else {
                const binding = element('p', 'em-credential-meta', 'Binding ID ');
                binding.append(element('code', null, record.binding_id));
                row.append(binding);
                if (entry.status === 'pending') actions.append(button('Confirm stored credential', () => possession(record, false), 'em-primary'));
                if (entry.status === 'active' && status.can_prepare) actions.append(button('Renew with this key', async () => saveAndActivate(await api('renewals', { binding_id: record.binding_id }))));
                actions.append(button('Remove key locally', async () => { await api('keys/' + encodeURIComponent(record.binding_id) + '/remove'); await deleteStoredBinding(record.binding_id); message('Key removed from this browser and the local registry. Any failed issuer report remains queued.', 'success'); await list(); }, 'em-danger'));
            }
            if (actions.children.length) row.append(actions);
            ul.append(row);
        }
        // A lost browser copy must not hide the account's server registration.
        if (status) {
            const missing = new Map();
            for (const entry of status.credentials) {
                if (!records.some(record => record.binding_id === entry.binding_id && status.credentials.some(item => item.ec_id === record.ec_id))) missing.set(entry.binding_id, entry);
            }
            for (const entry of missing.values()) {
                const row = element('li', 'em-credential');
                row.append(element('span', 'em-credential-name', 'Key \u2026' + entry.binding_id.slice(-6)),
                    element('p', 'em-credential-meta', 'Browser copy missing. Remove this registration before preparing the same authenticator again. This also ends its emergency sessions in other browsers.'));
                row.append(button('Remove key locally', async () => {
                    if (!confirm('Remove registration for key \u2026' + entry.binding_id.slice(-6) + ' and end its emergency sessions?')) return;
                    await api('keys/' + encodeURIComponent(entry.binding_id) + '/remove');
                    await deleteStoredBinding(entry.binding_id);
                    message('Registration removed locally. If Identify is unavailable, its revocation is queued; wait for it to synchronize before preparing this key again.', 'success');
                    await list();
                }, 'em-danger'));
                ul.append(row);
            }
        }
        if (!ul.children.length) { const empty = element('li', 'em-empty'); empty.textContent =status && status.can_prepare ? 'This browser has no stored emergency credential yet. Choose Prepare this browser to create one.' : root.dataset.mode === 'prepare' ? 'This browser has no matching stored credential. Get a new normal login to prepare it.' : 'This browser has no active emergency key. Prepare or confirm a key during a normal login.'; ul.append(empty); }
    }
    bind('signout', async () => { const result = await api('signout'); location.assign(result.redirect); });
    if (root.dataset.mode === 'prepare' || root.dataset.mode === 'login') safe(list)();
})();
