// Live view of the request log: polls /logs/live for entries newer than the last one shown and adds them at the top.
// Progressive enhancement: without JavaScript the page works with its Refresh link. Rows are built with textContent
// only (never HTML from the server), and the file is same-origin, so the strict Content-Security-Policy applies.
(() => {
    'use strict';

    const interval = 2000;
    const storageKey = 'waf-log-live';
    let timer = null;
    let state = null;

    const stop = () => {
        if (timer !== null) {
            clearTimeout(timer);
            timer = null;
        }
    };

    const setStatus = (text) => {
        const status = document.getElementById('live-status');
        if (status) {
            status.textContent = text;
        }
    };

    const cell = (text, className) => {
        const td = document.createElement('td');
        if (className) {
            td.className = className;
        }
        if (text !== null && text !== undefined) {
            td.textContent = text;
        }
        return td;
    };

    const badge = (text, className) => {
        const span = document.createElement('span');
        span.className = 'badge ' + className;
        span.textContent = text;
        return span;
    };

    const row = (item) => {
        const tr = document.createElement('tr');
        tr.className = 'live-new';

        const time = cell(null, 'nowrap');
        const link = document.createElement('a');
        link.href = item.url;
        link.textContent = item.time;
        time.append(link);

        const request = cell(null, 'log-request');
        const method = document.createElement('span');
        method.className = 'method';
        method.textContent = item.method;
        const path = document.createElement('span');
        path.className = 'path';
        path.textContent = item.path;
        request.append(method, ' ' + item.host, path);

        const outcome = cell(null);
        outcome.append(badge(item.outcome, item.outcomeBadge));
        if (item.note) {
            outcome.append(' ', badge(item.note, item.noteBadge));
        }

        tr.append(time, cell(item.clientIp), request, cell(item.route ?? ''), outcome, cell(item.rule ?? ''), cell(String(item.status)), cell(item.latency, 'nowrap'));
        return tr;
    };

    const poll = async () => {
        timer = null;
        const current = state;
        if (!current) {
            return;
        }

        if (document.hidden) {
            timer = setTimeout(poll, interval); // no work while the tab is in the background
            return;
        }

        const separator = current.url.includes('?') ? '&' : '?';
        try {
            const response = await fetch(current.url + separator + 'after=' + current.after, {
                headers: { Accept: 'application/json' },
                credentials: 'same-origin',
            });
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }

            const data = await response.json();
            if (state !== current) {
                return; // navigated away meanwhile
            }

            current.after = data.latest;
            if (data.items.length > 0) {
                const body = current.table.tBodies[0];
                for (const item of data.items) {
                    body.insertBefore(row(item), body.firstChild);
                }
                while (body.rows.length > current.max) {
                    body.deleteRow(-1);
                }
                current.table.hidden = false;
                document.getElementById('log-empty')?.remove();
            }

            setStatus('updated ' + new Date().toLocaleTimeString());
            timer = setTimeout(poll, data.more ? 200 : interval);
        } catch {
            setStatus('paused: the gateway could not be reached; retrying');
            timer = setTimeout(poll, interval * 3);
        }
    };

    const init = () => {
        stop();
        state = null;
        const table = document.querySelector('[data-live-log]');
        const toggle = document.getElementById('live-toggle');
        const checkbox = document.getElementById('live');
        if (!table || !toggle || !checkbox) {
            return;
        }

        state = {
            table,
            url: table.dataset.liveUrl,
            after: Number(table.dataset.liveAfter) || 0,
            max: Number(table.dataset.liveMax) || 200,
        };
        toggle.hidden = false;

        checkbox.addEventListener('change', () => {
            stop();
            if (checkbox.checked) {
                sessionStorage.setItem(storageKey, '1');
                poll();
            } else {
                sessionStorage.removeItem(storageKey);
                setStatus('');
            }
        });

        // On when chosen earlier in this tab, or with ?live=1 in the address (bookmarkable).
        if (sessionStorage.getItem(storageKey) === '1' || new URLSearchParams(location.search).get('live') === '1') {
            checkbox.checked = true;
            poll();
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Blazor's enhanced navigation replaces the page content without reloading scripts.
    if (window.Blazor && typeof window.Blazor.addEventListener === 'function') {
        window.Blazor.addEventListener('enhancedload', init);
    }
})();
