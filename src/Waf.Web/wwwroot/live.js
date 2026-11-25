// Live traffic on the dashboard: connects to the gateway's SignalR hub (hubs/traffic) and shows the numbers it pushes
// every second. Progressive enhancement: without JavaScript the card says so and the page works as before. Texts come
// from the page (data-text-* attributes, already in the admin's language); everything is written with textContent
// (never HTML), and all files are same-origin, so the strict Content-Security-Policy applies.
(() => {
    'use strict';

    let connection = null;
    let root = null;

    const text = (name) => (root && root.dataset['text' + name]) || '';

    const setStatus = (name, state) => {
        const status = root && root.querySelector('[data-live="status"]');
        if (status) {
            status.textContent = text(name);
            status.dataset.state = state;
        }
    };

    const format = (value) => new Intl.NumberFormat(document.documentElement.lang || undefined).format(value);

    const set = (name, value) => {
        const element = root && root.querySelector(`[data-live="${name}"]`);
        if (element) {
            element.textContent = value;
        }
    };

    const show = (snapshot) => {
        if (!root) {
            return;
        }

        set('total', format(snapshot.total));
        set('good', format(snapshot.good));
        set('bad', format(snapshot.bad));
        set('failed', format(snapshot.failed));

        const list = root.querySelector('[data-live="sources"]');
        if (list) {
            list.replaceChildren(...snapshot.topSources.slice(0, 5).map((source) => {
                const item = document.createElement('li');
                const address = document.createElement('code');
                address.textContent = source.source;
                item.append(address, ' ' + format(source.count));
                return item;
            }));
            const empty = root.querySelector('[data-live="no-sources"]');
            if (empty) {
                empty.hidden = snapshot.topSources.length > 0;
            }
        }

        setStatus('Live', 'live');
    };

    // Retry every 1, 2, 4, 8, 16, then 30 seconds, without end: a restarted gateway is found again.
    const retry = {
        nextRetryDelayInMilliseconds: (context) => Math.min(30000, 1000 * 2 ** Math.min(context.previousRetryCount, 5)),
    };

    const stop = () => {
        if (connection) {
            const old = connection;
            connection = null;
            old.stop();
        }
    };

    const watch = () => connection.invoke('Watch', root.dataset.route || null);

    const start = async () => {
        if (!window.signalR) {
            return;
        }

        connection = new signalR.HubConnectionBuilder()
            .withUrl(root.dataset.hub)
            .withAutomaticReconnect(retry)
            .configureLogging(signalR.LogLevel.None)
            .build();
        const current = connection;
        current.on('snapshot', show);
        current.on('sessionEnded', () => {
            setStatus('Ended', 'ended');
            stop();
        });
        current.onreconnecting(() => setStatus('Reconnecting', 'reconnecting'));
        current.onreconnected(() => watch().catch(() => {}));
        current.onclose(() => {
            if (connection === current) {
                // Gave up (should not happen with endless retries) or the server closed it: try again later.
                setStatus('Reconnecting', 'reconnecting');
                connection = null;
                setTimeout(init, 30000);
            }
        });

        setStatus('Connecting', 'connecting');
        try {
            await current.start();
            await watch();
        } catch {
            if (connection === current) {
                connection = null;
                setStatus('Reconnecting', 'reconnecting');
                setTimeout(init, 5000);
            }
        }
    };

    const init = () => {
        const found = document.getElementById('live-traffic');
        if (!found) {
            root = null;
            stop(); // left the dashboard (enhanced navigation keeps this script running)
            return;
        }

        if (found === root && connection) {
            return;
        }

        stop();
        root = found;
        start();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    if (window.Blazor && typeof window.Blazor.addEventListener === 'function') {
        window.Blazor.addEventListener('enhancedload', init);
    }
})();
