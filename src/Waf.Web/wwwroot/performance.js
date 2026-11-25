// Charts of the Performance page (uPlot), and the live view (SignalR hub hubs/traffic).
// Progressive enhancement: without JavaScript the page shows the same numbers in tables. The data comes from the page
// itself (data-chart, JSON written by the server); texts come from data-text-* attributes in the admin's language.
// Nothing is built from HTML strings, and all files are same-origin, so the strict Content-Security-Policy applies.
(() => {
    'use strict';

    const liveSeconds = 300;
    let root = null;
    let chart = null;
    let latencyChart = null;
    let connection = null;
    let resizeObserver = null;
    let state = null;

    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    const lang = () => document.documentElement.lang || undefined;
    const number = (value, digits = 1) =>
        value === null || value === undefined ? '–' : new Intl.NumberFormat(lang(), { maximumFractionDigits: digits }).format(value);
    const percent = (part, total) =>
        new Intl.NumberFormat(lang(), { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(total > 0 ? part / total : 0);
    const text = (name) => (root && root.dataset['text' + name]) || '';
    const css = (name, fallback) => getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;

    // Opaque fills, so the stacked layers do not mix; bad is hatched and failed dotted, so they differ without colour.
    const fill = (background, color, kind) => {
        const tile = document.createElement('canvas');
        tile.width = 8;
        tile.height = 8;
        const g = tile.getContext('2d');
        g.fillStyle = background;
        g.fillRect(0, 0, 8, 8);
        g.strokeStyle = color;
        g.fillStyle = color;
        g.lineWidth = 1.5;
        if (kind === 'hatch') {
            g.beginPath();
            g.moveTo(-2, 10);
            g.lineTo(10, -2);
            g.stroke();
        } else if (kind === 'dots') {
            g.fillRect(3, 3, 2, 2);
        }
        return g.createPattern(tile, 'repeat');
    };

    const setStatus = (name, stateName) => {
        const status = document.querySelector('#perf-chart ~ [data-live="status"]');
        if (status) {
            status.textContent = text(name);
            status.dataset.state = stateName;
        }
    };

    const setFigure = (name, value) => {
        const element = document.querySelector(`#perf-figures [data-live="${name}"]`);
        if (element) {
            element.textContent = value;
        }
    };

    // Rates per second from the buckets: [start, seconds, good, bad, failed, peak].
    const series = () => {
        const b = state.buckets;
        const rate = (i, value) => (b[i][1] > 0 ? value / b[i][1] : 0);
        const x = b.map((row) => row[0]);
        const good = b.map((row, i) => rate(i, row[2]));
        const bad = b.map((row, i) => rate(i, row[3]));
        const failed = b.map((row, i) => rate(i, row[4]));
        const data = [
            x,
            good.map((v, i) => v + bad[i] + failed[i]), // top of the stack: everything
            bad.map((v, i) => v + failed[i]),
            failed,
        ];
        if (state.hasPeaks) {
            data.push(b.map((row) => row[5]));
        }
        if (state.previous) {
            data.push(b.map((row, i) => (state.previous[i] ? state.previous[i][2] / Math.max(1, state.previous[i][1]) : null)));
        }
        return { data, good, bad, failed };
    };

    // Time axis labels in the admin's language: dates for long periods, times (with seconds for short ones) otherwise.
    const timeLabels = (u, ticks) => {
        const span = u.scales.x.max - u.scales.x.min;
        return ticks.map((tick) => {
            const moment = new Date(tick * 1000);
            if (span > 2 * 86400) {
                return moment.toLocaleDateString(lang(), span > 400 * 86400
                    ? { year: 'numeric', month: 'short' }
                    : { month: 'short', day: 'numeric' });
            }
            return moment.toLocaleTimeString(lang(), span < 600
                ? { hour: '2-digit', minute: '2-digit', second: '2-digit' }
                : { hour: '2-digit', minute: '2-digit' });
        });
    };

    const options = (width, values) => {
        const ok = css('--ok', '#1d7a46');
        const danger = css('--danger', '#b3261e');
        const warn = css('--warn', '#8a5a00');
        const muted = css('--muted', '#5b6574');
        const border = css('--border', '#d9dee5');
        const surface = css('--surface', '#ffffff');
        const textColor = css('--text', '#1d2430');
        const okBg = css('--ok-bg', '#e5f4eb');
        const dangerBg = css('--danger-bg', '#fde8e7');
        const warnBg = css('--warn-bg', '#fff4d6');
        const shown = (list) => (u, v, si, i) => (i === null || i === undefined ? '–' : number(list[i]));

        const s = [
            { value: (u, v) => (v === null ? '–' : new Date(v * 1000).toLocaleString(lang())) },
            { label: text('Good'), stroke: ok, width: 1, fill: okBg, value: shown(values.good) },
            { label: text('Bad'), stroke: danger, width: 1, fill: fill(dangerBg, danger, 'hatch'), value: shown(values.bad) },
            { label: text('Failed'), stroke: warn, width: 1, fill: fill(warnBg, warn, 'dots'), value: shown(values.failed) },
        ];
        if (state.hasPeaks) {
            s.push({ label: text('Peak'), stroke: textColor, width: 1, dash: [2, 3], value: (u, v) => number(v, 0) });
        }
        if (state.previous) {
            s.push({ label: text('Previous'), stroke: muted, width: 1.5, dash: [6, 4], value: (u, v) => number(v) });
        }

        const axis = { stroke: textColor, grid: { stroke: border, width: 1 }, ticks: { stroke: border, width: 1 } };
        return {
            width,
            height: width < 600 ? 220 : 300,
            series: s,
            axes: [{ ...axis, values: timeLabels }, { ...axis, values: (u, ticks) => ticks.map((t) => number(t)) }],
            scales: { x: { time: true }, y: { range: (u, min, max) => [0, Math.max(1, max * 1.1)] } },
            cursor: { drag: { x: !state.live, y: false, setScale: false } },
            legend: { live: true },
            hooks: {
                setSelect: [
                    (u) => {
                        if (state.live || u.select.width < 8) {
                            return;
                        }
                        const from = Math.floor(u.posToVal(u.select.left, 'x'));
                        const to = Math.ceil(u.posToVal(u.select.left + u.select.width, 'x'));
                        const url = new URL(window.location.href);
                        url.searchParams.set('period', 'custom');
                        url.searchParams.set('from', String(from));
                        url.searchParams.set('to', String(to));
                        window.location.assign(url.toString());
                    },
                ],
            },
            // The chart's own background, for the canvas (theme colours).
            plugins: [background(), failoverBands(state.failovers)],
        };
    };

    // The chart's own background, for the canvas (theme colours).
    const background = () => ({
        hooks: {
            drawClear: (u) => {
                u.ctx.fillStyle = css('--surface', '#ffffff');
                u.ctx.fillRect(0, 0, u.ctx.canvas.width, u.ctx.canvas.height);
            },
        },
    });

    // Periods in which a route ran on its failover: shaded bands behind the series, with a line on top.
    const failoverBands = (periods) => ({
        hooks: {
            drawAxes: (u) => {
                if (!periods || periods.length === 0) {
                    return;
                }
                const g = u.ctx;
                const { left, top, width, height } = u.bbox;
                const now = Date.now() / 1000;
                g.save();
                for (const [start, end] of periods) {
                    const x0 = Math.max(left, u.valToPos(start, 'x', true));
                    const x1 = Math.min(left + width, u.valToPos(end ?? now, 'x', true));
                    if (x1 <= x0) {
                        continue;
                    }
                    g.fillStyle = css('--warn-bg', '#fff4d6');
                    g.fillRect(x0, top, x1 - x0, height);
                    g.fillStyle = css('--warn', '#8a5a00');
                    g.fillRect(x0, top, x1 - x0, 3 * (window.devicePixelRatio || 1));
                }
                g.restore();
            },
        },
    });

    const decades = (u, splits) => splits.map((v) => (v > 0 && Math.abs(Math.log10(v) - Math.round(Math.log10(v))) < 1e-9 ? v : null));

    // Response times: median, 95th and 99th percentile and what the gateway adds, on a logarithmic scale.
    const drawLatency = () => {
        const element = document.getElementById('perf-latency');
        if (latencyChart) {
            latencyChart.destroy();
            latencyChart = null;
        }
        if (!element || !window.uPlot) {
            return;
        }
        let data;
        try {
            data = JSON.parse(element.dataset.chart || '{}');
        } catch {
            return;
        }
        const points = data.points || [];
        const label = (name) => element.dataset['text' + name] || name;
        const ms = (u, v) => (v === null || v === undefined ? '–' : `${number(v, v < 10 ? 1 : 0)} ms`);
        const textColor = css('--text', '#1d2430');
        const border = css('--border', '#d9dee5');
        const axis = { stroke: textColor, grid: { stroke: border, width: 1 }, ticks: { stroke: border, width: 1 } };
        const width = Math.max(280, element.clientWidth);
        latencyChart = new uPlot({
            width,
            height: width < 600 ? 200 : 260,
            series: [
                { value: (u, v) => (v === null ? '–' : new Date(v * 1000).toLocaleString(lang())) },
                { label: label('P50'), stroke: css('--ok', '#1d7a46'), width: 2, value: ms, spanGaps: false },
                { label: label('P95'), stroke: css('--warn', '#8a5a00'), width: 1.5, value: ms },
                { label: label('P99'), stroke: css('--danger', '#b3261e'), width: 1.5, dash: [4, 3], value: ms },
                { label: label('Gateway'), stroke: css('--accent', '#1f5fbf'), width: 1.5, dash: [2, 3], value: ms },
            ],
            axes: [
                { ...axis, values: timeLabels },
                {
                    ...axis,
                    // Only the powers of ten (0.1, 1, 10, 100 ms …): a line at every 2, 3 … 9 is too busy.
                    filter: decades,
                    grid: { ...axis.grid, filter: decades },
                    ticks: { ...axis.ticks, filter: decades },
                    values: (u, ticks) => ticks.map((t) => (t === null ? '' : `${number(t, t < 1 ? 1 : 0)}`)),
                },
            ],
            scales: { x: { time: true }, y: { distr: 3, log: 10 } },
            cursor: { drag: { x: false, y: false } },
            plugins: [background(), failoverBands(data.failovers)],
        }, [
            points.map((p) => p[0]),
            points.map((p) => p[1]),
            points.map((p) => p[2]),
            points.map((p) => p[3]),
            points.map((p) => p[4]),
        ], element);
    };

    const draw = () => {
        if (!root || !window.uPlot) {
            return;
        }
        if (chart) {
            chart.destroy();
            chart = null;
        }
        const values = series();
        chart = new uPlot(options(Math.max(280, root.clientWidth), values), values.data, root);
    };

    const update = () => {
        if (!chart) {
            draw();
            return;
        }
        const values = series();
        chart.setData(values.data);
        // The legend reads the component values through closures over the old arrays: rebuild them cheaply.
        chart.series[1].value = (u, v, si, i) => (i == null ? '–' : number(values.good[i]));
        chart.series[2].value = (u, v, si, i) => (i == null ? '–' : number(values.bad[i]));
        chart.series[3].value = (u, v, si, i) => (i == null ? '–' : number(values.failed[i]));
    };

    // Live: one snapshot a second from the hub; the chart keeps the last five minutes.
    const showSnapshot = (snapshot) => {
        const row = [snapshot.second, 1, snapshot.good, snapshot.bad, snapshot.failed, snapshot.total];
        const buckets = state.buckets;
        const at = buckets.findIndex((b) => b[0] === snapshot.second);
        if (at >= 0) {
            buckets[at] = row;
        } else {
            buckets.push(row);
            buckets.sort((a, b) => a[0] - b[0]);
        }
        while (buckets.length > liveSeconds) {
            buckets.shift();
        }

        let good = 0;
        let bad = 0;
        let failed = 0;
        for (const b of buckets) {
            good += b[2];
            bad += b[3];
            failed += b[4];
        }
        setFigure('total', number(snapshot.total, 0));
        setFigure('peak', number(Math.max(0, ...buckets.map((b) => b[2] + b[3] + b[4])), 0));
        setFigure('bad-share', percent(bad, good + bad + failed));
        setFigure('failed-share', percent(failed, good + bad + failed));
        setStatus('Live', 'live');
        update();
    };

    const retry = {
        nextRetryDelayInMilliseconds: (context) => Math.min(30000, 1000 * 2 ** Math.min(context.previousRetryCount, 5)),
    };

    const connect = async () => {
        if (!window.signalR) {
            return;
        }
        const current = new signalR.HubConnectionBuilder()
            .withUrl(root.dataset.hub)
            .withAutomaticReconnect(retry)
            .configureLogging(signalR.LogLevel.None)
            .build();
        connection = current;
        const watch = () => current.invoke('Watch', state.route || null);
        current.on('snapshot', showSnapshot);
        current.on('sessionEnded', () => {
            setStatus('Ended', 'ended');
            stopLive();
        });
        current.onreconnecting(() => setStatus('Reconnecting', 'reconnecting'));
        current.onreconnected(() => watch().catch(() => {}));
        setStatus('Connecting', 'connecting');
        try {
            await current.start();
            await watch();
        } catch {
            if (connection === current) {
                setStatus('Reconnecting', 'reconnecting');
                connection = null;
                setTimeout(() => { if (root && !connection && state && state.live) { connect(); } }, 5000);
            }
        }
    };

    const stopLive = () => {
        if (connection) {
            const old = connection;
            connection = null;
            old.stop();
        }
    };

    // Times in the admin's own time zone, with the zone named.
    const localTimes = () => {
        document.querySelectorAll('time[data-local]').forEach((element) => {
            const moment = new Date(element.getAttribute('datetime'));
            if (!Number.isNaN(moment.getTime())) {
                element.textContent = moment.toLocaleString(lang());
            }
        });
        document.querySelectorAll('[data-tz]').forEach((element) => {
            element.textContent = (text('Zone') || 'times in {0}').replace('{0}', zone);
        });
    };

    // The custom period form: its fields are local times; send them as Unix seconds.
    const customForm = () => {
        const form = document.querySelector('form[data-local-range]');
        if (!form || form.dataset.ready) {
            return;
        }
        form.dataset.ready = '1';
        const toLocalInput = (input) => {
            const utc = new Date(input.value + ':00Z');
            if (!Number.isNaN(utc.getTime())) {
                const local = new Date(utc.getTime() - utc.getTimezoneOffset() * 60000);
                input.value = local.toISOString().slice(0, 16);
            }
        };
        form.querySelectorAll('input[type="datetime-local"]').forEach(toLocalInput);
        const note = form.querySelector('[data-tz-note]');
        if (note) {
            note.textContent = (text('Zone') || 'times in {0}').replace('{0}', zone);
        }
        form.addEventListener('submit', (event) => {
            event.preventDefault();
            const url = new URL(form.getAttribute('action'), document.baseURI);
            new FormData(form).forEach((value, name) => {
                if (name === 'from' || name === 'to') {
                    const moment = new Date(String(value));
                    url.searchParams.append(name, String(Math.floor(moment.getTime() / 1000)));
                } else {
                    url.searchParams.append(name, String(value));
                }
            });
            window.location.assign(url.toString());
        });
    };

    // Pie charts of the breakdown tables (kinds, sources, destinations), with a switch back to the table. The tables
    // stay the source of the numbers: each row has data-count, each table data-total (all bad requests).
    const pieSlices = 7;
    const viewKey = 'waf-performance-breakdown';
    const savedView = () => {
        try {
            return window.localStorage.getItem(viewKey) === 'table' ? 'table' : 'pie';
        } catch {
            return 'pie';
        }
    };
    const saveView = (view) => {
        try {
            window.localStorage.setItem(viewKey, view);
        } catch {
            // Private window or blocked storage: the choice lasts for this page only.
        }
    };

    const palette = () => [1, 2, 3, 4, 5, 6, 7, 8].map((i) => css(`--pie-${i}`, '#888888'));

    const slicesOf = (table) => {
        const rows = [...table.querySelectorAll('tbody tr[data-count]')].map((row) => ({
            label: row.querySelector('th').textContent.trim(),
            count: Number(row.dataset.count) || 0,
            link: row.querySelector('td a[href]:not([title])') || null,
        }));
        const listed = rows.reduce((sum, row) => sum + row.count, 0);
        const total = Math.max(Number(table.dataset.total) || 0, listed);
        const top = rows.slice(0, pieSlices);
        const rest = total - top.reduce((sum, row) => sum + row.count, 0);
        if (rest > 0) {
            top.push({ label: text('Other'), count: rest, link: null, other: true });
        }
        return { slices: top.filter((s) => s.count > 0), total };
    };

    const drawPie = (canvas, slices, total) => {
        const size = 200;
        const ratio = window.devicePixelRatio || 1;
        canvas.width = size * ratio;
        canvas.height = size * ratio;
        canvas.style.width = `${size}px`;
        canvas.style.height = `${size}px`;
        const g = canvas.getContext('2d');
        g.scale(ratio, ratio);
        const colors = palette();
        const surface = css('--surface', '#ffffff');
        let angle = -Math.PI / 2;
        slices.forEach((slice, i) => {
            const sweep = total > 0 ? (slice.count / total) * Math.PI * 2 : 0;
            g.beginPath();
            g.moveTo(size / 2, size / 2);
            g.arc(size / 2, size / 2, size / 2 - 2, angle, angle + sweep);
            g.closePath();
            g.fillStyle = slice.other ? css('--border', '#d9dee5') : colors[i % colors.length];
            g.fill();
            g.strokeStyle = surface; // a gap between the slices
            g.lineWidth = 2;
            g.stroke();
            // The share on the slice when it is large enough to hold it.
            if (sweep > 0.45) {
                const middle = angle + sweep / 2;
                g.fillStyle = slice.other ? css('--text', '#1d2430') : '#ffffff';
                g.font = '600 12px system-ui, sans-serif';
                g.textAlign = 'center';
                g.textBaseline = 'middle';
                g.fillText(percent(slice.count, total), size / 2 + Math.cos(middle) * size * 0.3, size / 2 + Math.sin(middle) * size * 0.3);
            }
            angle += sweep;
        });
        // A ring, so it reads as a whole even when one slice is tiny.
        g.beginPath();
        g.arc(size / 2, size / 2, size * 0.17, 0, Math.PI * 2);
        g.fillStyle = surface;
        g.fill();
    };

    const legendOf = (slices, total) => {
        const colors = palette();
        const list = document.createElement('ul');
        list.className = 'pie-legend';
        slices.forEach((slice, i) => {
            const item = document.createElement('li');
            const swatch = document.createElement('span');
            swatch.className = 'pie-swatch';
            swatch.style.background = slice.other ? css('--border', '#d9dee5') : colors[i % colors.length];
            const label = document.createElement(slice.link ? 'a' : 'span');
            if (slice.link) {
                label.href = slice.link.getAttribute('href'); // "only this"
            }
            label.textContent = slice.label;
            const figures = document.createElement('span');
            figures.className = 'pie-figures';
            figures.textContent = `${number(slice.count, 0)} · ${percent(slice.count, total)}`;
            item.append(swatch, label, figures);
            list.append(item);
        });
        return list;
    };

    let pieViews = [];

    const setupPies = () => {
        pieViews = [];
        document.querySelectorAll('table[data-pie]').forEach((table) => {
            const scroll = table.closest('.table-scroll') || table;
            const section = scroll.parentElement;
            section.querySelectorAll(':scope > .view-switch, :scope > .pie-block').forEach((old) => old.remove());

            const { slices, total } = slicesOf(table);
            if (slices.length === 0) {
                return;
            }

            const heading = section.querySelector('h2');
            const block = document.createElement('div');
            block.className = 'pie-block';
            const canvas = document.createElement('canvas');
            canvas.setAttribute('role', 'img');
            canvas.setAttribute('aria-label', `${heading ? heading.textContent.trim() : ''}: ${slices.map((s) => `${s.label} ${percent(s.count, total)}`).join(', ')}`);
            block.append(canvas, legendOf(slices, total));
            drawPie(canvas, slices, total);

            const switcher = document.createElement('div');
            switcher.className = 'view-switch';
            switcher.setAttribute('role', 'group');
            switcher.setAttribute('aria-label', text('ShowAs'));
            const buttons = ['pie', 'table'].map((view) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'button button-secondary';
                button.dataset.view = view;
                button.textContent = text(view === 'pie' ? 'Pie' : 'Table');
                return button;
            });
            switcher.append(...buttons);

            const show = (view) => {
                block.hidden = view !== 'pie';
                scroll.hidden = view === 'pie';
                buttons.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === view)));
            };
            buttons.forEach((button) => button.addEventListener('click', () => {
                saveView(button.dataset.view);
                pieViews.forEach((apply) => apply(button.dataset.view)); // every breakdown follows the same choice
            }));
            pieViews.push(show);

            scroll.before(switcher, block);
            show(savedView());
        });
    };

    const teardown = () => {
        stopLive();
        if (resizeObserver) {
            resizeObserver.disconnect();
            resizeObserver = null;
        }
        if (latencyChart) {
            latencyChart.destroy();
            latencyChart = null;
        }
        if (chart) {
            chart.destroy();
            chart = null;
        }
        root = null;
        state = null;
    };

    const init = () => {
        const found = document.getElementById('perf-chart');
        if (found === root && root) {
            return;
        }
        teardown();
        if (!found) {
            return;
        }

        root = found;
        let data;
        try {
            data = JSON.parse(root.dataset.chart || '{}');
        } catch {
            return;
        }
        state = {
            live: !!data.live,
            route: data.route,
            buckets: data.buckets || [],
            previous: data.previous || null,
            hasPeaks: (data.buckets || []).some((b) => b[5] !== null),
            failovers: data.failovers || [],
        };
        if (state.live) {
            state.hasPeaks = false;
        }

        localTimes();
        customForm();
        if (!state.live) {
            setStatus('', 'off');
            const status = document.querySelector('#perf-chart ~ [data-live="status"]');
            if (status) {
                status.hidden = true;
            }
        }
        draw();
        drawLatency();
        setupPies();
        resizeObserver = new ResizeObserver(() => {
            if (chart && root) {
                const width = Math.max(280, root.clientWidth);
                chart.setSize({ width, height: width < 600 ? 220 : 300 });
            }
            const latency = document.getElementById('perf-latency');
            if (latencyChart && latency) {
                const width = Math.max(280, latency.clientWidth);
                latencyChart.setSize({ width, height: width < 600 ? 200 : 260 });
            }
        });
        resizeObserver.observe(root);
        if (state.live) {
            connect();
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    if (window.Blazor && typeof window.Blazor.addEventListener === 'function') {
        window.Blazor.addEventListener('enhancedload', init);
    }

    // A theme change (system setting) redraws with the new colours.
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (state) { draw(); drawLatency(); setupPies(); } });
    }
})();
