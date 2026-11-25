# uPlot

`uPlot.iife.min.js` and `uPlot.min.css` are `dist/uPlot.iife.min.js` and `dist/uPlot.min.css` from the npm package
[uplot 1.6.32](https://www.npmjs.com/package/uplot/v/1.6.32), unchanged. uPlot draws the charts of the Performance page.
It is served by the gateway itself (no CDN) and sets styles only through the DOM (no inline style attributes, no
`eval`), so the admin UI's Content-Security-Policy stays `script-src 'self'; style-src 'self'`. License: MIT
(`LICENSE`, Leon Sorokin); listed in THIRD-PARTY-NOTICES.md.

- Package tarball: `https://registry.npmjs.org/uplot/-/uplot-1.6.32.tgz`,
  integrity `sha512-KIMVnG68zvu5XXUbC4LQEPnhwOxBuLyW1AHtpm6IKTXImkbLgkMy+jabjLgSLMasNuGGzQm/ep3tOkyTxpiQIw==`
- `uPlot.iife.min.js` SHA-256: `19c8d4c6ad88929a79f4ae49d6f7161566dfd0ba3d15cc495e974f787eb78f1f`
- `uPlot.min.css` SHA-256: `df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04`

Both hashes are checked by `LicenseTests`. To update: download the tarball, check its integrity against the registry,
copy the two files and `LICENSE` here, and update the version and hashes above and in the test.
