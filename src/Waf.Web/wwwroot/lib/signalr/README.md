# SignalR JavaScript client

`signalr.min.js` is `dist/browser/signalr.min.js` from the npm package
[@microsoft/signalr 11.0.0](https://www.npmjs.com/package/@microsoft/signalr/v/11.0.0), unchanged. It is served by the
gateway itself (no CDN), so the admin UI's Content-Security-Policy stays `script-src 'self'`. License: MIT
(`LICENSE.txt`, .NET Foundation and Contributors); listed in THIRD-PARTY-NOTICES.md.

- Package tarball: `https://registry.npmjs.org/@microsoft/signalr/-/signalr-11.0.0.tgz`,
  integrity `sha512-NNYwAOYFaVH8HRt3YWUFJYETZ66G8P3K/g3Ch/6Od+Rrdpe/Uafe8iZp81UI7TIM7qRzjDe5DKUAuwsnt391zg==`
- `signalr.min.js` SHA-256: `830ef76ca570fbc1a5716ff0ae812155b2e09abc393f7d9d4457d404ad05a53e` (checked by `LiveTrafficTests`)

To update: download the package's tarball, check its integrity against the registry, copy
`package/dist/browser/signalr.min.js` and `package/LICENSE.txt` here, and update the version and hashes above and in
the test. Keep the client's major version equal to the server's (.NET).
