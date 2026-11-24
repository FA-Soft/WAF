# Admin UI screenshots

Screenshots of every page of the WAF Gateway admin UI at 1280×720. They use the example configuration (`schemas/gateway-config.example.json`) plus a few changes made through the UI, so the history has several versions.

- [Signing in](#signing-in)
- [Dashboard](#dashboard)
- [Request log](#request-log)
- [Routes](#routes)
- [Targets](#targets)
- [Rules](#rules)
- [Rate limits](#rate-limits)
- [Certificates](#certificates)
- [Templates and presets](#templates-and-presets)
- [Test a request](#test-a-request)
- [Configuration history](#configuration-history)
- [Audit log](#audit-log)
- [Backup and import](#backup-and-import)
- [Remote access](#remote-access)
- [Your account](#your-account)
- [Light and dark theme](#light-and-dark-theme)
- [Language](#language)
- [When no backend answers](#when-no-backend-answers)

## Signing in

First run: creating the admin account. On the gateway's own machine no setup token is needed.

![Create the admin account](images/admin-setup.png)

The sign-in page. Every other page needs a signed-in admin.

![Sign in](images/admin-login.png)

With two-factor sign-in on, the code from the authenticator app comes after the password.

![Two-factor sign-in](images/admin-two-factor-login.png)

## Dashboard

The firewall state, the active configuration version, and the routes, rules, rate limits and attack detection in plain language.

![Dashboard](images/admin-dashboard.png)

## Request log

Every public request, newest first, with filters, free-text search and a live view.

![Request log](images/admin-logs.png)

Only the blocked requests, with the rule that blocked each one.

![Blocked requests](images/admin-logs-blocked.png)

One entry in detail: an SQL injection blocked by attack detection.

![Log entry](images/admin-log-entry.png)

Log retention: size, entries, the last cleanup and the age and size limits.

![Log retention](images/admin-log-retention.png)

"Allow this (false positive)" from that entry: the exclusion form, pre-filled with the path, route and the check that fired.

![Exclusion pre-filled from a log entry](images/admin-exclusion-from-log.png)

## Routes

The list of routes: which requests go to which backends. Route "api" runs on its failover backend because its primaries do not answer.

![Routes list](images/admin-routes.png)

Editing a route: host names, path prefix, methods, backends and health check.

![Editing a route](images/admin-route-edit.png)

The HTTPS options of a route: redirect http:// to https://, and HSTS.

![HTTPS options of a route](images/admin-route-https.png)

The failover backends of a route, one per line in the order they take over; "Add as failover" adds a target there.

![Failover backends of a route](images/admin-route-failover.png)

Deleting a route is refused while rules or rate limits still refer to it.

![Deleting a route that is still in use](images/admin-route-delete.png)

## Targets

Named machines with labelled ports, and the routes that use them.

![Targets list](images/admin-targets.png)

Editing a target: name, address and its ports.

![Editing a target](images/admin-target-edit.png)

A device with an address from DHCP: its MAC address, filled in with "Look up MAC address", and how often it is looked up.

![A target with a MAC address](images/admin-target-mac.png)

In the route editor, a target is picked under "Add a target" or written as `nas/web` in the backends.

![A route forwarding to a target](images/admin-route-target.png)

## Rules

The rules in priority order, with the global detection-only switch.

![Rules list](images/admin-rules.png)

Editing a rule: action, priority, detection-only, route scope and conditions.

![Editing a rule](images/admin-rule-edit.png)

An IP block list: paste addresses and CIDR ranges, one per line.

![IP block list](images/admin-ip-block-list.png)

## Rate limits

The rate limits and what each one counts.

![Rate limits list](images/admin-rate-limits.png)

Editing a rate limit: limit, window, what is counted, routes and conditions.

![Editing a rate limit](images/admin-rate-limit-edit.png)

## Certificates

The host names with their certificate, how long it is valid and its status, and the uploaded certificates.

![Certificates](images/admin-certificates.png)

Uploading a certificate: a PFX file with its password, or PEM certificate and key files.

![Upload a certificate](images/admin-certificate-upload.png)

After uploading: choose the host names that use the certificate.

![Choose host names for a certificate](images/admin-certificate-hosts.png)

Let's Encrypt: the account settings, the staging switch, and choosing Let's Encrypt for a host name.

![Let's Encrypt](images/admin-letsencrypt.png)

HSTS: how long browsers use HTTPS only, for the routes that send the header.

![HSTS settings](images/admin-hsts.png)

## Templates and presets

The library of one-click presets and templates for routes, rules and rate limits.

![Templates and presets](images/admin-library.png)

The preview of the "Block common attacks" preset: nothing changes until you apply it.

![Preset preview](images/admin-preset-preview.png)

The "Lock a path to your IP addresses" preset, with its settings and the preview of the rule it adds.

![Lock a path preset](images/admin-preset-lock-path.png)

## Test a request

Describe a request to see whether the firewall would allow or block it, without sending anything.

![Test a request](images/admin-test-request.png)

The result: a blocked SQL injection, with the reason.

![Test result](images/admin-test-request-result.png)

## Configuration history

Every configuration version, with the active one marked, who stored it and a link to its audit entry.

![Configuration history](images/admin-history.png)

A version's details: what restoring it would change compared with the running configuration.

![Version details and restore](images/admin-history-version.png)

## Audit log

Who changed what, and when: configuration changes (with what each version changed), sign-ins and sign-outs, security settings, downloads and backups. Filter by kind, user or configuration version.

![Audit log](images/admin-audit.png)

## Backup and import

Export the configuration, import a file, download a full backup or restore one.

![Backup and import](images/admin-backup.png)

The preview of an import: the file was exported without secrets, so the running values are kept.

![Import preview](images/admin-import-preview.png)

## Remote access

Remote access: off by default; the requirements, the admin address and the optional allowlist.

![Remote access](images/admin-remote-access.png)

## AI assistant

The AI assistant: describe a change in a sentence; the list of proposals with their status.

![AI assistant](images/admin-ai.png)

Reviewing a proposal: the model's summary, the differences in plain language, and Apply or Discard.

![AI proposal](images/admin-ai-proposal.png)

The AI assistant settings: off until an Anthropic API key is saved; the key's last four characters, and the summary of the configuration that would be sent.

![AI assistant settings](images/admin-ai-settings.png)

## Your account

Two-factor sign-in, the previous sign-in with the failed attempts since, sessions, and changing the password.

![Your account](images/admin-account.png)

Turning on two-factor sign-in: scan the QR code, or type the key, and enter the first code.

![Two-factor setup](images/admin-two-factor-setup.png)

The login history: sign-ins, failed attempts (highlighted), lockouts and sign-outs.

![Login history](images/admin-login-history.png)

## Light and dark theme

The switch at the top right: **System** (the default) follows the device's setting; **Light** or **Dark** is stored with the account, so it applies at the next sign-in on any device. The dashboard and the request log with **Dark** chosen:

![Dashboard in the dark theme](images/admin-dashboard-dark.png)

![Request log in the dark theme](images/admin-logs-dark.png)

## Language

The language menu at the top right: **Browser** (the default) follows the browser's language; English, Nederlands, Français or Deutsch is stored with the account, like the theme.

![Language menu](images/admin-language.png)

## When no backend answers

Not part of the admin UI: what a visitor's browser shows when no backend of a route answers (here a 502). Programs get the same error as JSON, XML or a SOAP Fault. The page follows the visitor's light or dark setting:

![Error page](images/error-page.png)

![Error page in the dark theme](images/error-page-dark.png)
