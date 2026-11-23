# Admin UI screenshots

Screenshots of every page of the WAF Gateway admin UI at 1280×720. They use the example configuration (`schemas/gateway-config.example.json`) plus a few changes made through the UI, so the history has several versions.

- [Signing in](#signing-in)
- [Dashboard](#dashboard)
- [Request log](#request-log)
- [Routes](#routes)
- [Rules](#rules)
- [Rate limits](#rate-limits)
- [Templates and presets](#templates-and-presets)
- [Test a request](#test-a-request)
- [Configuration history](#configuration-history)
- [Backup and import](#backup-and-import)
- [Your account](#your-account)

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

The list of routes: which requests go to which backends.

![Routes list](images/admin-routes.png)

Editing a route: host names, path prefix, methods, backends and health check.

![Editing a route](images/admin-route-edit.png)

Deleting a route is refused while rules or rate limits still refer to it.

![Deleting a route that is still in use](images/admin-route-delete.png)

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

Every configuration version, with the active one marked.

![Configuration history](images/admin-history.png)

A version's details: what restoring it would change compared with the running configuration.

![Version details and restore](images/admin-history-version.png)

## Backup and import

Export the configuration, import a file, download a full backup or restore one.

![Backup and import](images/admin-backup.png)

The preview of an import: the file was exported without secrets, so the running values are kept.

![Import preview](images/admin-import-preview.png)

## Your account

Two-factor sign-in, the previous sign-in with the failed attempts since, sessions, and changing the password.

![Your account](images/admin-account.png)

Turning on two-factor sign-in: scan the QR code, or type the key, and enter the first code.

![Two-factor setup](images/admin-two-factor-setup.png)

The login history: sign-ins, failed attempts (highlighted), lockouts and sign-outs.

![Login history](images/admin-login-history.png)
