# Admin UI screenshots

Screenshots of every page of the WAF Gateway admin UI at 1280×720. They use the example configuration (`schemas/gateway-config.example.json`) plus a few changes made through the UI, so the history has several versions.

- [Dashboard](#dashboard)
- [Request log](#request-log)
- [Routes](#routes)
- [Rules](#rules)
- [Rate limits](#rate-limits)
- [Templates and presets](#templates-and-presets)
- [Test a request](#test-a-request)
- [Configuration history](#configuration-history)
- [Backup and import](#backup-and-import)

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
