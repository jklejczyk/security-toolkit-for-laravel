# Security Toolkit for Laravel

A security audit for Laravel 12 and 13 applications in one Artisan command.
It reads your application from the inside (configuration, file storage,
authentication, models, routes, dependencies) and reports what is wrong, why it is dangerous
and how to fix it.

```bash
composer require --dev jklejczyk/security-toolkit-for-laravel
php artisan security:scan
```

```
 MEDIUM  Private storage is reachable over HTTP through public/backups  files.private-storage-linked
         config/filesystems.php
         CWE-552 · CVSS 5.9 AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
         The link public/backups points to storage/app, which contains the private
         "local" disk. Anyone who knows or guesses a file path can download it …
         Fix: Link only the public disk directory (storage/app/public by default) …
         → https://laravel.com/docs/filesystem#the-public-disk
```

> **Early release (0.x).** The checks below are tested and stable, but the
> report format and options may still change before 1.0. More modules
> (routes and authorization, dynamic probes, static analysis) are on the way.

## Principles

- **Few, accurate checks instead of many noisy ones.** A false positive is a
  bug. When a check cannot decide reliably, it is skipped with a reason
  instead of guessing.
- **Zero configuration.** Install, run, read the recommendations.
- **A recommendation, not just an alarm.** Every finding explains the risk,
  the fix, and links to the Laravel documentation or OWASP.
- **Justified severity.** Every finding has a CWE. Findings an attacker can
  exploit on their own carry a CVSS 3.1 vector, and their severity follows
  from its score, so you can see exactly why something is rated High.

## Requirements

- PHP 8.3 or newer
- Laravel 12 or 13
- Composer 2.4 or newer on the machine that runs the scan (for the
  `dependencies` module)

## Installation

For scanning on your machine or in CI:

```bash
composer require --dev jklejczyk/security-toolkit-for-laravel
```

To scan on a production server, where dev dependencies are not installed,
require it as a regular dependency instead (`composer require`). The package
only adds the `security:scan` command; it registers no routes, middleware or
listeners.

## Usage

```bash
php artisan security:scan
```

### Where checks run

Rules that read code or committed config files (password rules, storage
links, Sanctum, dependencies) run in every environment, so a plain
`php artisan security:scan` on your machine or in CI already reports them.

Rules that read values Laravel takes from `.env` (debug mode, `APP_KEY`,
cookie flags, dashboards) run only for a production configuration; elsewhere
they are listed as skipped, because those values differ locally on purpose.
To audit them:

- **on the server**, run `php artisan security:scan` there (for example as a
  deploy step), or
- **locally with a real production env file**, run
  `php artisan security:scan --env=production`, which loads
  `.env.production`. Without that file Laravel uses your local `.env`, so the
  result describes your machine, not production.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `--only=config,files` | all | Run only the listed scanners |
| `--list` | | List registered scanners and whether they can run here |
| `--format=json` | `console` | Machine-readable report |
| `--min-severity=medium` | `info` | Hide findings below this severity (they still count in the summary) |
| `--fail-on=critical` | `high` | Exit with code 1 when a finding of this severity or higher exists; `none` never fails |

Severities, from the highest: `critical`, `high`, `medium`, `low`, `info`.
A finding rated `unknown` (an advisory published without a severity) is
always shown and always meets the `--fail-on` threshold, because it could be
critical.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding at or above `--fail-on` |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Invalid option, or a scanner failed (listed under "Errors") |

### In CI

```yaml
- run: php artisan security:scan --fail-on=high
```

This checks code and dependencies on every push. Do not add
`--env=production` here: CI has no production `.env`, so the configuration
rules would judge CI's values and report problems production does not have.

`--format=json` prints the whole report as one JSON document with `findings`
(including `confidence`, `cwe`, `cvss` and `cve`), `skipped`, `unavailable`, `errors` and a
`summary`.

## Checks

The scan is split into modules, each focused on one area of the application:

- **`config`**: the application configuration that controls what an error,
  a key or an admin dashboard exposes.
- **`files`**: how file storage is served, and whether private files can be
  reached over HTTP.
- **`auth`**: session cookies, password rules and API tokens.
- **`models`**: Eloquent mass assignment protection.
- **`routes`**: authentication, authorization, scoped bindings and CSRF exclusions of your routes.
- **`dependencies`**: known vulnerabilities and abandoned packages among the
  installed Composer packages.

[CHECKS.md](CHECKS.md) lists every rule with what it detects, its severity,
CWE and CVSS score, and explains how severity is decided.

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Credits

The list of known application keys is derived from
[laravel-crypto-killer](https://github.com/synacktiv/laravel-crypto-killer)
by Synacktiv, see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing

```bash
composer check     # Pint, PHPStan (max) and Pest, the same as CI
```

## License

MIT, see [LICENSE](LICENSE).
