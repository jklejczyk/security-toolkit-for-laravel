# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `config.dashboard-open` reports a dashboard whose gate lets guests in (a
  nullable user parameter, as in the Horizon stub) as open to everyone, rated
  without required privileges.
- `config.dashboard-open` reports Log Viewer without a `viewLogViewer` gate or
  `LogViewer::auth()` callback as open to everyone when
  `log-viewer.require_auth_in_production` is `false`.
- `models` module: `models.unguarded` for a global `Model::unguard()` left on
  after boot, and `models.guarded-empty` for models with an empty `$guarded`
  (including `#[Unguarded]` on Laravel 13), reported only when code in `app/`
  passes the whole request to `create()`, `fill()`, `update()` or a similar
  method.
- Every finding has a confidence: `certain` (read directly from the
  configuration or the booted application), `suspected` (inferred from code)
  or `confirmed` (reproduced by a probe). The JSON report has a `confidence`
  field and the console labels suspected and confirmed findings.

### Changed

- The console report shows findings of the same rule with the same fix, such
  as every advisory of one package, as one block: the highest severity, a list
  of titles with their CVEs, one fix and the references. The JSON report still
  has one finding per advisory.

## [0.1.0] - 2026-10-16

First public release.

### Added

- `php artisan security:scan` with `--only`, `--list`, `--format=console|json`,
  `--min-severity` and `--fail-on`; rules that read `.env` values run only for a
  production configuration and are skipped, with a reason, elsewhere; rules
  that read code run everywhere, including CI.
- `config` module: publicly known and missing `APP_KEY`, debug mode, Telescope,
  Horizon, Pulse and Log Viewer dashboards open to every logged-in user.
- `files` module: private storage linked into `public/`, public default disk.
- `auth` module: session cookie `Secure` and `HttpOnly` flags, weak
  `Password::defaults()`, Sanctum tokens that never expire.
- `dependencies` module: vulnerable and abandoned packages from `composer audit`.
- Every finding has a CWE; exploitable findings have a CVSS 3.1 vector that
  sets their severity; advisories carry their CVE.
- `unknown` severity for advisories published without one; it always meets the
  `--fail-on` threshold.

[Unreleased]: https://github.com/jklejczyk/security-toolkit-for-laravel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jklejczyk/security-toolkit-for-laravel/releases/tag/v0.1.0
