# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-18

Authorization: static route checks and opt-in probes that confirm them.

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
- `routes` module, for controllers in `app/` (closures and Livewire pages are
  left out): `routes.missing-authentication` for writes to a bound model
  without login, `routes.missing-authorization` for logged-in routes that load
  a model and never authorize it, `routes.unscoped-nested-binding` for nested
  models that belong to their parent but are not scoped, all reported as
  suspected; `routes.csrf-excluded` for URIs excluded from CSRF that match
  logged-in session routes while `session.same_site` is `none` or `null`.
- `probes` module, an opt-in DAST engine that confirms suspicions on a test
  database: it runs in a child process, refuses in production and on the
  application database, and reports what it could not check as "Probe coverage".
  The probes are `probes.idor` (a user reaching another owner's record),
  `probes.csrf-unprotected` (a write without a CSRF token),
  `probes.missing-rate-limit` (unlimited login attempts) and
  `probes.mass-assignment` (setting a privileged or tenant column that the
  validation rules do not mention; a confirmed mass-assignment keeps the
  `models.guarded-empty` / `models.unguarded` rule it proved).
- Request bodies for write probes are generated from the action's
  `FormRequest::rules()`, so probes send requests the application would accept;
  `probes.payloads.fields`, `probes.payloads.ignore` and
  `probes.payloads.attack_fields` tune this.
- Findings have an optional `reproduction` (probe, data source, actors and
  steps) in the JSON report and a "Reproduce" block in the console, showing how
  a probe confirmed the finding.
- The JSON report has a top-level `coverage` list and the console a "Probe
  coverage" section: what each probe checked, confirmed and skipped, with hints.
- The JSON report has a top-level `notices` list, shown under "Notices" in the
  console, for information that is neither a finding nor a skipped check; it is
  never counted by `--fail-on`.

### Changed

- The console report shows findings of the same rule with the same fix, such
  as every advisory of one package, as one block: the highest severity, a list
  of titles with their CVEs, one fix and the references. The JSON report still
  has one finding per advisory.
- A finding confirmed by a probe replaces the static finding of the same rule
  and location, so one issue is reported once.

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

[Unreleased]: https://github.com/jklejczyk/security-toolkit-for-laravel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jklejczyk/security-toolkit-for-laravel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jklejczyk/security-toolkit-for-laravel/releases/tag/v0.1.0
