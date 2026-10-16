# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
