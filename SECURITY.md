# Security Policy

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Use GitHub's private vulnerability reporting instead:
[Report a vulnerability](https://github.com/jklejczyk/security-toolkit-for-laravel/security/advisories/new).

Please include:

- affected version,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept.

You can expect an initial response within 7 days. Once the issue is confirmed,
a fix and a GitHub Security Advisory will be published, crediting the reporter
unless anonymity is requested.

## Supported versions

Until 1.0, only the latest released version receives security fixes.

## Scope

This toolkit runs inside your application with full privileges, and its
dynamic probes send real requests. In scope are, among others: probes that can
modify data outside the test database, ways to bypass the production-environment
guard, and leaks of secrets into reports.
