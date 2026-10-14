# Security Toolkit for Laravel

[![tests](https://github.com/jklejczyk/security-toolkit-for-laravel/actions/workflows/tests.yml/badge.svg)](https://github.com/jklejczyk/security-toolkit-for-laravel/actions/workflows/tests.yml)
[![static analysis](https://github.com/jklejczyk/security-toolkit-for-laravel/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/jklejczyk/security-toolkit-for-laravel/actions/workflows/static-analysis.yml)

> **Work in progress.** Not ready for use yet.

An open source security audit and hardening toolkit for Laravel 12 and 13.
It inspects your application from the inside (configuration, routes and
authorization, file handling, authentication, dependencies) and gives you
concrete recommendations: what is wrong, why it matters and how to fix it.

## Requirements

- PHP 8.3+
- Laravel 12 or 13

## Installation

```bash
composer require --dev jklejczyk/security-toolkit-for-laravel
```

## Development

```bash
composer test      # Pest
composer analyse   # PHPStan (Larastan)
composer format    # Pint
composer check     # all of the above, without fixing
```

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
