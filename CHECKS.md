# Checks

Every rule the toolkit reports, with its severity, CWE and CVSS 3.1 score.
The rule ID appears in every finding and in the `--format=json` output;
`--only` selects whole modules, e.g. `--only=config,auth`.

**Runs in** tells where a rule is checked. Rules that read a value Laravel takes
from `.env` (`APP_DEBUG`, `SESSION_SECURE_COOKIE` and the like) run only for a
production configuration, because locally that value differs on purpose; in
other environments they are listed as skipped. Rules that read code or
committed config files run everywhere, including CI.

## `config`

| Rule | Runs in | Detects | Severity | CWE | CVSS |
| --- | --- | --- | --- | --- | --- |
| `config.app-key-known` | production | `APP_KEY` is a publicly known key (default keys of open source projects and published examples) | Critical | 321 | 9.1 |
| `config.debug-enabled` | production | `APP_DEBUG` is on | High | 209 | 7.5 |
| `config.dashboard-open` | production | Telescope, Horizon, Pulse or Log Viewer gate lets every logged-in user in | High (Pulse: Medium) | 862 | 4.3–7.6 |
| `config.app-key-missing` | production | `APP_KEY` is empty, so signed URLs can be forged | Medium | 1391 | 5.3 |

## `files`

| Rule | Runs in | Detects | Severity | CWE | CVSS |
| --- | --- | --- | --- | --- | --- |
| `files.private-storage-linked` | everywhere | A link in `public/` exposes a private disk or `storage/` (High when it includes logs) | High / Medium | 552 | 5.9–7.5 |
| `files.default-disk-public` | production | The default filesystem disk is served publicly | Low | 552 | 3.7 |

## `auth`

| Rule | Runs in | Detects | Severity | CWE | CVSS |
| --- | --- | --- | --- | --- | --- |
| `auth.session-cookie-insecure` | production | Session cookie without the `Secure` flag | Medium | 614 | 6.4 |
| `auth.session-cookie-script-accessible` | production | Session cookie without `HttpOnly` | Medium | 1004 | — |
| `auth.password-too-short` | everywhere | `Password::defaults()` allows fewer than 8 characters | Medium | 521 | — |
| `auth.password-not-checked-for-leaks` | everywhere | `Password::defaults()` without `uncompromised()` | Medium | 521 | — |
| `auth.sanctum-tokens-never-expire` | everywhere | Sanctum API tokens never expire | Medium | 613 | — |

The password and Sanctum rules report only with evidence that the feature is
used, for example `Password::defaults()` in validation or `createToken()` in
`app/`.

Outside production the password rules are evaluated as production would see
them: a `Password::defaults()` callback that checks `app()->isProduction()`,
`app()->environment()` or `config('app.debug')` takes its production branch.
This works only when there is one unconditional `Password::defaults()` call
that decides inside its callback. Anything decided while the application boots
keeps its local value, so the rules are skipped with a reason when the rule is
registered in more than one place or only in some environments, when a rule
object is chosen by an environment check, when the callback captures variables
or reads `env()` directly, or when it is not a closure. Other inputs to the
callback, such as your own config keys read from `.env`, keep their local
values too. A Sanctum `expiration` read from `env()` is skipped outside
production as well.

## `dependencies`

| Rule | Runs in | Detects | Severity | CWE |
| --- | --- | --- | --- | --- |
| `dependencies.vulnerable-package` | everywhere | An installed package has a published security advisory (`composer audit`), with its CVE | From the advisory | 1395 |
| `dependencies.abandoned-package` | everywhere | An installed package is abandoned | Info | 1104 |

## How severity is decided

A finding that an attacker can exploit on its own has a CVSS 3.1 base vector,
written for a typical internet-facing application, and its severity is the
CVSS band of that score (9.0+ Critical, 7.0+ High, 4.0+ Medium, below Low).
A missing safeguard that only makes another attack worse, such as a cookie
without `HttpOnly` that matters only once there is an XSS, has no vector and
is never rated above Medium. Advisories keep the severity their source
published.
