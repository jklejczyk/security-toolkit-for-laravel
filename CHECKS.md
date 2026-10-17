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
| `config.dashboard-open` | production | Telescope, Horizon, Pulse or Log Viewer gate lets every logged-in user in, or guests too (a nullable user parameter); Log Viewer without a gate when `require_auth_in_production` is `false` | High (Pulse: Medium) | 862 | 4.3–8.6 |
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

## `models`

| Rule | Runs in | Detects | Severity | CWE | CVSS |
| --- | --- | --- | --- | --- | --- |
| `models.unguarded` | everywhere | `Model::unguard()` is on for every model after the application boots | Medium | 915 | — |
| `models.guarded-empty` | everywhere | A model in `app/` has an empty `$guarded` (or `#[Unguarded]`) | Medium | 915 | — |

`models.guarded-empty` reports only with evidence that the whole request is
mass assigned somewhere in `app/`, such as `Post::create($request->all())` or
`$model->fill(request()->input())`: with `$request->validated()` an empty
`$guarded` is safe. Pivot models, which are unguarded by default, are not
reported. When every model is unguarded, only `models.unguarded` is reported.

## `routes`

| Rule | Runs in | Detects | Severity | CWE | CVSS |
| --- | --- | --- | --- | --- | --- |
| `routes.missing-authentication` | everywhere | `POST`, `PUT`, `PATCH` or `DELETE` route with a model parameter and no `auth`, `auth.basic`, `signed` or `can:` middleware (suspected) | High | 306 | — |
| `routes.missing-authorization` | everywhere | Logged-in route with a model parameter that never authorizes it (suspected) | Medium | 639 | — |
| `routes.unscoped-nested-binding` | everywhere | Nested model parameters where the child belongs to the parent, without scoped bindings (suspected) | Medium | 639 | — |
| `routes.csrf-excluded` | everywhere | URI excluded from CSRF that matches a logged-in session route, with `session.same_site` `none` or `null` | Medium | 352 | 6.5 |

The rules look only at routes whose controller is in `app/`; closures and
Livewire pages (`Route::livewire()`) are left out. Authorization counts when
the route has a `can:` middleware, the action calls `authorize()`, `Gate::`,
`->can()`, `->cannot()`, `abort_if()`, `abort_unless()` or `abort(403)`, the
controller constructor calls `authorizeResource()`, or a form request of the
action has an `authorize()` that does more than `return true`. In doubt the
rule stays silent; authorization in a service or a global scope is not seen,
which is why these findings are suspected.

`routes.unscoped-nested-binding` treats a custom key on the child
(`{invoice:number}`) as scoped, because Laravel scopes it by itself, and skips
actions that compare the foreign key themselves.

`routes.csrf-excluded` reads `validateCsrfTokens(except: [...])` and the
`$except` of an application CSRF middleware. Webhooks without a session are
not reported, and with `same_site` `lax` or `strict` the browser does not send
the session cookie cross-site. Outside production, when `same_site` comes from
`env()`, the rule is skipped with a reason, but only if a matching exclusion
exists.

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
