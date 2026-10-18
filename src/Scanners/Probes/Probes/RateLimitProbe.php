<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Probes;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelection;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\ProbeData;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Engine\RateLimiterRecorder;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\Features;
use Laravel\Fortify\TwoFactorAuthenticatable;
use Throwable;

/**
 * Confirms an endpoint the application never limits: login, the password reset request and the two
 * factor challenge get a series of attempts from one address, and the probe reports only when
 * there is no trace of a limit anywhere — no 429, no lockout, no call to the rate limiter, no
 * password broker throttle. A limit on the web server or a WAF in front of the application is
 * invisible from inside the application, so the title says "not limited by the application" and
 * the description says that layer still has to be checked.
 */
final class RateLimitProbe implements Probe
{
    private const LOGIN = 'login';

    private const RESET = 'reset';

    private const CHALLENGE = 'two-factor';

    private const NOT_RECOGNIZED = '2FA challenge not recognized';

    /**
     * @var list<string>
     */
    private const LOGIN_NAMES = ['login', 'login.store'];

    /**
     * @var list<string>
     */
    private const RESET_NAMES = ['password.email'];

    /**
     * @var array<string, string>
     */
    private const URIS = [
        'login' => self::LOGIN,
        'forgot-password' => self::RESET,
        'two-factor-challenge' => self::CHALLENGE,
    ];

    public function id(): string
    {
        return 'probes.rate-limit';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(ProbeContext $context): iterable
    {
        $routes = $this->candidates($context);
        $login = $this->firstOfKind($routes, self::LOGIN, $context);
        $uris = array_values(array_unique(array_map(static fn (RouteInfo $route): string => $route->uri, $routes)));
        $before = $uris === [] ? null : $this->excludeCsrf($uris);

        try {
            if ($routes !== [] && $login === null) {
                $context->coverage()->skipped(new CoverageTarget(
                    'POST /login',
                    'login route not recognized',
                    'add the route name to probes.rate_limit.routes',
                ));
            }

            $selection = $routes === [] ? null : $context->data()?->actors();
            $recorder = $this->recorder();

            foreach ($routes as $route) {
                $finding = $this->check($context, $route, $login, $selection, $recorder);

                if ($finding !== null) {
                    yield $finding;
                }
            }
        } finally {
            if ($before !== null) {
                $this->restoreCsrf($before);
            }
        }
    }

    /**
     * The two factor challenge first, because preparing it needs a login that a lockout from the
     * login attempts of this same probe would block, then the password reset, then login.
     *
     * @return list<RouteInfo>
     */
    private function candidates(ProbeContext $context): array
    {
        $routes = [];

        foreach ([self::CHALLENGE, self::RESET, self::LOGIN] as $wanted) {
            foreach ($context->map()->routes() as $route) {
                if (in_array('POST', $route->methods, true) && $this->kind($route, $context) === $wanted) {
                    $routes[] = $route;
                }
            }
        }

        return $routes;
    }

    private function kind(RouteInfo $route, ProbeContext $context): ?string
    {
        $name = $route->name ?? '';
        $uri = '/'.ltrim($route->uri, '/');

        if (in_array($name, self::LOGIN_NAMES, true)) {
            return self::LOGIN;
        }

        if (in_array($name, self::RESET_NAMES, true)) {
            return self::RESET;
        }

        if (str_contains($name, 'two-factor.login')) {
            return self::CHALLENGE;
        }

        foreach (self::URIS as $path => $uriKind) {
            if ($uri === '/'.ltrim($path, '/')) {
                return $uriKind;
            }
        }

        foreach ($context->config()->rateLimitRoutes as $configured) {
            $path = '/'.ltrim($configured, '/');

            if ($name !== $configured && $uri !== $path) {
                continue;
            }

            if (str_contains($configured, self::CHALLENGE)) {
                return self::CHALLENGE;
            }

            return str_contains($configured, 'password') ? self::RESET : self::LOGIN;
        }

        return null;
    }

    private function check(ProbeContext $context, RouteInfo $route, ?RouteInfo $login, ?DataSelection $selection, ?RateLimiterRecorder $recorder): ?Finding
    {
        $kind = $this->kind($route, $context);

        if ($kind === null) {
            return null;
        }

        $label = $this->label($route);

        if (str_contains($route->uri, '{')) {
            $context->coverage()->skipped(new CoverageTarget($label, 'needs a record for every URL parameter'));

            return null;
        }

        if ($route->usesMiddleware(ThrottleRequests::class)) {
            $context->coverage()->skipped(new CoverageTarget($label, 'limited by middleware'));

            return null;
        }

        if ($kind === self::RESET && $this->passwordBrokerThrottles()) {
            $context->coverage()->skipped(new CoverageTarget($label, 'limited by password broker throttle'));

            return null;
        }

        if ($recorder === null) {
            $context->coverage()->skipped(new CoverageTarget(
                $label,
                'the rate limiter of the application could not be observed',
                'run the probe through security:probe, which installs the probe environment',
            ));

            return null;
        }

        if ($selection === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

            return null;
        }

        if (! $selection->isFound() || $selection->data === null) {
            $context->coverage()->skipped(new CoverageTarget($label, $selection->reason ?? 'no data', $selection->hint));

            return null;
        }

        return $kind === self::CHALLENGE
            ? $this->challenge($context, $route, $login, $label, $selection->data, $recorder)
            : $this->attempts($context, $route, $label, $kind, $selection->data, $recorder);
    }

    private function attempts(ProbeContext $context, RouteInfo $route, string $label, string $kind, ProbeData $data, RateLimiterRecorder $recorder): ?Finding
    {
        $field = $kind === self::RESET ? $this->emailField() : $this->usernameField();
        $address = $data->a->user->getAttribute($field);

        if (! is_string($address) || $address === '') {
            $context->coverage()->skipped(new CoverageTarget($label, sprintf('the user has no %s attribute', $field)));

            return null;
        }

        $payload = $kind === self::RESET
            ? [$field => $address]
            : [$field => $address, 'password' => 'not the password of the account'];

        $statuses = $this->send(
            $context,
            $label,
            $this->uri($route),
            $payload,
            $recorder,
            $kind === self::RESET ? 'the password reset' : 'login',
        );

        if ($statuses === null) {
            return null;
        }

        $context->coverage()->confirmed();

        return $this->finding($route, $kind, $data, $statuses, array_keys($payload));
    }

    private function challenge(ProbeContext $context, RouteInfo $route, ?RouteInfo $login, string $label, ProbeData $data, RateLimiterRecorder $recorder): ?Finding
    {
        $user = $data->a->user;

        if ($login === null) {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, 'add the login route to probes.rate_limit.routes'));

            return null;
        }

        if (! $this->challengeEnabled()) {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, 'enable the two factor authentication feature of Fortify'));

            return null;
        }

        if ($data->mode !== 'factories') {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, 'set probes.data=factories so the probe knows a password'));

            return null;
        }

        if (! $this->hasTwoFactor($user)) {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, 'use a user model that uses TwoFactorAuthenticatable'));

            return null;
        }

        $field = $this->usernameField();
        $address = $user->getAttribute($field);

        if (! is_string($address) || $address === '') {
            $context->coverage()->skipped(new CoverageTarget($label, sprintf('the user has no %s attribute', $field)));

            return null;
        }

        $password = 'security-toolkit-'.Str::random(16);

        if (! $this->enableTwoFactor($user, $password)) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the 2FA account could not be prepared'));

            return null;
        }

        $setup = $context->client()->request('POST', $this->uri($login), [$field => $address, 'password' => $password]);

        if ($setup->status === 429) {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, 'the login was limited (HTTP 429) before the challenge could start'));

            return null;
        }

        if ($setup->status >= 500) {
            $context->coverage()->skipped(new CoverageTarget($label, sprintf('login failed with an application error (HTTP %d)', $setup->status)));

            return null;
        }

        $answer = json_decode($setup->body, true);

        if ($setup->status !== 200 || ! is_array($answer) || ($answer['two_factor'] ?? null) !== true) {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, sprintf('the login answered HTTP %d without two_factor: true', $setup->status)));

            return null;
        }

        if ($setup->cookies === []) {
            $context->coverage()->skipped(new CoverageTarget($label, self::NOT_RECOGNIZED, 'the login returned no session cookie to carry the challenge'));

            return null;
        }

        $statuses = $this->send($context, $label, $this->uri($route), ['code' => '000000'], $recorder, 'the challenge', $setup->cookies);

        if ($statuses === null) {
            return null;
        }

        $context->coverage()->confirmed();

        return $this->finding($route, self::CHALLENGE, $data, $statuses, ['code']);
    }

    /**
     * Sends the attempts of one target and reports what the application did with them. Null means
     * the coverage of this target was already reported: a limit was found, the application broke,
     * or the request never reached the endpoint.
     *
     * @param  array<string, mixed>  $payload
     * @param  array<string, string>  $cookies
     * @return list<int>|null
     */
    private function send(ProbeContext $context, string $label, string $uri, array $payload, RateLimiterRecorder $recorder, string $subject, array $cookies = []): ?array
    {
        $recorder->reset();
        $statuses = [];

        for ($attempt = 1; $attempt <= $context->config()->rateLimitAttempts; $attempt++) {
            $response = $context->client()->request('POST', $uri, $payload, cookies: $cookies);
            $statuses[] = $response->status;

            if ($response->status === 429) {
                $context->coverage()->checked(new CoverageTarget($label, sprintf('answered 429 on attempt %d', $attempt)));

                return null;
            }

            if ($recorder->touched()) {
                $context->coverage()->checked(new CoverageTarget($label, 'the application counted the attempts against a rate limiter'));

                return null;
            }

            if ($response->status === 419) {
                $context->coverage()->skipped(new CoverageTarget($label, 'blocked by the CSRF check', 'the route sits behind a CSRF middleware the probe does not recognize'));

                return null;
            }

            if ($response->status >= 500) {
                $context->coverage()->skipped(new CoverageTarget($label, sprintf('%s failed with an application error (HTTP %d)', $subject, $response->status)));

                return null;
            }
        }

        return $statuses;
    }

    private function enableTwoFactor(Model $user, string $password): bool
    {
        try {
            return $user->forceFill([
                'password' => Hash::make($password),
                'two_factor_secret' => encrypt(app(TwoFactorAuthenticationProvider::class)->generateSecretKey()),
                'two_factor_confirmed_at' => now(),
            ])->save();
        } catch (Throwable) {
            return false;
        }
    }

    private function challengeEnabled(): bool
    {
        if (! class_exists(Features::class)) {
            return false;
        }

        $features = config('fortify.features');

        return is_array($features) && in_array(Features::twoFactorAuthentication(), $features, true);
    }

    private function hasTwoFactor(Model $user): bool
    {
        return in_array(TwoFactorAuthenticatable::class, class_uses_recursive($user), true);
    }

    private function passwordBrokerThrottles(): bool
    {
        $name = config('fortify.passwords') ?? config('auth.defaults.passwords');

        if (! is_string($name)) {
            return false;
        }

        $broker = config('auth.passwords.'.$name);

        if (! is_array($broker)) {
            return false;
        }

        $throttle = $broker['throttle'] ?? null;

        return is_numeric($throttle) && (int) $throttle > 0;
    }

    /**
     * The attempts carry no CSRF token: without this the check would answer 419 for every one of
     * them and the probe would take its own block for a limit. The URIs of the targets are excluded
     * for the life of this run — this process, no other — and the exclusions the process started
     * with are put back afterwards, so the CSRF probe, which reports on exactly these, is not
     * affected either way.
     *
     * @param  list<string>  $uris
     * @return list<string>
     */
    private function excludeCsrf(array $uris): array
    {
        $before = (new PreventRequestForgery(app(), app(Encrypter::class)))->getExcludedPaths();

        PreventRequestForgery::except($uris);

        return array_values(array_filter($before, is_string(...)));
    }

    /**
     * @param  list<string>  $before
     */
    private function restoreCsrf(array $before): void
    {
        PreventRequestForgery::flushState();

        if ($before !== []) {
            PreventRequestForgery::except($before);
        }
    }

    /**
     * @param  list<RouteInfo>  $routes
     */
    private function firstOfKind(array $routes, string $kind, ProbeContext $context): ?RouteInfo
    {
        foreach ($routes as $route) {
            if ($this->kind($route, $context) === $kind) {
                return $route;
            }
        }

        return null;
    }

    /**
     * @param  list<int>  $statuses
     * @param  list<string>  $fields
     */
    private function finding(RouteInfo $route, string $kind, ProbeData $data, array $statuses, array $fields): Finding
    {
        $target = $this->label($route);
        $seen = implode('/', array_unique($statuses));

        $base = new Finding(
            'probes.missing-rate-limit',
            $kind === self::CHALLENGE ? Severity::High : Severity::Medium,
            sprintf('%s is not limited by the application', $target),
            sprintf('The route %s answered %d attempts from one address in a row (%s) without the application blocking them, counting them against a rate limiter or raising a lockout. A limit on the web server or a WAF in front of the application is invisible from inside the application, so that layer has to be checked separately.', $target, count($statuses), $seen),
            'Give the route a rate limiter of its own: RateLimiter::for(\'login\', fn () => Limit::perMinute(5)) and throttle:login on the route.',
            [
                'https://laravel.com/docs/routing#rate-limiting',
                'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
            ],
            $route->file === null ? null : new Location($route->file, $route->line),
            cwe: [307],
        );

        return $base->withConfirmation(
            $this->reproduction($route, $data, $statuses, $fields),
            sprintf('%d attempts from one address were answered %s, none of them limited', count($statuses), $seen),
        );
    }

    /**
     * @param  list<int>  $statuses
     * @param  list<string>  $fields
     */
    private function reproduction(RouteInfo $route, ProbeData $data, array $statuses, array $fields): Reproduction
    {
        $group = $data->a->group;
        $seen = implode('/', array_unique($statuses));

        return new Reproduction(
            $this->id(),
            $data->mode,
            [[
                'name' => 'A',
                'model' => $data->a->user::class,
                'id' => $data->a->id(),
                'owner' => $group === null ? null : $group::class.'#'.$this->keyOf($group),
            ]],
            [new ReproductionStep(
                'A',
                'POST '.$this->uri($route),
                null,
                $fields,
                sprintf('429 or a lockout within %d attempts', count($statuses)),
                sprintf('%d attempts answered %s without a limit', count($statuses), $seen),
            )],
        );
    }

    private function uri(RouteInfo $route): string
    {
        return '/'.ltrim($route->uri, '/');
    }

    private function label(RouteInfo $route): string
    {
        return implode('|', $route->methods).' /'.$route->uri;
    }

    private function usernameField(): string
    {
        $field = config('fortify.username');

        return is_string($field) && $field !== '' ? $field : 'email';
    }

    private function emailField(): string
    {
        $field = config('fortify.email');

        return is_string($field) && $field !== '' ? $field : 'email';
    }

    private function recorder(): ?RateLimiterRecorder
    {
        if (! app()->bound(RateLimiterRecorder::class)) {
            return null;
        }

        return app()->make(RateLimiterRecorder::class);
    }

    private function keyOf(Model $record): string
    {
        $key = $record->getKey();

        return is_int($key) || is_string($key) ? (string) $key : '?';
    }
}
