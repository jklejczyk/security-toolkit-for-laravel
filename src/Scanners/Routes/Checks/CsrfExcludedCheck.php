<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes\Checks;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Support\Str;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use ReflectionClass;
use Throwable;

final class CsrfExcludedCheck implements Check
{
    /**
     * CSRF middleware: PreventRequestForgery in Laravel 13, VerifyCsrfToken (and ValidateCsrfToken)
     * in Laravel 12. Both keep the URIs from validateCsrfTokens(except:) in a static $neverVerify.
     */
    private const CSRF_MIDDLEWARE = [
        'Illuminate\Foundation\Http\Middleware\PreventRequestForgery',
        'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken',
    ];

    private const VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N';

    public function id(): string
    {
        return 'routes.csrf-excluded';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    /**
     * An excluded URI matters only for a route that changes data for a session user. A webhook
     * has no session, and with SameSite=lax or strict the browser does not send the session
     * cookie with a cross-site POST, so in both cases there is nothing to forge.
     */
    public function run(ScanContext $context): iterable
    {
        $exposed = [];

        foreach ($context->map->routes() as $route) {
            if (! $route->inApp || ! $route->isWrite() || ! $this->usesCsrfMiddleware($route) || ! $this->usesSession($route)) {
                continue;
            }

            foreach ($this->exclusions($route) as $pattern => $source) {
                if ($this->matches($pattern, $route)) {
                    $exposed[$pattern]['source'] = $source;
                    $exposed[$pattern]['routes'][] = implode('|', $route->methods).' /'.$route->uri;
                }
            }
        }

        if ($exposed === []) {
            return;
        }

        $sameSite = config('session.same_site');

        if (in_array(is_string($sameSite) ? strtolower($sameSite) : $sameSite, ['lax', 'strict'], true)) {
            return;
        }

        if (! $context->isProduction() && $this->sameSiteFromEnv($context)) {
            throw CheckSkipped::because('session.same_site comes from env(), so the production value is unknown here; run the scan with --env=production');
        }

        foreach ($exposed as $pattern => ['source' => $source, 'routes' => $routes]) {
            yield $this->finding((string) $pattern, $source, array_values(array_unique($routes)), $sameSite, $context);
        }
    }

    private function usesCsrfMiddleware(RouteInfo $route): bool
    {
        foreach (self::CSRF_MIDDLEWARE as $class) {
            if (class_exists($class) && $route->usesMiddleware($class)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Authenticate with a guard whose driver is "session" (the default guard when none is named).
     */
    private function usesSession(RouteInfo $route): bool
    {
        $guards = (array) config('auth.guards', []);
        $default = config('auth.defaults.guard');

        foreach ($route->middlewareParameters(Authenticate::class) as $parameters) {
            $names = $parameters === '' ? [$default] : explode(',', $parameters);

            foreach ($names as $name) {
                if (is_string($name) && is_array($guards[$name] ?? null) && ($guards[$name]['driver'] ?? null) === 'session') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Excluded URI pattern => where it is configured: the static list of the framework middleware
     * and the $except of an application subclass used by the route.
     *
     * @return array<string, ?string>
     */
    private function exclusions(RouteInfo $route): array
    {
        $exclusions = [];

        foreach (self::CSRF_MIDDLEWARE as $class) {
            foreach ($this->neverVerify($class) as $pattern) {
                $exclusions[$pattern] = 'bootstrap/app.php';
            }
        }

        foreach ($route->middleware as $middleware) {
            $class = explode(':', $middleware, 2)[0];

            if (in_array($class, self::CSRF_MIDDLEWARE, true) || ! class_exists($class) || ! $this->isCsrfMiddleware($class)) {
                continue;
            }

            try {
                $reflection = new ReflectionClass($class);
                $except = $reflection->getDefaultProperties()['except'] ?? [];
            } catch (Throwable) {
                continue;
            }

            foreach (is_array($except) ? $except : [] as $pattern) {
                if (is_string($pattern)) {
                    $exclusions[$pattern] = $reflection->getFileName() ?: null;
                }
            }
        }

        return $exclusions;
    }

    /**
     * @return list<string>
     */
    private function neverVerify(string $class): array
    {
        if (! class_exists($class) || ! property_exists($class, 'neverVerify')) {
            return [];
        }

        try {
            $value = (new ReflectionClass($class))->getStaticPropertyValue('neverVerify');
        } catch (Throwable) {
            return [];
        }

        return array_values(array_filter(is_array($value) ? $value : [], is_string(...)));
    }

    private function isCsrfMiddleware(string $class): bool
    {
        foreach (self::CSRF_MIDDLEWARE as $base) {
            if (class_exists($base) && is_subclass_of($class, $base)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The same matching as $request->is(): "*" matches anything, also across segments.
     */
    private function matches(string $pattern, RouteInfo $route): bool
    {
        $pattern = $pattern === '/' ? $pattern : trim($pattern, '/');

        return Str::is($pattern, $route->uri) || Str::is($pattern, '/'.$route->uri);
    }

    private function sameSiteFromEnv(ScanContext $context): bool
    {
        $path = rtrim($context->basePath, '/').'/config/session.php';

        // Without a published config the framework default, env('SESSION_SAME_SITE', 'lax'), applies.
        if (! is_file($path)) {
            return true;
        }

        $config = is_readable($path) ? file_get_contents($path) : false;

        if ($config === false) {
            throw CheckSkipped::because('could not read config/session.php');
        }

        return preg_match('/[\'"]same_site[\'"]\s*=>\s*env\s*\(/', $config) === 1;
    }

    /**
     * @param  list<string>  $routes
     */
    private function finding(string $pattern, ?string $source, array $routes, mixed $sameSite, ScanContext $context): Finding
    {
        $cvss = Cvss::fromVector(self::VECTOR);

        return new Finding(
            $this->id(),
            $cvss->severity(),
            sprintf('"%s" is excluded from CSRF protection for logged-in routes', $pattern),
            sprintf(
                'The URI pattern "%s" skips the CSRF token check, and it matches routes that change data for a user signed in with a session cookie: %s. session.same_site is %s, so the browser sends the session cookie with a request from another site, and a page the user visits can submit these requests in their name.',
                $pattern,
                implode(', ', $routes),
                is_string($sameSite) ? "'".$sameSite."'" : 'null',
            ),
            'Remove the pattern from validateCsrfTokens(except: [...]) and send the token with the request (the @csrf directive, or the X-XSRF-TOKEN header). Exclude only routes called without a session, such as webhooks, and set session.same_site to "lax".',
            [
                'https://laravel.com/docs/csrf#csrf-excluding-uris',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
            ],
            $this->location($pattern, $source, $context),
            cwe: [352],
            cvss: $cvss,
        );
    }

    private function location(string $pattern, ?string $source, ScanContext $context): ?Location
    {
        if ($source === null) {
            return null;
        }

        $path = str_starts_with($source, '/') ? $source : rtrim($context->basePath, '/').'/'.$source;
        $lines = is_readable($path) ? file($path) : false;

        if ($lines === false) {
            return null;
        }

        foreach ($lines as $number => $line) {
            if (str_contains($line, "'".$pattern."'") || str_contains($line, '"'.$pattern.'"')) {
                return Location::inApplication($path, $context->basePath, $number + 1);
            }
        }

        return Location::inApplication($path, $context->basePath);
    }
}
