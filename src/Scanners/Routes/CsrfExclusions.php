<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Support\Str;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use ReflectionClass;
use Throwable;

/**
 * Which routes are behind CSRF protection and which URIs the application excludes from it. Shared by
 * the static check (routes.csrf-excluded) and the CSRF probe, so both agree on the target and the
 * location the exclusion is written at.
 */
final class CsrfExclusions
{
    /**
     * CSRF middleware: PreventRequestForgery in Laravel 13, VerifyCsrfToken (and ValidateCsrfToken)
     * in Laravel 12. Both keep the URIs from validateCsrfTokens(except:) in a static $neverVerify.
     */
    public const CSRF_MIDDLEWARE = [
        'Illuminate\Foundation\Http\Middleware\PreventRequestForgery',
        'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken',
    ];

    public function usesMiddleware(RouteInfo $route): bool
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
    public function usesSession(RouteInfo $route): bool
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
     * The patterns that match the route, each with where it is configured.
     *
     * @return list<array{pattern: string, source: ?string}>
     */
    public function matching(RouteInfo $route): array
    {
        $matches = [];

        foreach ($this->exclusions($route) as $pattern => $source) {
            if ($this->matches($pattern, $route)) {
                $matches[] = ['pattern' => $pattern, 'source' => $source];
            }
        }

        return $matches;
    }

    /**
     * Excluded URI pattern => where it is configured: the static list of the framework middleware
     * and the $except of an application subclass used by the route.
     *
     * @return array<string, ?string>
     */
    public function exclusions(RouteInfo $route): array
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
     * The line of the pattern in its source file, relative to the application when inside it.
     */
    public function location(string $pattern, ?string $source, string $basePath): ?Location
    {
        if ($source === null) {
            return null;
        }

        $path = str_starts_with($source, '/') ? $source : rtrim($basePath, '/').'/'.$source;
        $lines = is_readable($path) ? file($path) : false;

        if ($lines === false) {
            return null;
        }

        foreach ($lines as $number => $line) {
            if (str_contains($line, "'".$pattern."'") || str_contains($line, '"'.$pattern.'"')) {
                return Location::inApplication($path, $basePath, $number + 1);
            }
        }

        return Location::inApplication($path, $basePath);
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
    public function matches(string $pattern, RouteInfo $route): bool
    {
        $pattern = $pattern === '/' ? $pattern : trim($pattern, '/');

        return Str::is($pattern, $route->uri) || Str::is($pattern, '/'.$route->uri);
    }
}
