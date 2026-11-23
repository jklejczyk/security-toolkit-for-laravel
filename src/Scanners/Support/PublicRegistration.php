<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Support;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\AuthenticateWithBasicAuth;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;

/**
 * Registration open to anyone, and whether an account it creates gets past a route's login.
 */
final class PublicRegistration
{
    /**
     * Route names of the registration form submit in Breeze, the starter kits, Fortify and Jetstream.
     */
    private const NAMES = ['register', 'register.store'];

    /**
     * A POST registration route that needs no login.
     *
     * @param  list<RouteInfo>  $routes
     */
    public function route(array $routes): ?RouteInfo
    {
        foreach ($routes as $route) {
            if (! in_array('POST', $route->methods, true)) {
                continue;
            }

            if (! in_array($route->name, self::NAMES, true) && trim($route->uri, '/') !== 'register') {
                continue;
            }

            if (! $route->usesMiddleware(Authenticate::class, AuthenticateWithBasicAuth::class)) {
                return $route;
            }
        }

        return null;
    }

    /**
     * True when one of the route's guards uses the provider of the default guard, where
     * registration creates accounts. An unknown guard or a guard without a provider does not count.
     */
    public function reaches(RouteInfo $route): bool
    {
        $default = config('auth.defaults.guard');
        $provider = is_string($default) ? $this->provider($default) : null;

        if ($provider === null) {
            return false;
        }

        foreach ($this->guards($route) as $guard) {
            if ($this->provider($guard) === $provider) {
                return true;
            }
        }

        return false;
    }

    public function label(RouteInfo $route): string
    {
        return sprintf('%s /%s', implode('|', array_diff($route->methods, ['HEAD'])), ltrim($route->uri, '/'));
    }

    /**
     * Guards named by the auth middleware ("auth:admin,web"); none means the default guard, and
     * sanctum stands for the guards Sanctum authenticates with.
     *
     * @return list<string>
     */
    private function guards(RouteInfo $route): array
    {
        $default = config('auth.defaults.guard');
        $guards = [];

        foreach ($route->middlewareParameters(Authenticate::class) as $parameters) {
            foreach ($parameters === '' ? [is_string($default) ? $default : ''] : explode(',', $parameters) as $guard) {
                $guard = trim($guard);

                if ($guard === 'sanctum') {
                    $guards = [...$guards, ...array_values(array_filter((array) config('sanctum.guard', ['web']), is_string(...)))];

                    continue;
                }

                $guards[] = $guard;
            }
        }

        return $guards;
    }

    private function provider(string $guard): ?string
    {
        $provider = config("auth.guards.{$guard}.provider");

        return is_string($provider) ? $provider : null;
    }
}
