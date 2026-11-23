<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth\Checks;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\AuthenticateWithBasicAuth;
use Illuminate\Auth\Middleware\EnsureEmailIsVerified;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use ReflectionClass;

final class VerifiedWithoutMustVerifyEmailCheck implements Check
{
    /**
     * Route names of the registration form submit in Breeze, the starter kits, Fortify and Jetstream.
     */
    private const REGISTRATION_NAMES = ['register', 'register.store'];

    public function id(): string
    {
        return 'auth.verified-without-must-verify-email';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    /**
     * EnsureEmailIsVerified checks only users that implement MustVerifyEmail; everyone else passes.
     * The starter kits ship "verified" routes with the interface commented out, which is harmless
     * while accounts are created by someone trusted, so the rule needs public registration too.
     */
    public function run(ScanContext $context): iterable
    {
        $verified = array_values(array_filter($context->map->routes(), fn (RouteInfo $route): bool => $route->usesMiddleware(EnsureEmailIsVerified::class)));
        $registration = $this->publicRegistration($context->map->routes());

        if ($verified === [] || $registration === null) {
            return [];
        }

        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! class_exists($model)) {
            throw CheckSkipped::because('the user model (auth.providers.users.model) could not be resolved');
        }

        if (is_subclass_of($model, MustVerifyEmail::class)) {
            return [];
        }

        $file = (new ReflectionClass($model))->getFileName();

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                'The verified middleware does not check anything',
                sprintf(
                    '%d %s the verified middleware (for example %s), but %s does not implement MustVerifyEmail, so EnsureEmailIsVerified lets every user through. Registration is public (%s), so anyone can create an account with an address they do not own and reach those routes as if it were confirmed.',
                    count($verified),
                    count($verified) === 1 ? 'route uses' : 'routes use',
                    $this->describe($verified[0]),
                    $model,
                    $this->describe($registration),
                ),
                'Add "implements MustVerifyEmail" (Illuminate\Contracts\Auth\MustVerifyEmail) to the user model; Illuminate\Foundation\Auth\User already has the methods it needs. If the application does not need confirmed addresses, remove verified from the routes so it does not suggest a check that is not there.',
                [
                    'https://laravel.com/docs/verification#model-preparation',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
                ],
                $file === false ? null : Location::inApplication($file, $context->basePath),
                cwe: [304],
            ),
        ];
    }

    /**
     * A POST registration route that needs no login.
     *
     * @param  list<RouteInfo>  $routes
     */
    private function publicRegistration(array $routes): ?RouteInfo
    {
        foreach ($routes as $route) {
            if (! in_array('POST', $route->methods, true)) {
                continue;
            }

            if (! in_array($route->name, self::REGISTRATION_NAMES, true) && trim($route->uri, '/') !== 'register') {
                continue;
            }

            if (! $route->usesMiddleware(Authenticate::class, AuthenticateWithBasicAuth::class)) {
                return $route;
            }
        }

        return null;
    }

    private function describe(RouteInfo $route): string
    {
        $methods = array_values(array_diff($route->methods, ['HEAD']));

        return sprintf('%s /%s', implode('|', $methods), ltrim($route->uri, '/'));
    }
}
