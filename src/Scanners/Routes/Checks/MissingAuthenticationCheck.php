<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes\Checks;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\AuthenticateWithBasicAuth;
use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Routing\Middleware\ValidateSignature;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

final class MissingAuthenticationCheck implements Check
{
    public function id(): string
    {
        return 'routes.missing-authentication';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    /**
     * Only writes to an existing model: a public form (contact, sign up) or a webhook writes
     * without a model in the URL, while changing or deleting a bound record without logging in
     * is almost always a mistake.
     */
    public function run(ScanContext $context): iterable
    {
        foreach ($context->map->routes() as $route) {
            if (! $route->inApp || $route->controller === null || ! $route->isWrite() || $route->models === []) {
                continue;
            }

            if ($route->usesMiddleware(Authenticate::class, AuthenticateWithBasicAuth::class, ValidateSignature::class, Authorize::class)) {
                continue;
            }

            yield $this->finding($route);
        }
    }

    private function finding(RouteInfo $route): Finding
    {
        $methods = implode('|', $route->methods);
        $models = implode(', ', array_map(fn ($parameter) => class_basename($parameter->model), $route->models));

        return new Finding(
            $this->id(),
            Severity::High,
            sprintf('%s /%s changes %s records without login', $methods, $route->uri, $models),
            sprintf('The route %s /%s (%s@%s) changes or deletes an existing %s, but has no authentication middleware (auth, auth.basic), no signed URL and no can: middleware, so anyone who knows or guesses an id can call it. If the action checks a token or signature itself, this finding can be ignored.', $methods, $route->uri, class_basename((string) $route->controller), $route->action, $models),
            'Put the route in a group with the auth middleware (or auth:sanctum for an API), or use a signed URL (signed middleware) for links sent by email.',
            [
                'https://laravel.com/docs/authentication#protecting-routes',
                'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
            ],
            $route->file === null ? null : new Location($route->file, $route->line),
            cwe: [306],
            confidence: Confidence::Suspected,
        );
    }
}
