<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes\Checks;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\AuthenticateWithBasicAuth;
use Illuminate\Auth\Middleware\Authorize;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Routes\ActionSource;

final class MissingAuthorizationCheck implements Check
{
    public function __construct(
        private readonly ActionSource $source = new ActionSource,
    ) {}

    public function id(): string
    {
        return 'routes.missing-authorization';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    /**
     * A logged-in route that loads a model from the URL with no trace of authorization: no can:
     * middleware, no authorize()/Gate/abort call in the action, no authorizeResource() and no form
     * request with a real authorize(). Authorization in a service or a global scope is invisible
     * here, hence "suspected".
     */
    public function run(ScanContext $context): iterable
    {
        $unreadable = [];

        foreach ($context->map->routes() as $route) {
            if (! $route->inApp || $route->controller === null || $route->models === []) {
                continue;
            }

            if (! $route->usesMiddleware(Authenticate::class, AuthenticateWithBasicAuth::class) || $route->usesMiddleware(Authorize::class)) {
                continue;
            }

            $authorizes = $this->source->authorizes($route);

            if ($authorizes === null) {
                $unreadable[] = sprintf('%s@%s', $route->controller, $route->action);

                continue;
            }

            if (! $authorizes) {
                yield $this->finding($route, $context);
            }
        }

        if ($unreadable !== []) {
            throw CheckSkipped::because('could not read the code of '.implode(', ', array_unique($unreadable)));
        }
    }

    private function finding(RouteInfo $route, ScanContext $context): Finding
    {
        $methods = implode('|', $route->methods);
        $model = $route->models[count($route->models) - 1]->model;
        $policy = $context->map->policyFor($model);

        return new Finding(
            $this->id(),
            Severity::Medium,
            sprintf('%s /%s does not authorize access to the %s', $methods, $route->uri, class_basename($model)),
            sprintf(
                'The route %s /%s (%s@%s) loads a %s from the URL for any logged-in user, but neither the route nor the action checks that the user may access it, so changing the id in the URL may reach another user\'s record (IDOR). %s',
                $methods,
                $route->uri,
                class_basename((string) $route->controller),
                $route->action,
                class_basename($model),
                $policy === null
                    ? sprintf('%s has no policy.', class_basename($model))
                    : sprintf('%s exists but is not used here.', class_basename($policy)),
            ),
            sprintf('Call $this->authorize() with a policy method in the action, or add ->can(\'...\', \'%s\') to the route.', $route->models[count($route->models) - 1]->name),
            [
                'https://laravel.com/docs/authorization#authorizing-actions-using-policies',
                'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            ],
            $route->file === null ? null : new Location($route->file, $route->line),
            cwe: [639],
            confidence: Confidence::Suspected,
        );
    }
}
