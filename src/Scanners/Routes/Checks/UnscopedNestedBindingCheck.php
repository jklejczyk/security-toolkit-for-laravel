<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\BelongsToInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteParameter;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Routes\ActionSource;

final class UnscopedNestedBindingCheck implements Check
{
    public function __construct(
        private readonly ActionSource $source = new ActionSource,
    ) {}

    public function id(): string
    {
        return 'routes.unscoped-nested-binding';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    /**
     * /clients/{client}/invoices/{invoice} where Invoice belongs to Client: without scoped bindings
     * Laravel loads invoice 5 even when it belongs to another client, and a check on the client
     * alone lets it through.
     */
    public function run(ScanContext $context): iterable
    {
        foreach ($context->map->routes() as $route) {
            if (! $route->inApp || $route->controller === null || count($route->models) < 2) {
                continue;
            }

            for ($i = 1; $i < count($route->models); $i++) {
                [$parent, $child] = [$route->models[$i - 1], $route->models[$i]];

                if ($this->scoped($route, $child)) {
                    continue;
                }

                $relation = $this->relation($context, $child, $parent);

                if ($relation === null || $this->comparedInAction($route, $child, $relation)) {
                    continue;
                }

                yield $this->finding($route, $parent, $child, $relation);
            }
        }
    }

    /**
     * scopeBindings() on the route, or a custom key on the child ({invoice:number}), which Laravel
     * scopes by itself unless the route calls withoutScopedBindings().
     */
    private function scoped(RouteInfo $route, RouteParameter $child): bool
    {
        if ($route->preventsScopedBindings) {
            return false;
        }

        return $route->enforcesScopedBindings || $child->field !== null;
    }

    private function relation(ScanContext $context, RouteParameter $child, RouteParameter $parent): ?BelongsToInfo
    {
        foreach ($context->map->belongsTo($child->model) as $relation) {
            if (is_a($parent->model, $relation->related, true)) {
                return $relation;
            }
        }

        return null;
    }

    /**
     * The action compares the foreign key itself, e.g. abort_unless($invoice->client_id === $client->id, 404).
     */
    private function comparedInAction(RouteInfo $route, RouteParameter $child, BelongsToInfo $relation): bool
    {
        $code = $this->source->action($route);

        return $code !== null && (
            str_contains($code, sprintf('$%s->%s', $child->name, $relation->foreignKey))
            || str_contains($code, sprintf('$%s->%s()->is(', $child->name, $relation->method))
            || str_contains($code, sprintf('$%s->%s->is(', $child->name, $relation->method))
        );
    }

    private function finding(RouteInfo $route, RouteParameter $parent, RouteParameter $child, BelongsToInfo $relation): Finding
    {
        $methods = implode('|', $route->methods);

        return new Finding(
            $this->id(),
            Severity::Medium,
            sprintf('%s /%s loads any %s, not only one of the %s', $methods, $route->uri, class_basename($child->model), class_basename($parent->model)),
            sprintf(
                'The route nests {%s} under {%s}, and %s belongs to %s (%s), but the binding is not scoped: Laravel loads the %s by id alone, even when it belongs to another %s. If the action authorizes only the %s, a user who may see one %s can read every %s by changing the id.',
                $child->name,
                $parent->name,
                class_basename($child->model),
                class_basename($parent->model),
                $relation->foreignKey,
                class_basename($child->model),
                class_basename($parent->model),
                class_basename($parent->model),
                class_basename($parent->model),
                class_basename($child->model),
            ),
            'Call ->scopeBindings() on the route or the route group, so Laravel loads the child through the parent\'s relation, or authorize the child itself.',
            [
                'https://laravel.com/docs/routing#implicit-model-binding-scoping',
                'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            ],
            $route->file === null ? null : new Location($route->file, $route->line),
            cwe: [639],
            confidence: Confidence::Suspected,
        );
    }
}
