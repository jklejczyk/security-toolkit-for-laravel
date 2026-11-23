<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Probes;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\AuthenticateWithBasicAuth;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteParameter;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\ProbeData;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\Owner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\ValidationRequest;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;

/**
 * Confirms an IDOR on an authenticated route: user A asks for a record owned by B, the policy says A
 * may not, and the route still answers. A read is confirmed when the response carries a value of B's
 * record that the owner's own request did not; a delete is confirmed when B's record really goes.
 * The policy is the source of intent, so a resource that is shared on purpose is never reported.
 */
final class IdorProbe implements Probe
{
    private const ABILITIES = ['GET' => 'view', 'DELETE' => 'delete', 'PUT' => 'update', 'PATCH' => 'update'];

    private const SUSPICIONS = ['routes.missing-authorization', 'routes.unscoped-nested-binding'];

    private const MIN_VALUE_LENGTH = 6;

    public function id(): string
    {
        return 'probes.idor';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(ProbeContext $context): iterable
    {
        $suspicions = [];

        foreach (self::SUSPICIONS as $rule) {
            foreach ($context->targets()->forRule($rule) as $target) {
                $suspicions[$this->key($target->route)] = $target->suspicion;
            }
        }

        foreach ($this->candidates($context, $suspicions) as $route) {
            $finding = $this->check($context, $route, $suspicions[$this->key($route)] ?? null);

            if ($finding !== null) {
                yield $finding;
            }
        }
    }

    /**
     * Authenticated routes with a model parameter, suspicions first so the probe reproduces what the
     * static scan already suspected, then the rest (a route can authorize the wrong object entirely).
     *
     * @param  array<string, Finding>  $suspicions
     * @return list<RouteInfo>
     */
    private function candidates(ProbeContext $context, array $suspicions): array
    {
        $ordered = [];
        $seen = [];

        foreach ($context->map()->routes() as $route) {
            if (! $this->authenticated($route) || $route->models === []) {
                continue;
            }

            $key = $this->key($route);

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;

            if (isset($suspicions[$key])) {
                array_unshift($ordered, $route);

                continue;
            }

            $ordered[] = $route;
        }

        return $ordered;
    }

    private function check(ProbeContext $context, RouteInfo $route, ?Finding $suspicion): ?Finding
    {
        $method = $this->method($route->methods);

        if ($method === null) {
            return null;
        }

        $label = $this->label($route);

        $child = $route->models[count($route->models) - 1]->model;
        $ability = self::ABILITIES[$method];
        $policy = $context->map()->policyFor($child);

        if ($policy === null || ! method_exists($policy, $ability)) {
            $context->coverage()->skipped(new CoverageTarget(
                $label,
                $policy === null ? 'no policy for '.class_basename($child) : sprintf('%s has no %s method', class_basename($policy), $ability),
                'add a policy so the probe knows who may access '.class_basename($child),
            ));

            return null;
        }

        $ownership = $context->ownership();
        $selector = $context->data();

        if ($ownership === null || $selector === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

            return null;
        }

        $owner = $ownership->for($child)->owner;

        if ($owner === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'no owner for '.class_basename($child), 'set probes.owners'));

            return null;
        }

        $selection = $selector->for($child, $owner);

        if (! $selection->isFound() || $selection->data === null) {
            $context->coverage()->skipped(new CoverageTarget($label, $selection->reason ?? 'no data', $selection->hint));

            return null;
        }

        $data = $selection->data;
        $actor = $data->a->user;

        if ($data->recordA === null || $data->recordB === null) {
            return null;
        }

        if (! $actor instanceof Authenticatable) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model is not an Authenticatable'));

            return null;
        }

        if (Gate::forUser($actor)->allows($ability, $data->recordB)) {
            $context->coverage()->checked(new CoverageTarget($label, 'the policy allows A to access B'));

            return null;
        }

        $parent = null;

        if (count($route->models) > 1 && $this->uri($route, $ownership, $data->recordA, $data->recordA) === null) {
            $nested = $this->nested($context, $route, $owner, $data, $label);

            if ($nested === null) {
                return null;
            }

            [$parent, $childA] = $nested;
            $data = new ProbeData($data->mode, $data->a, $data->b, $childA, $data->recordB);
        }

        return match ($method) {
            'GET' => $this->read($context, $route, $suspicion, $ownership, $data, $actor, $ability, $parent),
            'DELETE' => $this->delete($context, $route, $suspicion, $ownership, $data, $actor, $ability, $method, $parent),
            default => $this->write($context, $route, $suspicion, $ownership, $data, $actor, $ability, $method, $owner, $parent),
        };
    }

    /**
     * The URL parent of a nested route that is not on the child's owner path (a client in
     * clients/{client}/invoices/{invoice} when the invoice belongs to a company): a parent record of A
     * and a child of A under it, for the baseline. One such parent only; a deeper chain built from
     * unlinked records would answer 404 even for A and hide what the route does.
     *
     * @return array{0: Model, 1: Model}|null
     */
    private function nested(ProbeContext $context, RouteInfo $route, Owner $owner, ProbeData $data, string $label): ?array
    {
        if (count($route->models) > 2) {
            $context->coverage()->skipped(new CoverageTarget($label, 'nested routes with more than one parent outside the owner path are not supported', 'set probes.owners'));

            return null;
        }

        $parentModel = $route->models[0]->model;
        $childModel = $route->models[1]->model;
        $relation = null;

        foreach ($context->map()->belongsTo($childModel) as $belongsTo) {
            if (is_a($belongsTo->related, $parentModel, true)) {
                $relation = $belongsTo;

                break;
            }
        }

        if ($relation === null) {
            $context->coverage()->skipped(new CoverageTarget($label, sprintf('cannot find how %s belongs to %s', class_basename($childModel), class_basename($parentModel)), 'set probes.owners'));

            return null;
        }

        $selector = $context->data();
        $parent = $selector?->recordFor($parentModel, $data->a, $data->mode);

        if ($selector === null || $parent === null) {
            $context->coverage()->skipped(new CoverageTarget($label, sprintf('no %s of A', class_basename($parentModel)), 'set probes.owners or probes.data'));

            return null;
        }

        $childA = $selector->childUnder($childModel, $owner, $data->a, $relation->foreignKey, $parent, $data->mode);

        if ($childA === null) {
            $context->coverage()->skipped(new CoverageTarget($label, sprintf('no %s of A under its %s', class_basename($childModel), class_basename($parentModel))));

            return null;
        }

        return [$parent, $childA];
    }

    private function read(ProbeContext $context, RouteInfo $route, ?Finding $suspicion, OwnershipResolver $ownership, ProbeData $data, Authenticatable $actor, string $ability, ?Model $parent = null): ?Finding
    {
        $recordA = $data->recordA;
        $recordB = $data->recordB;
        $label = $this->label($route);

        if ($recordA === null || $recordB === null) {
            return null;
        }

        $baseline = $this->uri($route, $ownership, $recordA, $recordA, $parent);
        $attack = $this->uri($route, $ownership, $recordA, $recordB, $parent);

        if ($baseline === null || $attack === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'needs records for every URL parameter'));

            return null;
        }

        $before = $context->client()->request('GET', $baseline, user: $actor);

        if ($parent !== null && ! $before->isSuccessful()) {
            $context->coverage()->skipped(new CoverageTarget($label, 'A cannot open its own record through this route', 'set probes.owners'));

            return null;
        }

        $response = $context->client()->request('GET', $attack, user: $actor);

        if (! $response->isSuccessful()) {
            $context->coverage()->checked(new CoverageTarget($label, sprintf('answered %d for the other owner', $response->status)));

            return null;
        }

        $value = $this->distinguishingValue($recordB, $recordA, $before->body);

        if ($value === null || ! $this->contains($response->body, $value)) {
            $context->coverage()->checked(new CoverageTarget($label, 'the answer could not be compared'));

            return null;
        }

        $context->coverage()->confirmed();

        return $this->confirmed($suspicion, $route, $data, $recordB, $value, $attack, sprintf(
            'user A read %s#%s owned by B (HTTP %d)',
            class_basename($recordB),
            $this->keyOf($recordB),
            $response->status,
        ));
    }

    private function delete(ProbeContext $context, RouteInfo $route, ?Finding $suspicion, OwnershipResolver $ownership, ProbeData $data, Authenticatable $actor, string $ability, string $method, ?Model $parent = null): ?Finding
    {
        $recordA = $data->recordA;
        $recordB = $data->recordB;
        $label = $this->label($route);

        if ($recordA === null || $recordB === null) {
            return null;
        }

        $attack = $this->uri($route, $ownership, $recordA, $recordB, $parent);

        if ($attack === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'needs records for every URL parameter'));

            return null;
        }

        $response = $context->client()->request($method, $attack, user: $actor, verifyCsrf: false);

        if ($response->isCsrfRejection()) {
            $context->coverage()->skipped(new CoverageTarget($label, 'blocked by the CSRF check', 'the route sits behind a CSRF middleware the probe does not recognize'));

            return null;
        }

        $model = $recordB::class;
        $gone = ! $model::query()->whereKey($recordB->getKey())->exists();

        if (! $gone) {
            $context->coverage()->checked(new CoverageTarget($label, sprintf('answered %d for the other owner', $response->status)));

            return null;
        }

        $context->coverage()->confirmed();

        return $this->confirmed($suspicion, $route, $data, $recordB, null, $attack, sprintf(
            'user A deleted %s#%s owned by B (HTTP %d)',
            class_basename($recordB),
            $this->keyOf($recordB),
            $response->status,
        ));
    }

    /**
     * Confirms a write IDOR: A sends the route with B's record and a valid body, and B's record really
     * changes. The effect on B (not the status) is the proof, so a route that validates and then
     * refuses, or one that returns 200 without saving, is never confirmed.
     */
    private function write(ProbeContext $context, RouteInfo $route, ?Finding $suspicion, OwnershipResolver $ownership, ProbeData $data, Authenticatable $actor, string $ability, string $method, Owner $owner, ?Model $parent = null): ?Finding
    {
        $recordA = $data->recordA;
        $recordB = $data->recordB;
        $label = $this->label($route);

        if ($recordA === null || $recordB === null) {
            return null;
        }

        $attack = $this->uri($route, $ownership, $recordA, $recordB, $parent);

        if ($attack === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'needs records for every URL parameter'));

            return null;
        }

        $payload = $context->payload();

        if ($payload === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

            return null;
        }

        $child = $route->models[count($route->models) - 1]->model;
        $own = $this->uri($route, $ownership, $recordA, $recordA, $parent);
        $body = $payload->build($route, $owner, $data->a, $child, $own === null ? null : new ValidationRequest($context->client(), $method, $own, $actor));

        if (! $body->isBuilt() || $body->body === null) {
            $context->coverage()->skipped(new CoverageTarget($label, $body->reason ?? 'cannot build a request body', 'set probes.payloads.fields'));

            return null;
        }

        // Both fingerprints come from the database row: a record fresh from a factory lacks the
        // columns it did not set, which would look like a change.
        $before = $this->fingerprint($recordB->refresh());
        $response = $context->client()->request($method, $attack, $body->body, user: $actor, verifyCsrf: false);

        if ($response->isCsrfRejection()) {
            $context->coverage()->skipped(new CoverageTarget($label, 'blocked by the CSRF check', 'the route sits behind a CSRF middleware the probe does not recognize'));

            return null;
        }

        $recordB->refresh();

        if ($this->fingerprint($recordB) === $before) {
            $context->coverage()->checked(new CoverageTarget($label, sprintf('answered %d and B did not change', $response->status)));

            return null;
        }

        $context->coverage()->confirmed();

        return $this->confirmed($suspicion, $route, $data, $recordB, null, $attack, sprintf(
            'user A changed %s#%s owned by B through %s (HTTP %d)%s',
            class_basename($recordB),
            $this->keyOf($recordB),
            $method,
            $response->status,
            $body->source === 'runtime' ? ", with a request body inferred from the application's validation errors" : '',
        ));
    }

    private function fingerprint(Model $record): string
    {
        $attributes = $record->getAttributes();
        ksort($attributes);

        return (string) json_encode($attributes);
    }

    private function confirmed(?Finding $suspicion, RouteInfo $route, ProbeData $data, Model $record, ?string $value, string $uri, string $evidence): Finding
    {
        $base = $suspicion ?? new Finding(
            $this->id(),
            Severity::Medium,
            sprintf('%s /%s returns another owner\'s %s', implode('|', $route->methods), $route->uri, class_basename($record)),
            sprintf('The route %s /%s lets a signed-in user reach a %s that belongs to someone else by changing the id, while the policy does not allow it.', implode('|', $route->methods), $route->uri, class_basename($record)),
            'Authorize the action against the loaded record (a policy or a scoped query), not just the model class.',
            [
                'https://laravel.com/docs/authorization#authorizing-actions-using-policies',
                'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            ],
            $route->file === null ? null : new Location($route->file, $route->line),
            cwe: [639],
        );

        return $base->withConfirmation($this->reproduction($data, $route, $record, $value, $uri), $evidence);
    }

    private function reproduction(ProbeData $data, RouteInfo $route, Model $record, ?string $value, string $uri): Reproduction
    {
        $group = $data->a->group;

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
                strtoupper($route->methods[0]).' '.$uri,
                sprintf('%s#%s (owned by B)', $record::class, $this->keyOf($record)),
                [],
                '403 or 404',
                $value === null
                    ? sprintf('%s#%s deleted', class_basename($record), $this->keyOf($record))
                    : sprintf('%s returned', $value),
            )],
        );
    }

    /**
     * Builds the request URI: A's records (walked from recordA) for the parent parameters and the
     * chosen record for the last (child) one. Null when the route's parameters do not follow the
     * owner chain of the child model.
     */
    private function uri(RouteInfo $route, OwnershipResolver $ownership, Model $parentSource, Model $child, ?Model $parent = null): ?string
    {
        $params = $route->models;
        $count = count($params);

        if ($count === 0) {
            return null;
        }

        if ($parent !== null && $count === 2) {
            return $this->fill($route, [$this->segment($params[0], $parent), $this->segment($params[1], $child)]);
        }

        $owner = $ownership->for($params[$count - 1]->model)->owner;
        $segments = [];
        $node = $parentSource;

        for ($i = 0; $i < $count - 1; $i++) {
            $relation = $owner?->relations[$i] ?? null;

            if ($relation === null) {
                return null;
            }

            $parent = $node->getRelationValue($relation);

            if (! $parent instanceof Model || ! is_a($parent, $params[$i]->model, true)) {
                return null;
            }

            $segments[] = $this->segment($params[$i], $parent);
            $node = $parent;
        }

        $segments[] = $this->segment($params[$count - 1], $child);

        return $this->fill($route, $segments);
    }

    /**
     * @param  list<string>  $segments
     */
    private function fill(RouteInfo $route, array $segments): string
    {
        $replaced = preg_replace_callback(
            '/\{([^}?]+)\??\}/',
            function () use (&$segments): string {
                return (string) array_shift($segments);
            },
            $route->uri,
        );

        return '/'.ltrim($replaced ?? $route->uri, '/');
    }

    private function segment(RouteParameter $parameter, Model $record): string
    {
        $key = $parameter->field === null ? $record->getRouteKey() : $record->getAttribute($parameter->field);

        return is_int($key) || is_string($key) ? (string) $key : $this->keyOf($record);
    }

    private function distinguishingValue(Model $recordB, Model $recordA, string $baseline): ?string
    {
        foreach ($recordB->getAttributes() as $key => $value) {
            if (! is_string($value) || mb_strlen($value) < self::MIN_VALUE_LENGTH) {
                continue;
            }

            if ($this->contains($baseline, $value)) {
                continue;
            }

            $other = $recordA->getAttribute($key);

            if (is_string($other) && $other === $value) {
                continue;
            }

            return $value;
        }

        return null;
    }

    private function contains(string $body, string $value): bool
    {
        if (str_contains($body, $value)) {
            return true;
        }

        $escaped = htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        if ($escaped !== $value && str_contains($body, $escaped)) {
            return true;
        }

        $json = json_encode($value);

        if (is_string($json)) {
            $inner = trim($json, '"');

            if ($inner !== $value && str_contains($body, $inner)) {
                return true;
            }
        }

        return false;
    }

    private function authenticated(RouteInfo $route): bool
    {
        return $route->usesMiddleware(Authenticate::class, AuthenticateWithBasicAuth::class);
    }

    /**
     * @param  list<string>  $methods
     */
    private function method(array $methods): ?string
    {
        foreach (['GET', 'DELETE', 'PUT', 'PATCH'] as $method) {
            if (in_array($method, $methods, true)) {
                return $method;
            }
        }

        return null;
    }

    private function label(RouteInfo $route): string
    {
        return $this->key($route);
    }

    private function key(RouteInfo $route): string
    {
        return implode('|', $route->methods).' '.$route->uri;
    }

    private function keyOf(Model $record): string
    {
        $key = $record->getKey();

        return is_int($key) || is_string($key) ? (string) $key : '?';
    }
}
