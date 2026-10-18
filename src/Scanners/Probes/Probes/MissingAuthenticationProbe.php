<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Probes;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelection;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTarget;

/**
 * Confirms routes.missing-authentication: a guest sends the write request to a route that changes an
 * existing record without login, and the finding is confirmed only when the record really changed.
 * This part only sends DELETE; a route that needs a body is reported in the coverage and its
 * suspicion stays suspected.
 */
final class MissingAuthenticationProbe implements Probe
{
    public function id(): string
    {
        return 'probes.missing-authentication';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(ProbeContext $context): iterable
    {
        foreach ($context->targets()->forRule('routes.missing-authentication') as $target) {
            $finding = $this->check($context, $target);

            if ($finding !== null) {
                yield $finding;
            }
        }
    }

    private function check(ProbeContext $context, ProbeTarget $target): ?Finding
    {
        $route = $target->route;
        $method = $this->method($route->methods);

        if ($method === null) {
            return null;
        }

        if ($method !== 'DELETE') {
            $context->coverage()->skipped(new CoverageTarget($target->label(), 'needs a request body (not supported yet)'));

            return null;
        }

        if (count($route->models) !== 1) {
            $context->coverage()->skipped(new CoverageTarget($target->label(), 'needs records for every URL parameter'));

            return null;
        }

        $model = $route->models[0]->model;
        $selection = $this->select($context, $model, $target->label());

        if ($selection === null || $selection->data === null) {
            return null;
        }

        $data = $selection->data;
        $record = $data->recordA;

        if ($record === null) {
            return null;
        }

        if ($this->policyAllowsGuests($context, $model, $record)) {
            $context->coverage()->skipped(new CoverageTarget($target->label(), 'policy allows guests'));

            return null;
        }

        $uri = $this->uri($route->uri, $record);
        $response = $context->client()->request($method, $uri);
        $deleted = ! $model::query()->whereKey($record->getKey())->exists();

        if (! $deleted) {
            $context->coverage()->checked(new CoverageTarget($target->label(), sprintf('answered %d', $response->status)));

            return null;
        }

        $context->coverage()->confirmed();

        return $target->suspicion->withConfirmation(
            $this->reproduction($data->mode, $model, $record, $method, $uri, $response->status),
            sprintf('the guest %s removed %s#%s (HTTP %d)', $method, class_basename($model), $this->keyOf($record), $response->status),
        );
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function select(ProbeContext $context, string $model, string $label): ?DataSelection
    {
        $ownership = $context->ownership();
        $selector = $context->data();

        if ($ownership === null || $selector === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

            return null;
        }

        $owner = $ownership->for($model)->owner;

        if ($owner === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'no owner for '.class_basename($model), 'set probes.owners'));

            return null;
        }

        $selection = $selector->for($model, $owner);

        if (! $selection->isFound()) {
            $context->coverage()->skipped(new CoverageTarget($label, $selection->reason ?? 'no data', $selection->hint));
        }

        return $selection;
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function policyAllowsGuests(ProbeContext $context, string $model, Model $record): bool
    {
        $policy = $context->map()->policyFor($model);

        if ($policy === null || ! method_exists($policy, 'delete')) {
            return false;
        }

        return Gate::forUser(null)->allows('delete', $record);
    }

    /**
     * @param  list<string>  $methods
     */
    private function method(array $methods): ?string
    {
        foreach (['DELETE', 'PUT', 'PATCH', 'POST'] as $method) {
            if (in_array($method, $methods, true)) {
                return $method;
            }
        }

        return null;
    }

    private function uri(string $uri, Model $record): string
    {
        return (string) preg_replace_callback(
            '/\{([^}?]+)\??\}/',
            fn (): string => $this->routeKey($record),
            '/'.ltrim($uri, '/'),
        );
    }

    private function routeKey(Model $record): string
    {
        $key = $record->getRouteKey();

        return is_int($key) || is_string($key) ? (string) $key : $this->keyOf($record);
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function reproduction(string $mode, string $model, Model $record, string $method, string $uri, int $status): Reproduction
    {
        return new Reproduction(
            $this->id(),
            $mode,
            [['name' => 'guest', 'model' => null, 'id' => null, 'owner' => null]],
            [new ReproductionStep(
                'guest',
                $method.' '.$uri,
                sprintf('%s#%s', $model, $this->keyOf($record)),
                [],
                '401 or 403',
                sprintf('%d (%s #%s deleted)', $status, class_basename($model), $this->keyOf($record)),
            )],
        );
    }

    private function keyOf(Model $record): string
    {
        $key = $record->getKey();

        return is_int($key) || is_string($key) ? (string) $key : '?';
    }
}
