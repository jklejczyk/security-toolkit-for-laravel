<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Probes;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\AuthenticateWithBasicAuth;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\ProbeData;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\StaticModels;
use Throwable;

/**
 * Confirms a mass-assignment hole on a write route: user A fills a request body the action accepts,
 * plus one privileged or tenant column that the validation rules do not mention, and the column really
 * changes. The effect on the record (not the status code) is the proof, read back with refresh() so a
 * validated-but-discarded column never counts.
 */
final class MassAssignmentProbe implements Probe
{
    /**
     * Columns that escalate privileges when an attacker can set them.
     */
    private const PRIVILEGED = [
        'is_admin', 'admin', 'role', 'role_id', 'status', 'plan', 'balance', 'credits', 'verified', 'email_verified_at',
    ];

    /**
     * Columns that move a record out of its tenant or owner.
     */
    private const TENANT = [
        'user_id', 'owner_id', 'author_id', 'created_by', 'team_id', 'company_id', 'organization_id', 'tenant_id', 'account_id', 'workspace_id',
    ];

    public function __construct(
        private readonly StaticModels $static = new StaticModels,
    ) {}

    public function id(): string
    {
        return 'probes.mass-assignment';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(ProbeContext $context): iterable
    {
        foreach ($this->candidates($context) as $route) {
            $finding = $this->check($context, $route);

            if ($finding !== null) {
                yield $finding;
            }
        }
    }

    /**
     * Authenticated POST/PUT/PATCH routes with a model parameter.
     *
     * @return list<RouteInfo>
     */
    private function candidates(ProbeContext $context): array
    {
        $routes = [];
        $seen = [];

        foreach ($context->map()->routes() as $route) {
            if (! $this->isWrite($route) || $route->models === [] || ! $this->authenticated($route)) {
                continue;
            }

            $key = implode('|', $route->methods).' /'.$route->uri;

            if (! isset($seen[$key])) {
                $seen[$key] = true;
                $routes[] = $route;
            }
        }

        return $routes;
    }

    private function check(ProbeContext $context, RouteInfo $route): ?Finding
    {
        $method = $this->method($route->methods);

        if ($method === null) {
            return null;
        }

        $label = implode('|', $route->methods).' /'.$route->uri;
        $model = $route->models[count($route->models) - 1]->model;

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

        if (! $selection->isFound() || $selection->data === null) {
            $context->coverage()->skipped(new CoverageTarget($label, $selection->reason ?? 'no data', $selection->hint));

            return null;
        }

        $data = $selection->data;
        $actor = $data->a->user;

        if (! $actor instanceof Authenticatable) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model is not an Authenticatable'));

            return null;
        }

        $record = $data->recordA;

        if ($record === null) {
            return null;
        }

        $payload = $context->payload();

        if ($payload === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

            return null;
        }

        $body = $payload->build($route, $owner, $data->a, $model);

        if (! $body->isBuilt() || $body->body === null) {
            $context->coverage()->skipped(new CoverageTarget($label, $body->reason ?? 'cannot build a request body', 'set probes.payloads.fields'));

            return null;
        }

        $attack = $this->attackFields($context, $model, array_keys($body->body));

        foreach ($this->attackNames(array_keys($attack)) as $field) {
            $value = $this->attackValue($attack[$field], $data, $record, $field);

            if ($value === null) {
                continue;
            }

            if ($this->changesRecord($context, $route, $method, $body->body, $field, $value, $record, $actor)) {
                $context->coverage()->confirmed();

                return $this->finding($context, $route, $model, $data, $record, $method, $field, $attack[$field], $body->body);
            }
        }

        $context->coverage()->checked(new CoverageTarget($label, 'no attack field changed the record'));

        return null;
    }

    /**
     * Sends the valid body plus one attack field and reports whether the column really changed.
     *
     * @param  array<array-key, mixed>  $body
     */
    private function changesRecord(ProbeContext $context, RouteInfo $route, string $method, array $body, string $field, mixed $value, Model $record, Authenticatable $actor): bool
    {
        $uri = $this->uri($route, $record);
        $before = $this->attribute($record, $field);

        try {
            $response = $context->client()->request($method, $uri, array_merge($body, [$field => $value]), $actor);
        } catch (Throwable) {
            return false;
        }

        if ($response->isDenied()) {
            return false;
        }

        $record->refresh();

        return $this->attribute($record, $field) !== $before && $this->equals($this->attribute($record, $field), $value);
    }

    /**
     * @param  class-string<Model>  $model
     * @param  array<array-key, mixed>  $body
     */
    private function finding(ProbeContext $context, RouteInfo $route, string $model, ProbeData $data, Model $record, string $method, string $field, bool $tenant, array $body): Finding
    {
        $static = $this->staticFinding($context, $model);

        if ($static !== null) {
            return $static->withConfirmation(
                $this->reproduction($data, $record, $method, $route, $field),
                sprintf('user A set %s on %s#%s', $field, class_basename($record), $this->keyOf($record)),
            );
        }

        $escalate = $tenant || in_array($field, self::PRIVILEGED, true);

        return new Finding(
            $this->id(),
            $escalate ? Severity::High : Severity::Medium,
            sprintf('%s /%s accepts mass assignment of %s', implode('|', $route->methods), $route->uri, $field),
            sprintf('The route %s /%s lets a signed-in user set %s on %s by adding it to the request, even though the validation rules do not mention it, and the column really changed.', implode('|', $route->methods), $route->uri, $field, class_basename($record)),
            'Fill the model through $fillable and pass $request->validated() (or $request->only(...)) to update(), so columns outside the rules never reach the model.',
            [
                'https://laravel.com/docs/eloquent#mass-assignment',
                'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
            ],
            $route->file === null ? null : new Location($route->file, $route->line),
            cwe: [915],
            confidence: Confidence::Confirmed,
            reproduction: $this->reproduction($data, $record, $method, $route, $field),
        );
    }

    private function reproduction(ProbeData $data, Model $record, string $method, RouteInfo $route, string $field): Reproduction
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
                $method.' '.$this->uri($route, $record),
                sprintf('%s#%s', $record::class, $this->keyOf($record)),
                [$field],
                'field rejected (validation or model guard)',
                sprintf('%s changed to the injected value', $field),
            )],
        );
    }

    /**
     * The static mass-assignment finding the probe proved, if any: models.unguarded globally, or the
     * models.guarded-empty finding for this model.
     *
     * @param  class-string<Model>  $model
     */
    private function staticFinding(ProbeContext $context, string $model): ?Finding
    {
        return $this->static->unguarded($context->scanContext())
            ?? $this->static->guardedEmpty($context->scanContext(), $model);
    }

    /**
     * The attack fields for the model: its columns crossed with the privileged/tenant names and the
     * configured attack fields, minus the fields the valid body already contains.
     *
     * @param  class-string<Model>  $model
     * @param  list<int|string>  $present
     * @return array<string, bool> column => isTenant
     */
    private function attackFields(ProbeContext $context, string $model, array $present): array
    {
        $configured = $context->config()->payloads['attack_fields'] ?? [];

        $names = array_values(array_unique(array_merge(
            self::PRIVILEGED,
            self::TENANT,
            is_array($configured) ? array_values(array_filter($configured, is_string(...))) : [],
        )));

        $columns = $this->columns($model);

        $fields = [];

        foreach ($names as $name) {
            if (in_array($name, $present, true)) {
                continue;
            }

            if ($columns !== null && ! in_array($name, $columns, true)) {
                continue;
            }

            $fields[$name] = in_array($name, self::TENANT, true);
        }

        return $fields;
    }

    /**
     * @param  list<string>  $names
     * @return list<string>
     */
    private function attackNames(array $names): array
    {
        return array_slice($names, 0, 5);
    }

    /**
     * @param  class-string<Model>  $model
     * @return list<string>|null
     */
    private function columns(string $model): ?array
    {
        try {
            $table = (new $model)->getTable();
            $columns = Schema::getColumnListing($table);

            return array_values(array_filter($columns, is_string(...)));
        } catch (Throwable) {
            return null;
        }
    }

    private function attackValue(bool $tenant, ProbeData $data, Model $record, string $field): mixed
    {
        if ($tenant) {
            $targetId = $data->b->ownerId();

            if (is_int($targetId) || is_string($targetId)) {
                return $targetId;
            }

            return null;
        }

        if ($this->isFlag($record, $field)) {
            return true;
        }

        return in_array($field, self::PRIVILEGED, true) ? 'adminset' : 'probeset';
    }

    private function isFlag(Model $record, string $field): bool
    {
        $value = $this->attribute($record, $field);

        return is_bool($value) || $value === 0 || $value === 1 || $value === '0' || $value === '1' || $value === null;
    }

    private function attribute(Model $record, string $field): mixed
    {
        return $record->getAttribute($field);
    }

    private function equals(mixed $after, mixed $value): bool
    {
        if ($after === $value) {
            return true;
        }

        // A boolean column stored as 0/1.
        if (is_bool($value) && ($after === (int) $value || $after === (string) $value || (is_string($after) && in_array($after, ['1', '0'], true)))) {
            return true;
        }

        return false;
    }

    private function uri(RouteInfo $route, Model $record): string
    {
        $parameter = $route->models[count($route->models) - 1];
        $key = $parameter->field === null ? $record->getRouteKey() : $record->getAttribute($parameter->field);
        $segment = is_int($key) || is_string($key) ? (string) $key : $this->keyOf($record);

        $replaced = preg_replace('/\{[^}?]+\??\}/', $segment, $route->uri, 1);

        return '/'.ltrim($replaced ?? $route->uri, '/');
    }

    private function isWrite(RouteInfo $route): bool
    {
        return $route->isWrite() && ! in_array('DELETE', $route->methods, true);
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
        foreach (['PUT', 'PATCH', 'POST'] as $method) {
            if (in_array($method, $methods, true)) {
                return $method;
            }
        }

        return null;
    }

    private function keyOf(Model $record): string
    {
        $key = $record->getKey();

        return is_int($key) || is_string($key) ? (string) $key : '?';
    }
}
