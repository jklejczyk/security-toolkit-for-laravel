<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Probes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\ProbeData;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Routes\CsrfExclusions;

/**
 * Confirms a CSRF hole: a write route that a session user reaches without a token really performs the
 * write. Targets are write routes behind a session guard that either match a CSRF exclusion or lost
 * the CSRF middleware. With SameSite=lax or strict the browser would not send the cookie with a
 * cross-site request, so the probe only reports at none/null and otherwise leaves a coverage note.
 */
final class CsrfProbe implements Probe
{
    public function __construct(
        private readonly CsrfExclusions $csrf = new CsrfExclusions,
    ) {}

    public function id(): string
    {
        return 'probes.csrf';
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
     * Write routes behind a session guard that are not protected by the CSRF check: they match an
     * exclusion, or the CSRF middleware was removed from the route.
     *
     * @return list<RouteInfo>
     */
    private function candidates(ProbeContext $context): array
    {
        $routes = [];

        foreach ($context->map()->routes() as $route) {
            if (! $route->isWrite() || $route->models === [] || ! $this->csrf->usesSession($route)) {
                continue;
            }

            if ($this->csrf->usesMiddleware($route) && $this->csrf->matching($route) === []) {
                continue;
            }

            $routes[] = $route;
        }

        return $routes;
    }

    private function check(ProbeContext $context, RouteInfo $route): ?Finding
    {
        $label = $this->label($route);
        $method = $this->method($route->methods);

        if ($method === null) {
            return null;
        }

        if (count($route->models) !== 1) {
            $context->coverage()->skipped(new CoverageTarget($label, 'needs records for every URL parameter'));

            return null;
        }

        $sameSite = config('session.same_site');
        $sameSite = is_string($sameSite) ? strtolower($sameSite) : null;

        if ($sameSite !== null && in_array($sameSite, ['lax', 'strict'], true)) {
            $context->coverage()->checked(new CoverageTarget(
                $label,
                sprintf('accepts writes without a CSRF token; SameSite=%s blocks cross-site requests here, check production with --env=production', $sameSite),
            ));

            return null;
        }

        $ownership = $context->ownership();
        $selector = $context->data();

        if ($ownership === null || $selector === null) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

            return null;
        }

        $child = $route->models[0]->model;
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
        $record = $data->recordA;
        $actor = $data->a->user;

        if ($record === null) {
            return null;
        }

        if (! $actor instanceof Authenticatable) {
            $context->coverage()->skipped(new CoverageTarget($label, 'the user model is not an Authenticatable'));

            return null;
        }

        $uri = $this->uri($route, $record);
        $body = [];

        if ($method !== 'DELETE') {
            $payload = $context->payload();

            if ($payload === null) {
                $context->coverage()->skipped(new CoverageTarget($label, 'the user model could not be resolved'));

                return null;
            }

            $built = $payload->build($route, $owner, $data->a, $child);

            if (! $built->isBuilt() || $built->body === null) {
                $context->coverage()->skipped(new CoverageTarget($label, $built->reason ?? 'cannot build a request body', 'set probes.payloads.fields'));

                return null;
            }

            $body = $built->body;
        }

        [$changed, $status] = $this->sendsEffect($context, $method, $uri, $body, $actor, $record);

        if (! $changed) {
            $context->coverage()->checked(new CoverageTarget($label, sprintf('answered %d and no data changed', $status)));

            return null;
        }

        $context->coverage()->confirmed();

        return $this->finding($context, $route, $data, $record, $uri, $status, $method);
    }

    /**
     * Sends the request and reports whether it really changed data. For DELETE the record must be
     * gone; for other writes the record must change, read back with refresh().
     *
     * @param  array<array-key, mixed>  $body
     * @return array{0: bool, 1: int}
     */
    private function sendsEffect(ProbeContext $context, string $method, string $uri, array $body, Authenticatable $actor, Model $record): array
    {
        $before = $this->fingerprint($record);
        $response = $context->client()->request($method, $uri, $body, user: $actor);

        if ($method === 'DELETE') {
            return [! $record::query()->whereKey($record->getKey())->exists(), $response->status];
        }

        $record->refresh();

        return [$this->fingerprint($record) !== $before, $response->status];
    }

    private function fingerprint(Model $record): string
    {
        $attributes = $record->getAttributes();
        ksort($attributes);

        return (string) json_encode($attributes);
    }

    private function finding(ProbeContext $context, RouteInfo $route, ProbeData $data, Model $record, string $uri, int $status, string $method): Finding
    {
        $matches = $this->csrf->matching($route);

        if ($matches !== []) {
            $pattern = $matches[0]['pattern'];

            $base = new Finding(
                'routes.csrf-excluded',
                Severity::Medium,
                sprintf('"%s" is excluded from CSRF protection for logged-in routes', $pattern),
                sprintf('A signed-in user reached %s /%s and it changed data without a CSRF token, and the URI pattern "%s" is excluded from the check, so another site could submit this request in their name.', implode('|', $route->methods), $route->uri, $pattern),
                'Remove the pattern from the CSRF exclusions and send the token with the request, or set session.same_site to "lax".',
                [
                    'https://laravel.com/docs/csrf#csrf-excluding-uris',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
                ],
                $this->csrf->location($pattern, $matches[0]['source'], $context->scanContext()->basePath),
                cwe: [352],
            );
        } else {
            $base = new Finding(
                'probes.csrf-unprotected',
                Severity::Medium,
                sprintf('%s /%s changes data without a CSRF token', implode('|', $route->methods), $route->uri),
                sprintf('The route %s /%s is behind a session guard but has no CSRF middleware, so a signed-in user reached it and it changed data without a token.', implode('|', $route->methods), $route->uri),
                'Keep the ValidateCsrfToken middleware on the route and send the token (the @csrf directive or the X-XSRF-TOKEN header).',
                ['https://laravel.com/docs/csrf'],
                $route->file === null ? null : new Location($route->file, $route->line),
                cwe: [352],
            );
        }

        return $base->withConfirmation(
            $this->reproduction($data, $record, $uri, $status, $method),
            sprintf('user A reached %s#%s without a CSRF token (HTTP %d)', class_basename($record), $this->keyOf($record), $status),
        );
    }

    private function reproduction(ProbeData $data, Model $record, string $uri, int $status, string $method): Reproduction
    {
        $group = $data->a->group;
        $changed = $method === 'DELETE' ? 'deleted' : 'changed';

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
                $method.' '.$uri,
                sprintf('%s#%s', $record::class, $this->keyOf($record)),
                [],
                '419 (token mismatch)',
                sprintf('%s#%s %s without a token', class_basename($record), $this->keyOf($record), $changed),
            )],
        );
    }

    private function uri(RouteInfo $route, Model $record): string
    {
        $parameter = $route->models[0];
        $key = $parameter->field === null ? $record->getRouteKey() : $record->getAttribute($parameter->field);
        $segment = is_int($key) || is_string($key) ? (string) $key : $this->keyOf($record);

        $replaced = preg_replace('/\{[^}?]+\??\}/', $segment, $route->uri, 1);

        return '/'.ltrim($replaced ?? $route->uri, '/');
    }

    private function label(RouteInfo $route): string
    {
        return implode('|', $route->methods).' /'.$route->uri;
    }

    /**
     * @param  list<string>  $methods
     */
    private function method(array $methods): ?string
    {
        foreach (['DELETE', 'POST', 'PUT', 'PATCH'] as $method) {
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
