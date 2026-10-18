<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Payload;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Validation\Rule as ValidationRule;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Routing\Redirector;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Enum as EnumRule;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\Actor;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\Owner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionProperty;
use Throwable;

/**
 * Builds a request body a route action will accept, from the validation rules of the FormRequest the
 * action receives. Every value is deterministic and satisfies its rule; ``exists`` and foreign keys
 * resolve to records owned by actor A through the owner resolver, so the body describes a legitimate
 * request, never a guessed one. A body that does not pass the rules is never returned: the probe must
 * not mistake a 422 validation refusal for a security refusal.
 */
final class PayloadBuilder
{
    private const PLACEHOLDER = 'probe';

    public function __construct(
        private readonly Container $container,
        private readonly ApplicationMap $map,
        private readonly OwnershipResolver $ownership,
        private readonly ProbesConfig $config,
    ) {}

    /**
     * @param  class-string<Model>  $model  the model of the last URL parameter
     */
    public function build(RouteInfo $route, Owner $owner, Actor $actor, string $model): PayloadResult
    {
        if ($route->controller === null || $route->action === null) {
            return PayloadResult::skipped('no controller action to read rules from');
        }

        $formRequest = $this->formRequest($route);

        if ($formRequest === null) {
            return PayloadResult::skipped('no FormRequest; cannot build a request body, set probes.payloads.fields');
        }

        if (! method_exists($formRequest, 'rules')) {
            return PayloadResult::skipped('the FormRequest has no rules');
        }

        try {
            $rules = $formRequest->{'rules'}();
        } catch (Throwable $exception) {
            return PayloadResult::skipped('the FormRequest rules() threw: '.$exception->getMessage());
        }

        if (! is_array($rules) || $rules === []) {
            return PayloadResult::skipped('the FormRequest has no rules');
        }

        $body = [];
        $failed = null;

        foreach ($rules as $field => $fieldRules) {
            if ($this->ignored((string) $field)) {
                continue;
            }

            $value = $this->value($this->normalise($fieldRules), $owner, $actor, $model);

            if ($value === null) {
                if ($this->required($fieldRules)) {
                    $failed = sprintf('cannot satisfy %s (%s)', $field, $this->describe($fieldRules));

                    break;
                }

                continue;
            }

            $this->assign($body, (string) $field, $value);
        }

        if ($failed !== null || $body === []) {
            return PayloadResult::skipped($failed ?? 'no fillable rules');
        }

        $error = $this->verify($body, $rules);

        if ($error !== null) {
            return PayloadResult::skipped($error);
        }

        return PayloadResult::built($body);
    }

    /**
     * The FormRequest parameter of the action, resolved through the container the way the framework
     * prepares it before validate(). Null when the action has none.
     */
    private function formRequest(RouteInfo $route): ?FormRequest
    {
        try {
            $parameters = (new ReflectionMethod((string) $route->controller, (string) $route->action))->getParameters();
        } catch (Throwable) {
            return null;
        }

        foreach ($parameters as $parameter) {
            $type = $parameter->getType();

            if ($type instanceof ReflectionNamedType && ! $type->isBuiltin() && is_subclass_of($type->getName(), FormRequest::class)) {
                return $this->instantiate($type->getName());
            }
        }

        return null;
    }

    /**
     * Builds the FormRequest without the framework's automatic validation, so its rules() can be read
     * before any body is ready. The container, route and redirector are attached as the framework does
     * before validate(), so rules that read $this->route() or $this->user() mostly work; anything else
     * throws and is reported as a reason, never a finding.
     */
    /**
     * @param  class-string<FormRequest>  $class
     */
    private function instantiate(string $class): ?FormRequest
    {
        try {
            // Built by hand, not through the container: resolving a FormRequest triggers the
            // ValidatesWhenResolved callback that validates it before there is any body to validate.
            $formRequest = new $class;

            $formRequest->setContainer($this->container)->setRedirector($this->container->make(Redirector::class));
        } catch (Throwable) {
            return null;
        }

        return $formRequest;
    }

    /**
     * The value for one field per its rules, or null when it cannot be built.
     *
     * @param  list<mixed>  $rules
     * @param  class-string<Model>  $model
     */
    private function value(array $rules, Owner $owner, Actor $actor, string $model): mixed
    {
        foreach ($rules as $rule) {
            if ($rule instanceof EnumRule) {
                return $this->enumValue($rule);
            }

            if ($rule instanceof ValidationRule) {
                continue;
            }

            if (is_string($rule)) {
                $value = $this->stringRule($rule, $owner, $actor, $model);

                if ($value !== null) {
                    return $value;
                }
            }
        }

        // Only shape rules (string, array, etc.): fall back to a placeholder string.
        return $this->stringRules($rules);
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function stringRule(string $rule, Owner $owner, Actor $actor, string $model): mixed
    {
        $name = explode(':', $rule, 2)[0];
        $parameters = count(explode(':', $rule, 2)) > 1 ? explode(',', explode(':', $rule, 2)[1]) : [];

        return match ($name) {
            'email' => 'probe@example.test',
            'url' => 'https://example.test',
            'uuid' => '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
            'ulid' => '01ARZ3NDEKTSV4RRFFQ69G5FAV',
            'ip', 'ipv4' => '127.0.0.1',
            'ipv6' => '::1',
            'date' => '2026-01-01',
            'date_format' => $this->dateFormat($parameters),
            'timezone' => 'UTC',
            'boolean' => true,
            'integer' => 1,
            'numeric' => 1,
            'json' => '{}',
            'array' => ['probe'],
            'in' => isset($parameters[0]) && $parameters[0] !== '' ? $parameters[0] : null,
            'not_in', 'different', 'prohibited' => null,
            'in_array' => isset($parameters[0]) && $parameters[0] !== '' ? $parameters[0] : null,
            'confirmed', 'same' => null,
            'string', 'required', 'nullable', 'sometimes', 'alpha', 'alpha_num', 'alpha_dash', 'accepted',
            'active_url', 'after', 'after_or_equal', 'before', 'before_or_equal', 'regex', 'starts_with',
            'ends_with', 'present', 'filled' => $this->placeholder(),
            'exists' => $this->exists($parameters, $owner, $actor),
            'min', 'max', 'between', 'size', 'gt', 'gte', 'lt', 'lte', 'digits', 'digits_between' => $this->length($name, $parameters),
            default => $this->foreignKey($name, $owner, $actor, $model),
        };
    }

    /**
     * @param  list<string>  $parameters
     */
    private function exists(array $parameters, Owner $owner, Actor $actor): int|string|null
    {
        $table = $parameters[0] ?? null;

        if (! is_string($table)) {
            return null;
        }

        $record = $this->recordForTable($table, $owner, $actor);

        if ($record === null) {
            return null;
        }

        $column = $parameters[1] ?? $record->getKeyName();
        $value = $column === $record->getKeyName() ? $record->getKey() : $record->getAttribute($column);

        return is_int($value) || is_string($value) ? $value : null;
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function foreignKey(string $column, Owner $owner, Actor $actor, string $model): mixed
    {
        if (! str_ends_with($column, '_id')) {
            return null;
        }

        // A column that names the owner directly (company_id → A's group, user_id → A).
        if (in_array($column, $owner->foreignKeys, true)) {
            return $actor->ownerId();
        }

        // A relation from the model that reaches the user or the actor's group.
        $related = $this->relatedFor($model, $column);

        if ($related !== null) {
            $node = $this->nodeFor($related, $actor);

            if ($node !== null) {
                $value = $node->getKey();

                if (is_int($value) || is_string($value)) {
                    return $value;
                }
            }
        }

        return null;
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function relatedFor(string $model, string $column): ?string
    {
        foreach ($this->map->belongsTo($model) as $relation) {
            if ($relation->foreignKey === $column) {
                return $relation->related;
            }
        }

        return null;
    }

    private function nodeFor(string $related, Actor $actor): ?Model
    {
        $userModel = $this->ownership->userModel();

        if ($related === $userModel || is_a($userModel, $related, true) || is_a($related, $userModel, true)) {
            return $actor->user;
        }

        $group = $actor->group;

        if ($group !== null && (is_a($group, $related))) {
            return $group;
        }

        return null;
    }

    /**
     * Resolves an ``exists:table,column`` to a record actor A owns, when the table names a model the
     * actor or the owner chain can reach. Otherwise leaves the field unresolved.
     */
    private function recordForTable(string $table, Owner $owner, Actor $actor): ?Model
    {
        $userModel = $this->ownership->userModel();

        if ($table === (new $userModel)->getTable()) {
            return $actor->user;
        }

        if ($actor->group !== null && $table === (new ($actor->group::class))->getTable()) {
            return $actor->group;
        }

        return null;
    }

    /**
     * @param  list<string>  $parameters
     */
    /**
     * @param  list<string>  $parameters
     */
    private function length(string $rule, array $parameters): mixed
    {
        if (in_array($rule, ['min', 'gte', 'size'], true)) {
            $min = max(1, (int) ($parameters[0] ?? 1));

            return str_pad('', $min, 'x');
        }

        if ($rule === 'max' || $rule === 'lte') {
            $max = max(1, (int) ($parameters[0] ?? 10));

            return str_pad('', min($max, 5), 'x');
        }

        if (in_array($rule, ['between', 'digits_between'], true)) {
            $min = max(1, (int) ($parameters[0] ?? 1));

            return str_pad('', $min, 'x');
        }

        if ($rule === 'digits') {
            return str_pad('', max(1, (int) ($parameters[0] ?? 5)), '1');
        }

        if (in_array($rule, ['gt', 'lt'], true)) {
            return str_pad('', (int) ($parameters[0] ?? 1) + 1, 'x');
        }

        return $this->placeholder();
    }

    /**
     * @param  list<string>  $parameters
     */
    /**
     * @param  list<string>  $parameters
     */
    private function dateFormat(array $parameters): string
    {
        return '2026-01-01';
    }

    private function enumValue(EnumRule $rule): mixed
    {
        try {
            $property = new ReflectionProperty(EnumRule::class, 'type');
            $type = $property->getValue($rule);

            if (is_string($type) && enum_exists($type)) {
                $case = $type::cases()[0] ?? null;

                return $case instanceof \BackedEnum ? $case->value : null;
            }
        } catch (Throwable) {
            return null;
        }

        return null;
    }

    /**
     * @param  array<array-key, mixed>  $body
     */
    private function assign(array &$body, string $field, mixed $value): void
    {
        $nested = $this->nest(explode('.', $field), $value);

        $body = $this->merge($body, is_array($nested) ? $nested : ['value' => $nested]);
    }

    /**
     * @param  list<string>  $pieces
     * @return array<array-key, mixed>|mixed
     */
    private function nest(array $pieces, mixed $value): mixed
    {
        $piece = array_shift($pieces);

        if ($piece === null || $piece === '') {
            return $value;
        }

        if ($piece === '*') {
            return [0 => $this->nest($pieces, $value)];
        }

        return [$piece => $this->nest($pieces, $value)];
    }

    /**
     * @param  array<array-key, mixed>  $base
     * @param  array<array-key, mixed>  $overlay
     * @return array<array-key, mixed>
     */
    private function merge(array $base, array $overlay): array
    {
        foreach ($overlay as $key => $value) {
            if (is_array($value) && isset($base[$key]) && is_array($base[$key])) {
                $value = $this->merge($base[$key], $value);
            }

            $base[$key] = $value;
        }

        return $base;
    }

    /**
     * @param  array<array-key, mixed>  $body
     * @param  array<array-key, mixed>  $rules
     */
    private function verify(array $body, array $rules): ?string
    {
        $validator = Validator::make($body, $this->stripObjects($rules));

        return $validator->passes() ? null : 'cannot build a request body: '.implode('; ', (array) $validator->errors()->all());
    }

    /**
     * @param  array<array-key, mixed>  $rules
     * @return array<array-key, mixed>
     */
    private function stripObjects(array $rules): array
    {
        $stripped = [];

        foreach ($rules as $field => $fieldRules) {
            foreach (is_array($fieldRules) ? $fieldRules : [$fieldRules] as $rule) {
                if (! is_object($rule)) {
                    $stripped[$field][] = $rule;
                }
            }
        }

        return $stripped;
    }

    /**
     * @return list<mixed>
     */
    private function normalise(mixed $rules): array
    {
        return is_array($rules) ? array_values($rules) : [$rules];
    }

    private function required(mixed $rules): bool
    {
        foreach (is_array($rules) ? $rules : [$rules] as $rule) {
            if ($rule === 'required' || $rule === 'present') {
                return true;
            }
        }

        return false;
    }

    private function ignored(string $field): bool
    {
        $ignore = $this->config->payloads['ignore'] ?? [];

        return in_array($field, is_array($ignore) ? $ignore : [], true) || str_starts_with($field, '_');
    }

    private function placeholder(): string
    {
        return self::PLACEHOLDER;
    }

    /**
     * @param  list<mixed>  $rules
     */
    private function stringRules(array $rules): ?string
    {
        foreach ($rules as $rule) {
            if ($rule === 'string' || $rule === 'required' || $rule === 'nullable' || $rule === 'sometimes') {
                return $this->placeholder();
            }
        }

        return null;
    }

    private function describe(mixed $rules): string
    {
        if (! is_array($rules)) {
            $rules = [$rules];
        }

        $parts = array_map(static function (mixed $rule): string {
            return is_string($rule) ? $rule : (is_object($rule) ? class_basename($rule::class) : gettype($rule));
        }, $rules);

        return implode(', ', $parts);
    }
}
