<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Models\Checks;

use Illuminate\Database\Eloquent\Model;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Models\AppModels;
use Jklejczyk\SecurityToolkit\Scanners\Support\AppSource;
use ReflectionClass;
use Throwable;

final class GuardedEmptyCheck implements Check
{
    /**
     * A mass-assignment method receiving the whole request, e.g. User::create($request->all()),
     * with its receiver: a variable ($post->fill) or a class (Post::create, \\App\\Models\\Post::create).
     */
    private const WHOLE_REQUEST_ASSIGNED = '/(?:\$(\w+)->|\\\\?((?:\w+\\\\)*\w+)::)(?:create|fill|update|make|firstOrCreate|firstOrNew|updateOrCreate)\(\s*(?:\$request->(?:all|input)\(\s*\)|request\(\)->(?:all|input)\(\s*\)|Request::(?:all|input)\(\s*\))/';

    public function __construct(
        private readonly AppSource $source = new AppSource,
        private readonly AppModels $models = new AppModels,
    ) {}

    public function id(): string
    {
        return 'models.guarded-empty';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    public function run(ScanContext $context): iterable
    {
        // With every model unguarded, models.unguarded reports the cause and $guarded does not matter.
        if (Model::isUnguarded()) {
            return;
        }

        // $guarded = [] is safe with validated input, so a model is reported only with evidence of the whole request reaching it.
        $evidence = $this->source->matches(self::WHOLE_REQUEST_ASSIGNED);

        if ($evidence === []) {
            return;
        }

        $failures = [];

        foreach ($this->models->all() as ['class' => $class, 'file' => $file]) {
            $reaching = $this->evidenceFor($class, $evidence);

            if ($reaching === null) {
                continue;
            }

            $evidenceAt = sprintf('%s:%d', Location::inApplication($reaching['file'], $context->basePath)->file, substr_count(substr($reaching['code'], 0, $reaching['offset']), "\n") + 1);

            try {
                $unguarded = $this->guardedIsEmpty($class);
            } catch (Throwable $exception) {
                $failures[] = sprintf('could not read the guarded attributes of %s: %s', $class, $exception->getMessage());

                continue;
            }

            if ($unguarded) {
                yield $this->finding($class, Location::inApplication($file, $context->basePath), $evidenceAt);
            }
        }

        if ($failures !== []) {
            throw CheckSkipped::because(implode('; ', $failures));
        }
    }

    /**
     * The first assignment of the whole request whose receiver is the model: the class itself, or a
     * variable named after it, typed with it or assigned from it. A receiver that cannot be linked to
     * a model (e.g. $this->model in a generic repository) is not evidence for any of them.
     *
     * @param  list<array{file: string, code: string, offset: int}>  $evidence
     * @return array{file: string, code: string, offset: int}|null
     */
    private function evidenceFor(string $class, array $evidence): ?array
    {
        $model = class_basename($class);
        $quoted = preg_quote($model, '/');

        foreach ($evidence as $match) {
            if (preg_match(self::WHOLE_REQUEST_ASSIGNED, $match['code'], $call, 0, $match['offset']) !== 1) {
                continue;
            }

            $variable = $call[1];
            $receiver = $call[2] ?? '';

            if ($variable === '') {
                if (class_basename($receiver) === $model) {
                    return $match;
                }

                continue;
            }

            $quotedVariable = preg_quote($variable, '/');

            if (strcasecmp($variable, $model) === 0
                || preg_match('/\b'.$quoted.'\s+\$'.$quotedVariable.'\b/', $match['code']) === 1
                || preg_match('/\$'.$quotedVariable.'\s*=\s*(?:new\s+)?\\\\?(?:\w+\\\\)*'.$quoted.'\b/', $match['code']) === 1) {
                return $match;
            }
        }

        return null;
    }

    /**
     * Read without the constructor, which may need arguments or touch the database.
     *
     * @param  class-string<Model>  $class
     */
    private function guardedIsEmpty(string $class): bool
    {
        $model = (new ReflectionClass($class))->newInstanceWithoutConstructor();

        // Laravel 13 applies #[Unguarded] and #[Guarded] in this initializer; Laravel 12 has none.
        // @phpstan-ignore function.alreadyNarrowedType (always true only when analysed against Laravel 13)
        if (method_exists($model, 'initializeGuardsAttributes')) {
            $model->initializeGuardsAttributes();
        }

        return $model->getGuarded() === [];
    }

    private function finding(string $class, Location $location, string $evidenceAt): Finding
    {
        return new Finding(
            $this->id(),
            Severity::Medium,
            sprintf('%s accepts mass assignment of every attribute', class_basename($class)),
            sprintf('%s has an empty $guarded list, so create(), fill() and update() set any column they receive. The application passes the whole request to such a method (%s), so if it reaches this model, a user can set columns like is_admin, role or user_id by adding them to the request.', $class, $evidenceAt),
            'List the assignable attributes in $fillable instead of $guarded = [], and pass $request->validated() or $request->only([\'title\', \'body\']) instead of the whole request.',
            [
                'https://laravel.com/docs/eloquent#mass-assignment',
                'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
            ],
            $location,
            cwe: [915],
        );
    }
}
