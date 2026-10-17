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
     * A mass-assignment method receiving the whole request, e.g. User::create($request->all()).
     */
    private const WHOLE_REQUEST_ASSIGNED = '/(?:->|::)(?:create|fill|update|make|firstOrCreate|firstOrNew|updateOrCreate)\(\s*(?:\$request->(?:all|input)\(\s*\)|request\(\)->(?:all|input)\(\s*\)|Request::(?:all|input)\(\s*\))/';

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

        // $guarded = [] is safe with validated input, so a model is reported only with evidence of the whole request reaching one.
        $evidence = $this->source->matches(self::WHOLE_REQUEST_ASSIGNED)[0] ?? null;

        if ($evidence === null) {
            return;
        }

        $evidenceAt = sprintf('%s:%d', Location::inApplication($evidence['file'], $context->basePath)->file, substr_count(substr($evidence['code'], 0, $evidence['offset']), "\n") + 1);
        $failures = [];

        foreach ($this->models->all() as ['class' => $class, 'file' => $file]) {
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
