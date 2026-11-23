<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Pivot;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Scanners\Support\AppSource;
use ReflectionClass;

/**
 * Eloquent models declared in app/, found by the namespace and class declarations of each file.
 *
 * A class is loaded only when its source shows it may be a model: its chain of parents, followed
 * through the source of app/, ends in a class outside app/ that is a model. Loading an unrelated
 * class can be a fatal error (an incompatible signature, a missing parent), which no catch stops.
 */
final class AppModels
{
    private const NAMESPACE = '/^namespace\s+([\w\\\\]+)\s*;/m';

    private const CLASS_DECLARATION = '/^(?:(?:final|abstract|readonly)\s+)*class\s+(\w+)(?:\s+extends\s+(\\\\?[\w\\\\]+))?/m';

    private const IMPORT = '/^use\s+\\\\?([\w\\\\]+)(?:\s+as\s+(\w+))?\s*;/m';

    public function __construct(
        private readonly AppSource $source = new AppSource,
    ) {}

    /**
     * Instantiable models other than pivots, which are unguarded by default and filled by relations.
     *
     * @return list<array{class: class-string<Model>, file: string}>
     *
     * @throws CheckSkipped
     */
    public function all(): array
    {
        $declarations = $this->declarations();
        $models = [];

        foreach ($declarations as $class => ['file' => $file]) {
            if (! $this->extendsModel($class, $declarations, []) || ! class_exists($class) || ! is_subclass_of($class, Model::class) || is_subclass_of($class, Pivot::class)) {
                continue;
            }

            if ((new ReflectionClass($class))->isAbstract()) {
                continue;
            }

            $models[] = ['class' => $class, 'file' => $file];
        }

        return $models;
    }

    /**
     * The first class declared in each file of app/, with its parent resolved to a full name.
     *
     * @return array<string, array{file: string, parent: ?string}>
     *
     * @throws CheckSkipped
     */
    private function declarations(): array
    {
        $declarations = [];

        $this->source->any(function (string $code, string $file) use (&$declarations): bool {
            if (preg_match(self::NAMESPACE, $code, $namespace) !== 1 || preg_match(self::CLASS_DECLARATION, $code, $declaration) !== 1) {
                return false;
            }

            $parent = isset($declaration[2]) ? $this->resolve($declaration[2], $namespace[1], $code) : null;
            $declarations[$namespace[1].'\\'.$declaration[1]] = ['file' => $file, 'parent' => $parent];

            return false;
        });

        return $declarations;
    }

    /**
     * The full name of a class referenced in a file, following its imports.
     */
    private function resolve(string $name, string $namespace, string $code): string
    {
        if (str_starts_with($name, '\\')) {
            return substr($name, 1);
        }

        $parts = explode('\\', $name, 2);
        $first = $parts[0];
        $rest = $parts[1] ?? null;

        preg_match_all(self::IMPORT, $code, $imports, PREG_SET_ORDER);

        foreach ($imports as $import) {
            $alias = $import[2] ?? '';
            $alias = $alias !== '' ? $alias : substr((string) strrchr('\\'.$import[1], '\\'), 1);

            if (strcasecmp($alias, $first) === 0) {
                return $rest === null ? $import[1] : $import[1].'\\'.$rest;
            }
        }

        return $namespace.'\\'.$name;
    }

    /**
     * Follows the parents declared in app/ without loading them; only the first parent outside app/ is loaded.
     *
     * @param  array<string, array{file: string, parent: ?string}>  $declarations
     * @param  array<string, true>  $visited
     */
    private function extendsModel(string $class, array $declarations, array $visited): bool
    {
        $parent = $declarations[$class]['parent'] ?? null;

        if ($parent === null || isset($visited[$class])) {
            return false;
        }

        if (isset($declarations[$parent])) {
            return $this->extendsModel($parent, $declarations, $visited + [$class => true]);
        }

        return $parent === Model::class || (class_exists($parent) && is_subclass_of($parent, Model::class));
    }
}
