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
 */
final class AppModels
{
    private const DECLARATION = '/^namespace\s+([\w\\\\]+)\s*;.*?^(?:(?:final|abstract|readonly)\s+)*class\s+(\w+)/ms';

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
        $models = [];

        $this->source->any(function (string $code, string $file) use (&$models): bool {
            if (preg_match(self::DECLARATION, $code, $declaration) !== 1) {
                return false;
            }

            $class = $declaration[1].'\\'.$declaration[2];

            if (! class_exists($class) || ! is_subclass_of($class, Model::class) || is_subclass_of($class, Pivot::class)) {
                return false;
            }

            if ((new ReflectionClass($class))->isAbstract()) {
                return false;
            }

            $models[] = ['class' => $class, 'file' => $file];

            return false;
        });

        return $models;
    }
}
