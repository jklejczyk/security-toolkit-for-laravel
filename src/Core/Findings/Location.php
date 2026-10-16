<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

use Closure;
use ReflectionFunction;

final readonly class Location
{
    public function __construct(
        public string $file,
        public ?int $line = null,
    ) {}

    /**
     * A file inside the application is stored relative to its root, any other file as given.
     * The root is also tried resolved, for deployments that reach it through a symlink.
     */
    public static function inApplication(string $file, string $basePath, ?int $line = null): self
    {
        foreach ([$basePath, realpath($basePath)] as $root) {
            if (! is_string($root) || $root === '') {
                continue;
            }

            $prefix = rtrim($root, '/').'/';

            if (str_starts_with($file, $prefix)) {
                return new self(substr($file, strlen($prefix)), $line);
            }
        }

        return new self($file, $line);
    }

    /**
     * Where a closure is defined, e.g. a gate or the Password::defaults() callback.
     */
    public static function ofClosure(Closure $closure, string $basePath): ?self
    {
        $reflection = new ReflectionFunction($closure);
        $file = $reflection->getFileName();

        if ($file === false) {
            return null;
        }

        return self::inApplication($file, $basePath, $reflection->getStartLine() ?: null);
    }
}
