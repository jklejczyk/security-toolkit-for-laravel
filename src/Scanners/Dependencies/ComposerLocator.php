<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Dependencies;

use Symfony\Component\Process\ExecutableFinder;

final class ComposerLocator
{
    public function __construct(
        private readonly ExecutableFinder $finder = new ExecutableFinder,
    ) {}

    /**
     * The command that runs Composer, or null when it is not installed.
     *
     * @return list<string>|null
     */
    public function command(string $basePath): ?array
    {
        $composer = $this->finder->find('composer');

        if ($composer !== null) {
            return [$composer];
        }

        $phar = rtrim($basePath, '/').'/composer.phar';

        return is_file($phar) ? [PHP_BINARY, $phar] : null;
    }
}
