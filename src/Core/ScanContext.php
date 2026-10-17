<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use Illuminate\Contracts\Foundation\Application;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;

final readonly class ScanContext
{
    public function __construct(
        public string $environment,
        public string $basePath,
        public InstalledPackages $packages,
        public ApplicationMap $map = new ApplicationMap,
    ) {}

    public static function fromApplication(Application $app): self
    {
        return new self($app->environment(), $app->basePath(), InstalledPackages::fromComposer());
    }

    public function isProduction(): bool
    {
        return $this->environment === 'production';
    }
}
