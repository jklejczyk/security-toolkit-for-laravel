<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use Composer\InstalledVersions;

final readonly class InstalledPackages
{
    /**
     * @param  list<string>|null  $packages  null asks Composer's runtime metadata
     */
    private function __construct(
        private ?array $packages,
    ) {}

    public static function fromComposer(): self
    {
        return new self(null);
    }

    /**
     * @param  list<string>  $packages
     */
    public static function fromList(array $packages): self
    {
        return new self($packages);
    }

    public function isInstalled(string $package): bool
    {
        if ($this->packages === null) {
            return InstalledVersions::isInstalled($package);
        }

        return in_array($package, $this->packages, true);
    }
}
