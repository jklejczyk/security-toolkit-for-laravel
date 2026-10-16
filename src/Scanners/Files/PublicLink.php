<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Files;

final readonly class PublicLink
{
    /**
     * @param  string  $path  where the link lives, normalized
     * @param  string  $target  the directory it points to, normalized
     * @param  bool  $fromConfig  defined in filesystems.links rather than only found on disk
     */
    public function __construct(
        public string $path,
        public string $target,
        public bool $fromConfig,
    ) {}
}
