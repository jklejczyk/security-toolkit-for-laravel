<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

final readonly class UnavailableScanner
{
    public function __construct(
        public string $scannerId,
        public string $reason,
    ) {}
}
