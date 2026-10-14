<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

final readonly class Location
{
    public function __construct(
        public string $file,
        public ?int $line = null,
    ) {}
}
