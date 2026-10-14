<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

final readonly class SkippedCheck
{
    public function __construct(
        public string $checkId,
        public string $reason,
    ) {}
}
