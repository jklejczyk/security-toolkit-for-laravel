<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

final readonly class Availability
{
    private function __construct(
        public bool $available,
        public ?string $reason,
    ) {}

    public static function available(): self
    {
        return new self(true, null);
    }

    public static function unavailable(string $reason): self
    {
        return new self(false, $reason);
    }
}
