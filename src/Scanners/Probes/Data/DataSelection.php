<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Data;

/**
 * The result of data selection: the actors and records, or the reason they could not be built (no
 * factory, too few records) and how the user can help.
 */
final readonly class DataSelection
{
    private function __construct(
        public ?ProbeData $data,
        public ?string $reason,
        public ?string $hint,
    ) {}

    public static function found(ProbeData $data): self
    {
        return new self($data, null, null);
    }

    public static function skipped(string $reason, ?string $hint = null): self
    {
        return new self(null, $reason, $hint);
    }

    public function isFound(): bool
    {
        return $this->data !== null;
    }
}
