<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership;

/**
 * The result of owner detection: either an owner, or the reason it could not be determined and how
 * the user could help with configuration.
 */
final readonly class OwnerResolution
{
    private function __construct(
        public ?Owner $owner,
        public ?string $reason,
        public ?string $hint,
    ) {}

    public static function found(Owner $owner): self
    {
        return new self($owner, null, null);
    }

    public static function skipped(string $reason, ?string $hint = null): self
    {
        return new self(null, $reason, $hint);
    }

    public function isFound(): bool
    {
        return $this->owner !== null;
    }
}
