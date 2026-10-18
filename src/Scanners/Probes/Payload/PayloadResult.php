<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Payload;

/**
 * The result of building a request body for a route action: the fields to send (names only) and the
 * resolved values, or the reason they could not be built. Values never reach a finding: the probe
 * uses them only inside the child process.
 */
final readonly class PayloadResult
{
    /**
     * @param  array<array-key, mixed>|null  $body
     */
    private function __construct(
        public ?array $body,
        public ?string $reason,
    ) {}

    /**
     * @param  array<array-key, mixed>  $body
     */
    public static function built(array $body): self
    {
        return new self($body, null);
    }

    public static function skipped(string $reason): self
    {
        return new self(null, $reason);
    }

    public function isBuilt(): bool
    {
        return $this->body !== null;
    }
}
