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
        public ?string $source = null,
    ) {}

    /**
     * @param  array<array-key, mixed>  $body
     * @param  string  $source  where the body came from: form_request, inline, runtime or config
     */
    public static function built(array $body, string $source = 'form_request'): self
    {
        return new self($body, null, $source);
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
