<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Engine;

/**
 * Notes whether the application counted this request against a rate limiter. Decorated onto the
 * container's RateLimiter for the life of the probe process, and filled by the Lockout event, so a
 * probe can tell "no limit at all" from "limited without answering 429".
 */
final class RateLimiterRecorder
{
    private bool $touched = false;

    public function touch(): void
    {
        $this->touched = true;
    }

    public function touched(): bool
    {
        return $this->touched;
    }

    public function reset(): void
    {
        $this->touched = false;
    }
}
