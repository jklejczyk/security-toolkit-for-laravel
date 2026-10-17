<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

/**
 * Information for the reader that is neither a finding nor a skipped check, e.g. that probes ran
 * against the application database. Never counted by --fail-on.
 */
final readonly class Notice
{
    public function __construct(
        public string $scannerId,
        public string $message,
    ) {}
}
