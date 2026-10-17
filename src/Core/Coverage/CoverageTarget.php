<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Coverage;

/**
 * A target a probe did not confirm or could not check, with the reason and how to fix it.
 */
final readonly class CoverageTarget
{
    /**
     * @param  string  $target  e.g. "DELETE /api/invoices/{invoice}"
     */
    public function __construct(
        public string $target,
        public string $reason,
        public ?string $hint = null,
    ) {}
}
