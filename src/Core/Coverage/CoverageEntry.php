<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Coverage;

/**
 * What one probe checked: how many targets, how many it confirmed, and which ones it left open.
 */
final readonly class CoverageEntry
{
    /**
     * @param  list<CoverageTarget>  $notConfirmed  checked, with no issue found
     * @param  list<CoverageTarget>  $skipped  not checked
     */
    public function __construct(
        public string $probe,
        public int $checked,
        public int $confirmed,
        public array $notConfirmed = [],
        public array $skipped = [],
    ) {}
}
