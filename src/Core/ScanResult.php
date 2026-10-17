<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;

final readonly class ScanResult
{
    /**
     * @param  list<Finding>  $findings
     * @param  list<SkippedCheck>  $skipped
     * @param  list<Notice>  $notices
     */
    public function __construct(
        public array $findings = [],
        public array $skipped = [],
        public array $notices = [],
    ) {}
}
