<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Contracts;

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;

interface Scanner
{
    /**
     * Identifier used in --only and as the rule ID prefix, e.g. "config".
     */
    public function id(): string;

    public function availability(): Availability;

    public function scan(ScanContext $context): ScanResult;
}
