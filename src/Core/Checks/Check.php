<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Checks;

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

interface Check
{
    /**
     * Rule identifier, e.g. "config.debug-enabled".
     */
    public function id(): string;

    /**
     * Production-only checks are skipped, not reported, in other environments.
     */
    public function onlyInProduction(): bool;

    /**
     * @return iterable<Finding>
     *
     * @throws CheckSkipped when the check cannot be evaluated reliably
     */
    public function run(ScanContext $context): iterable;
}
