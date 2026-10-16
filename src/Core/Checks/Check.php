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
     * True when the checked value comes from .env in a default Laravel application
     * (APP_DEBUG, SESSION_SECURE_COOKIE): locally it differs on purpose, so the check runs
     * only in production and is skipped, not reported, elsewhere. Values from code and
     * committed config files are the same everywhere, so those checks return false.
     */
    public function onlyInProduction(): bool;

    /**
     * @return iterable<Finding>
     *
     * @throws CheckSkipped when the check cannot be evaluated reliably
     */
    public function run(ScanContext $context): iterable;
}
