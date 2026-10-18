<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;

/**
 * One DAST probe: it sends requests and returns the findings it reproduced. Coverage of what it
 * checked, confirmed and skipped is reported through the context, so the caller can build the
 * coverage entry without knowing the shape of each probe.
 */
interface Probe
{
    /**
     * Rule prefix of the findings without a static counterpart, e.g. "probes.idor".
     */
    public function id(): string;

    /**
     * @return iterable<Finding>
     */
    public function run(ProbeContext $context): iterable;
}
