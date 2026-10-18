<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Probes;

use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;

/**
 * The control probe: it sends a guest GET to the home page and records the answer, so the engine
 * and the HTTP client can be exercised without a production probe. Registered only in tests, never
 * by the package.
 */
final class EngineSmokeProbe implements Probe
{
    public function id(): string
    {
        return 'probes.engine-smoke';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(ProbeContext $context): iterable
    {
        $response = $context->client()->request('GET', '/');

        $context->coverage()->checked(new CoverageTarget(
            'GET /',
            sprintf('answered %d', $response->status),
        ));

        return [];
    }
}
