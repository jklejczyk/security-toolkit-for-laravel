<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\Notice;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;

/**
 * The DAST module. Without a configured probe connection it is unavailable, so the scan never
 * starts a child process by itself. With one, it refuses on production, on a cached configuration
 * and against the application database, and otherwise runs the isolated probe process.
 */
final class ProbesScanner implements Scanner
{
    public function id(): string
    {
        return 'probes';
    }

    public function availability(): Availability
    {
        $connection = config('security-toolkit.probes.connection');

        if (! is_string($connection) || trim($connection) === '') {
            return Availability::unavailable('probes are off: set SECURITY_TOOLKIT_PROBES_CONNECTION to a test database connection');
        }

        $data = config('security-toolkit.probes.data', 'auto');

        if (! is_string($data) || ! in_array($data, ProbesConfig::DATA_MODES, true)) {
            return Availability::unavailable(sprintf(
                'probes are off: probes.data must be one of %s',
                implode(', ', ProbesConfig::DATA_MODES),
            ));
        }

        return Availability::available();
    }

    public function scan(ScanContext $context): ScanResult
    {
        $config = ProbesConfig::fromConfig();
        $blocker = new ProbeBlocker;

        $block = $blocker->reason($context, $config);

        if ($block !== null) {
            return new ScanResult(skipped: [new SkippedCheck($this->id(), $block)]);
        }

        $notices = [];

        if ($config->allowAppDatabase && $blocker->sharesWithApplication($config)) {
            $notices[] = new Notice($this->id(), 'probes ran against the application database '.(string) $config->connection);
        }

        $report = (new ChildProcess($config))->run($context);

        return new ScanResult(
            $report->findings,
            notices: [...$notices, ...$report->notices],
            coverage: $report->coverage,
        );
    }
}
