<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Illuminate\Support\Facades\Process;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol\ProbeReport;
use RuntimeException;

/**
 * Runs `php artisan security:probe --internal` in an isolated process, with the probe connection
 * and the neutralized environment set in its environment so the overrides apply before the
 * application boots. The child prints its report as JSON on the last line of stdout.
 */
final class ChildProcess
{
    public function __construct(
        private readonly ProbesConfig $config,
    ) {}

    public function run(ScanContext $context): ProbeReport
    {
        $result = Process::path($context->basePath)
            ->timeout($this->config->timeout)
            ->env($this->environment($context))
            ->run([
                PHP_BINARY,
                'artisan',
                'security:probe',
                '--internal',
                '--deadline='.max(1, $this->config->timeout - 30),
            ]);

        if (! $result->successful()) {
            $error = trim($result->errorOutput());

            throw new RuntimeException($error !== ''
                ? 'the probe process failed: '.$error
                : sprintf('the probe process failed with exit code %s', (string) $result->exitCode()));
        }

        return ProbeReport::fromJson($this->lastJsonLine($result->output()));
    }

    private function lastJsonLine(string $output): string
    {
        $lines = preg_split('/\R/', $output);

        if ($lines === false) {
            throw new RuntimeException('the probe process produced no JSON report');
        }

        for ($index = count($lines) - 1; $index >= 0; $index--) {
            $line = trim($lines[$index]);

            if (str_starts_with($line, '{')) {
                return $line;
            }
        }

        throw new RuntimeException('the probe process produced no JSON report');
    }

    /**
     * @return array<string, string>
     */
    private function environment(ScanContext $context): array
    {
        return [
            'APP_ENV' => $context->environment,
            'DB_CONNECTION' => (string) $this->config->connection,
            'MAIL_MAILER' => 'array',
            'QUEUE_CONNECTION' => 'sync',
            'BROADCAST_CONNECTION' => 'null',
            'CACHE_STORE' => 'array',
            'SESSION_DRIVER' => 'array',
            'SECURITY_TOOLKIT_PROBE_CONNECTION' => (string) $this->config->connection,
            'SECURITY_TOOLKIT_PROBE_DATA' => $this->config->data,
            'SECURITY_TOOLKIT_PROBE_MIGRATE' => $this->config->migrate ? '1' : '0',
            'SECURITY_TOOLKIT_PROBE_ALLOW_APP_DATABASE' => $this->config->allowAppDatabase ? '1' : '0',
        ];
    }
}
