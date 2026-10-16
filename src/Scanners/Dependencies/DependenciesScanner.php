<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Dependencies;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Process;
use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use RuntimeException;

final class DependenciesScanner implements Scanner
{
    private const TIMEOUT_SECONDS = 120;

    public function __construct(
        private readonly Application $app,
        private readonly ComposerLocator $composer,
    ) {}

    public function id(): string
    {
        return 'dependencies';
    }

    public function availability(): Availability
    {
        $basePath = $this->app->basePath();

        if ($this->composer->command($basePath) === null) {
            return Availability::unavailable('composer executable not found (neither in PATH nor composer.phar in the application directory)');
        }

        if (! is_file($basePath.'/composer.json')) {
            return Availability::unavailable('no composer.json in the application directory');
        }

        if (! is_file($basePath.'/vendor/composer/installed.json')) {
            return Availability::unavailable('no installed Composer packages found (vendor/composer/installed.json)');
        }

        return Availability::available();
    }

    public function scan(ScanContext $context): ScanResult
    {
        $command = $this->composer->command($context->basePath)
            ?? throw new RuntimeException('composer executable not found');

        // Audits the installed packages, so a server installed with --no-dev is not blamed for dev tools.
        $result = Process::timeout(self::TIMEOUT_SECONDS)->run([
            ...$command,
            'audit',
            '--format=json',
            '--no-interaction',
            '--working-dir='.$context->basePath,
        ]);

        if (str_contains($result->errorOutput(), 'Command "audit" is not defined')) {
            $reason = 'composer audit requires Composer 2.4 or newer; run composer self-update';

            return new ScanResult([], [
                new SkippedCheck('dependencies.vulnerable-package', $reason),
                new SkippedCheck('dependencies.abandoned-package', $reason),
            ]);
        }

        // The exit code is a bitmask (1: vulnerable packages, 2: abandoned packages), not an error flag.
        return new ScanResult((new AuditFindings)->fromOutput($result->output(), $result->errorOutput()));
    }
}
