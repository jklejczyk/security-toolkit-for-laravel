<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests;

use Illuminate\Support\Facades\Process;
use Jklejczyk\SecurityToolkit\SecurityToolkitServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        // composer audit needs the network: every test must fake the processes it runs.
        Process::fake([]);
        Process::preventStrayProcesses();
    }

    protected function getPackageProviders($app): array
    {
        return [
            SecurityToolkitServiceProvider::class,
        ];
    }
}
