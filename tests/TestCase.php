<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests;

use Jklejczyk\SecurityToolkit\SecurityToolkitServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SecurityToolkitServiceProvider::class,
        ];
    }
}
