<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit;

use Illuminate\Support\ServiceProvider;
use Jklejczyk\SecurityToolkit\Console\ScanCommand;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Scanners\Config\ConfigScanner;

final class SecurityToolkitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScannerRegistry::class);
    }

    public function boot(): void
    {
        $this->app->make(ScannerRegistry::class)->register(ConfigScanner::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class]);
        }
    }
}
