<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit;

use Illuminate\Support\ServiceProvider;
use Jklejczyk\SecurityToolkit\Console\ScanCommand;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Scanners\Auth\AuthScanner;
use Jklejczyk\SecurityToolkit\Scanners\Config\ConfigScanner;
use Jklejczyk\SecurityToolkit\Scanners\Dependencies\DependenciesScanner;
use Jklejczyk\SecurityToolkit\Scanners\Files\FilesScanner;
use Jklejczyk\SecurityToolkit\Scanners\Models\ModelsScanner;

final class SecurityToolkitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(ScannerRegistry::class);
    }

    public function boot(): void
    {
        $registry = $this->app->make(ScannerRegistry::class);
        $registry->register(ConfigScanner::class);
        $registry->register(FilesScanner::class);
        $registry->register(AuthScanner::class);
        $registry->register(ModelsScanner::class);
        $registry->register(DependenciesScanner::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class]);
        }
    }
}
