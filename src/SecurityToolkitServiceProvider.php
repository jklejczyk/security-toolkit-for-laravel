<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Jklejczyk\SecurityToolkit\Console\ProbeCommand;
use Jklejczyk\SecurityToolkit\Console\ScanCommand;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Scanners\Auth\AuthScanner;
use Jklejczyk\SecurityToolkit\Scanners\Config\ConfigScanner;
use Jklejczyk\SecurityToolkit\Scanners\Dependencies\DependenciesScanner;
use Jklejczyk\SecurityToolkit\Scanners\Files\FilesScanner;
use Jklejczyk\SecurityToolkit\Scanners\Models\ModelsScanner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Engine\ProbeEngine;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\CsrfProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\IdorProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\MassAssignmentProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\MissingAuthenticationProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\RateLimitProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesScanner;
use Jklejczyk\SecurityToolkit\Scanners\Routes\RoutesScanner;

final class SecurityToolkitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security-toolkit.php', 'security-toolkit');

        $this->app->singleton(ScannerRegistry::class);

        $this->app->singleton(
            ProbeEngine::class,
            fn (Application $app): ProbeEngine => new ProbeEngine($app, probes: [new MissingAuthenticationProbe, new IdorProbe, new CsrfProbe, new RateLimitProbe, new MassAssignmentProbe]),
        );
    }

    public function boot(): void
    {
        $registry = $this->app->make(ScannerRegistry::class);
        $registry->register(ConfigScanner::class);
        $registry->register(FilesScanner::class);
        $registry->register(AuthScanner::class);
        $registry->register(ModelsScanner::class);
        $registry->register(RoutesScanner::class);
        $registry->register(ProbesScanner::class);
        $registry->register(DependenciesScanner::class);

        if ($this->app->runningInConsole()) {
            $this->commands([ScanCommand::class, ProbeCommand::class]);

            $this->publishes([
                __DIR__.'/../config/security-toolkit.php' => config_path('security-toolkit.php'),
            ], 'security-toolkit-config');
        }
    }
}
