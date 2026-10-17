<?php

declare(strict_types=1);

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\InstalledPackages;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\DashboardOpenCheck;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Models\UserWithRequiredArgument;
use Opcodes\LogViewer\Facades\LogViewer;

beforeEach(function () {
    config(['auth.providers.users.model' => User::class]);
});

/**
 * @return list<Finding>
 */
function dashboardFindings(ScanContext $context): array
{
    return iterator_to_array((new DashboardOpenCheck)->run($context), false);
}

it('is a production-only check', function () {
    expect((new DashboardOpenCheck)->onlyInProduction())->toBeTrue()
        ->and((new DashboardOpenCheck)->id())->toBe('config.dashboard-open');
});

it('reports a dashboard whose gate lets every user in', function () {
    Gate::define('viewTelescope', fn ($user) => true);

    $findings = dashboardFindings(productionContext(['laravel/telescope']));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->title)->toContain('Telescope')
        ->and($findings[0]->description)->toContain('viewTelescope')
        ->and($findings[0]->location?->file)->toEndWith('DashboardOpenCheckTest.php')
        ->and($findings[0]->location?->line)->toBeInt();
});

it('makes the gate location relative to the application path', function () {
    Gate::define('viewHorizon', fn ($user) => true);

    // __DIR__ is tests/Feature/Scanners/Config, so the repository root is four levels up.
    $context = new ScanContext('production', dirname(__DIR__, 4), InstalledPackages::fromList(['laravel/horizon']));

    expect(dashboardFindings($context)[0]->location?->file)
        ->toBe('tests/Feature/Scanners/Config/DashboardOpenCheckTest.php');
});

it('does not report a restricted gate', function () {
    Gate::define('viewTelescope', fn ($user) => $user->email === 'admin@example.com');

    expect(dashboardFindings(productionContext(['laravel/telescope'])))->toBe([]);
});

it('ignores dashboards that are not installed', function () {
    Gate::define('viewTelescope', fn ($user) => true);

    expect(dashboardFindings(productionContext()))->toBe([]);
});

it('ignores installed dashboards without a gate', function () {
    expect(dashboardFindings(productionContext(['laravel/pulse'])))->toBe([]);
});

it('reports each open dashboard separately', function () {
    Gate::define('viewTelescope', fn ($user) => true);
    Gate::define('viewPulse', fn ($user) => true);

    $titles = array_map(
        fn (Finding $finding) => $finding->title,
        dashboardFindings(productionContext(['laravel/telescope', 'laravel/pulse'])),
    );

    expect($titles)->toHaveCount(2)
        ->and(implode(' ', $titles))->toContain('Telescope', 'Pulse');
});

it('keeps other findings and skips when a gate cannot be evaluated', function () {
    Gate::define('viewTelescope', fn ($user) => throw new RuntimeException('database is down'));
    Gate::define('viewHorizon', fn ($user) => true);

    $findings = [];

    expect(function () use (&$findings) {
        foreach ((new DashboardOpenCheck)->run(productionContext(['laravel/telescope', 'laravel/horizon'])) as $finding) {
            $findings[] = $finding;
        }
    })->toThrow(CheckSkipped::class, 'could not evaluate the viewTelescope gate: database is down');

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->title)->toContain('Horizon');
});

it('skips when the user model cannot be resolved', function () {
    config(['auth.providers.users.model' => 'App\Models\Missing']);
    Gate::define('viewTelescope', fn ($user) => true);

    dashboardFindings(productionContext(['laravel/telescope']));
})->throws(CheckSkipped::class, 'user model');

it('ignores a dashboard that is switched off in its config', function (string $package, string $ability, string $configKey) {
    Gate::define($ability, fn ($user) => true);
    config([$configKey => false]);

    expect(dashboardFindings(productionContext([$package])))->toBe([]);
})->with([
    ['laravel/telescope', 'viewTelescope', 'telescope.enabled'],
    ['opcodesio/log-viewer', 'viewLogViewer', 'log-viewer.enabled'],
]);

it('skips instead of failing when the user model cannot be instantiated', function () {
    config(['auth.providers.users.model' => UserWithRequiredArgument::class]);
    Gate::define('viewTelescope', fn ($user) => true);

    dashboardFindings(productionContext(['laravel/telescope']));
})->throws(CheckSkipped::class, 'could not instantiate the user model');

it('rates each dashboard by what it exposes', function (string $package, string $ability, string $vector, Severity $severity) {
    Gate::define($ability, fn ($user) => true);

    $findings = dashboardFindings(productionContext([$package]));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->cwe)->toBe([862])
        ->and($findings[0]->cvss?->vector)->toBe($vector)
        ->and($findings[0]->severity)->toBe($severity);
})->with([
    'Telescope' => ['laravel/telescope', 'viewTelescope', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L', Severity::High],
    'Horizon' => ['laravel/horizon', 'viewHorizon', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N', Severity::High],
    'Pulse' => ['laravel/pulse', 'viewPulse', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', Severity::Medium],
    'Log Viewer' => ['opcodesio/log-viewer', 'viewLogViewer', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L', Severity::High],
]);

it('reports a gate that lets guests in as open to everyone', function () {
    Gate::define('viewHorizon', fn ($user = null) => true);

    $findings = dashboardFindings(productionContext(['laravel/horizon']));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->title)->toBe('Horizon dashboard is open to everyone')
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N')
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->location?->file)->toEndWith('DashboardOpenCheckTest.php');
});

it('reports a gate with a required user only as open to logged-in users', function () {
    Gate::define('viewHorizon', fn ($user) => true);

    expect(dashboardFindings(productionContext(['laravel/horizon']))[0]->title)
        ->toBe('Horizon dashboard is open to every logged-in user');
});

it('does not report a nullable gate that refuses guests', function () {
    Gate::define('viewHorizon', fn ($user = null) => $user !== null && $user->email === 'admin@example.com');

    expect(dashboardFindings(productionContext(['laravel/horizon'])))->toBe([]);
});

describe('Log Viewer without a gate', function () {
    beforeEach(function () {
        require_once dirname(__DIR__, 3).'/Fixtures/LogViewer/LogViewer.php';
        LogViewer::$hasAuthCallback = false;
    });

    it('reports it as open to everyone when auth is not required in production', function () {
        config(['log-viewer.require_auth_in_production' => false]);

        $findings = dashboardFindings(productionContext(['opcodesio/log-viewer']));

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->title)->toBe('Log Viewer dashboard is open to everyone')
            ->and($findings[0]->description)->toContain('require_auth_in_production')
            ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L')
            ->and($findings[0]->location)->toBeNull();
    });

    it('treats a missing require_auth_in_production like Log Viewer does, as false', function () {
        expect(dashboardFindings(productionContext(['opcodesio/log-viewer'])))->toHaveCount(1);
    });

    it('does not report it when auth is required in production', function () {
        config(['log-viewer.require_auth_in_production' => true]);

        expect(dashboardFindings(productionContext(['opcodesio/log-viewer'])))->toBe([]);
    });

    it('does not report it when LogViewer::auth() has a callback', function () {
        config(['log-viewer.require_auth_in_production' => false]);
        LogViewer::$hasAuthCallback = true;

        expect(dashboardFindings(productionContext(['opcodesio/log-viewer'])))->toBe([]);
    });

    it('does not report it when it is switched off', function () {
        config(['log-viewer.require_auth_in_production' => false, 'log-viewer.enabled' => false]);

        expect(dashboardFindings(productionContext(['opcodesio/log-viewer'])))->toBe([]);
    });
});

it('reports a dashboard open to guests even when the user model cannot be resolved', function () {
    config(['auth.providers.users.model' => 'App\Models\Missing']);
    Gate::define('viewHorizon', fn ($user = null) => true);

    expect(dashboardFindings(productionContext(['laravel/horizon']))[0]->title)
        ->toBe('Horizon dashboard is open to everyone');
});
