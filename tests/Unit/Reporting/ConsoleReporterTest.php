<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScannerFailure;
use Jklejczyk\SecurityToolkit\Core\ScanReport;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Core\UnavailableScanner;
use Jklejczyk\SecurityToolkit\Reporting\ConsoleReporter;
use Symfony\Component\Console\Output\BufferedOutput;

function renderConsole(ScanReport $report, Severity $min = Severity::Info): string
{
    $output = new BufferedOutput;
    (new ConsoleReporter)->render($report, $min, $output);

    return $output->fetch();
}

it('renders a finding with its full recommendation', function () {
    $output = renderConsole(new ScanReport([
        new Finding(
            'config.debug-enabled',
            Severity::Critical,
            'Debug mode is enabled in production',
            'Error pages expose secrets.',
            'Set APP_DEBUG=false.',
            ['https://laravel.com/docs/configuration#debug-mode'],
            new Location('config/app.php'),
        ),
    ]));

    expect($output)
        ->toContain('CRITICAL')
        ->toContain('Debug mode is enabled in production')
        ->toContain('config.debug-enabled')
        ->toContain('config/app.php')
        ->toContain('Error pages expose secrets.')
        ->toContain('Fix: Set APP_DEBUG=false.')
        ->toContain('https://laravel.com/docs/configuration#debug-mode')
        ->toContain('Summary: 1 critical, 0 high, 0 medium, 0 low, 0 info');
});

it('prints the line number when the location has one', function () {
    $output = renderConsole(new ScanReport([
        new Finding('a.rule', Severity::High, 'T', 'D', 'R', [], new Location('app/Providers/TelescopeServiceProvider.php', 42)),
    ]));

    expect($output)->toContain('app/Providers/TelescopeServiceProvider.php:42');
});

it('prints finding text literally, without interpreting console tags', function () {
    $output = renderConsole(new ScanReport([
        new Finding('a.rule', Severity::High, 'Gate <viewTelescope> is open', 'Uses <info>tags</info>.', 'R'),
    ]));

    expect($output)
        ->toContain('Gate <viewTelescope> is open')
        ->toContain('Uses <info>tags</info>.');
});

it('hides findings below the minimum severity but counts them in the summary', function () {
    $output = renderConsole(new ScanReport([
        new Finding('a.high', Severity::High, 'High finding', 'D', 'R'),
        new Finding('a.low', Severity::Low, 'Low finding', 'D', 'R'),
    ]), Severity::High);

    expect($output)
        ->toContain('High finding')
        ->not->toContain('Low finding')
        ->toContain('Summary: 0 critical, 1 high, 0 medium, 1 low, 0 info')
        ->toContain('1 hidden by --min-severity=high');
});

it('says so when there is nothing to show, and lists skipped checks', function () {
    $output = renderConsole(new ScanReport([], [
        new SkippedCheck('config.debug-enabled', 'only relevant in production (current environment: local)'),
    ]));

    expect($output)
        ->toContain('No findings to show.')
        ->toContain('1 check skipped')
        ->toContain('config.debug-enabled')
        ->toContain('only relevant in production (current environment: local)');
});

it('lists unavailable scanners and errors', function () {
    $output = renderConsole(new ScanReport(
        unavailable: [new UnavailableScanner('zap', 'needs Docker')],
        errors: [new ScannerFailure('broken', 'boom')],
    ));

    expect($output)
        ->toContain('zap')
        ->toContain('needs Docker')
        ->toContain('broken')
        ->toContain('boom');
});
