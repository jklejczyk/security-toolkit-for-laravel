<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners\BrokenScanner;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners\FakeScanner;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners\OfflineScanner;

beforeEach(function () {
    $registry = app(ScannerRegistry::class);
    $registry->register(FakeScanner::class);
    $registry->register(BrokenScanner::class);
    $registry->register(OfflineScanner::class);
});

/**
 * @param  array<string, string|bool>  $options
 * @return array{int, string}
 */
function scan(array $options = []): array
{
    $exitCode = Artisan::call('security:scan', $options);

    return [$exitCode, Artisan::output()];
}

it('lists registered scanners without scanning', function () {
    [$exitCode, $output] = scan(['--list' => true]);

    expect($exitCode)->toBe(0)
        ->and($output)->toContain('fake', 'available', FakeScanner::class)
        ->toContain('offline', 'unavailable: needs Docker')
        ->not->toContain('boom');
});

it('fails with code 1 when a finding reaches the default threshold', function () {
    [$exitCode, $output] = scan(['--only' => 'fake']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('fake.rule', 'Fake <finding> title');
});

it('respects --fail-on', function (string $failOn, int $expected) {
    [$exitCode] = scan(['--only' => 'fake', '--fail-on' => $failOn]);

    expect($exitCode)->toBe($expected);
})->with([
    ['critical', 0],
    ['high', 1],
    ['info', 1],
    ['none', 0],
]);

it('hides findings with --min-severity but still fails on them', function () {
    [$exitCode, $output] = scan(['--only' => 'fake', '--min-severity' => 'critical']);

    expect($exitCode)->toBe(1)
        ->and($output)->not->toContain('Fake <finding> title')
        ->toContain('1 hidden by --min-severity=critical');
});

it('accepts spaces and empty entries in --only', function () {
    [$exitCode, $output] = scan(['--only' => ' fake , ']);

    expect($exitCode)->toBe(1)
        ->and($output)->toContain('fake.rule');
});

it('rejects --only without any scanner id', function () {
    [$exitCode, $output] = scan(['--only' => ',']);

    expect($exitCode)->toBe(2)
        ->and($output)->toContain('--only')
        ->not->toContain('fake.rule');
});

it('rejects unknown scanner ids without scanning', function () {
    [$exitCode, $output] = scan(['--only' => 'fake,nope']);

    expect($exitCode)->toBe(2)
        ->and($output)->toContain('Unknown scanner(s): nope')
        ->not->toContain('fake.rule');
});

it('rejects invalid option values', function (string $option, string $value) {
    [$exitCode] = scan(['--only' => 'fake', $option => $value]);

    expect($exitCode)->toBe(2);
})->with([
    ['--format', 'xml'],
    ['--min-severity', 'urgent'],
    ['--fail-on', 'HIGH'],
    ['--min-severity', 'unknown'],
    ['--fail-on', 'unknown'],
]);

it('returns code 2 when a scanner fails, even with findings, and still reports the rest', function () {
    [$exitCode, $output] = scan(['--only' => 'fake,broken']);

    expect($exitCode)->toBe(2)
        ->and($output)->toContain('fake.rule', 'broken', 'boom');
});

it('reports unavailable scanners without failing', function () {
    [$exitCode, $output] = scan(['--only' => 'offline']);

    expect($exitCode)->toBe(0)
        ->and($output)->toContain('needs Docker');
});

it('prints a single JSON document with --format=json', function () {
    [$exitCode, $output] = scan(['--only' => 'fake', '--format' => 'json']);

    $json = json_decode($output, true, flags: JSON_THROW_ON_ERROR);

    expect($exitCode)->toBe(1)
        ->and($json['findings'][0]['rule'])->toBe('fake.rule')
        ->and($json['summary']['high'])->toBe(1);
});

it('rejects --only given without a value', function () {
    [$exitCode, $output] = scan(['--only' => null]);

    expect($exitCode)->toBe(2)
        ->and($output)->toContain('--only')
        ->not->toContain('fake.rule');
});
