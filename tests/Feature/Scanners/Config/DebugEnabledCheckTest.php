<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\DebugEnabledCheck;

it('is a production-only check', function () {
    expect((new DebugEnabledCheck)->onlyInProduction())->toBeTrue()
        ->and((new DebugEnabledCheck)->id())->toBe('config.debug-enabled');
});

// Laravel enables debug pages whenever app.debug is truthy, so a raw "false" string still counts.
it('reports debug mode', function (mixed $value) {
    config(['app.debug' => $value]);

    $findings = iterator_to_array((new DebugEnabledCheck)->run(productionContext()), false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('config.debug-enabled')
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->location?->file)->toBe('config/app.php');
})->with([true, 'true', '1', 1, 'false', 'off']);

it('does not report disabled debug mode', function (mixed $value) {
    config(['app.debug' => $value]);

    expect(iterator_to_array((new DebugEnabledCheck)->run(productionContext()), false))->toBe([]);
})->with([false, '0', 0, null, '']);
