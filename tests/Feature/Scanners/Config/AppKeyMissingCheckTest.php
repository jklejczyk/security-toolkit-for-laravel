<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\AppKeyMissingCheck;

it('is a production-only check', function () {
    expect((new AppKeyMissingCheck)->onlyInProduction())->toBeTrue()
        ->and((new AppKeyMissingCheck)->id())->toBe('config.app-key-missing');
});

it('reports a missing key', function (mixed $value) {
    config(['app.key' => $value]);

    $findings = iterator_to_array((new AppKeyMissingCheck)->run(productionContext()), false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([1391])
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N');
})->with(['', null, '   ']);

it('does not report a configured key', function () {
    config(['app.key' => 'base64:'.base64_encode(random_bytes(32))]);

    expect(iterator_to_array((new AppKeyMissingCheck)->run(productionContext()), false))->toBe([]);
});
