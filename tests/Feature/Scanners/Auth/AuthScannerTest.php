<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\AuthScanner;

it('is registered by the service provider', function () {
    $ids = array_map(fn ($scanner) => $scanner->id(), app(ScannerRegistry::class)->all());

    expect($ids)->toContain('auth');
});

it('skips only the checks that read .env values outside production', function () {
    config(['session.secure' => null, 'session.http_only' => false]);

    $result = (new AuthScanner)->scan(localContext());

    $productionOnly = array_values(array_filter(
        $result->skipped,
        fn (SkippedCheck $skipped) => str_contains($skipped->reason, 'only relevant in production'),
    ));

    expect($result->findings)->toBe([])
        ->and(array_map(fn (SkippedCheck $skipped) => $skipped->checkId, $productionOnly))
        ->toBe(['auth.session-cookie-insecure', 'auth.session-cookie-script-accessible']);
});
