<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\AuthScanner;

it('is registered by the service provider', function () {
    $ids = array_map(fn ($scanner) => $scanner->id(), app(ScannerRegistry::class)->all());

    expect($ids)->toContain('auth');
});

it('skips every check outside production', function () {
    config(['session.secure' => null, 'session.http_only' => false]);

    $result = (new AuthScanner)->scan(localContext());

    expect($result->findings)->toBe([])
        ->and(array_map(fn (SkippedCheck $skipped) => $skipped->checkId, $result->skipped))
        ->toBe([
            'auth.session-cookie-insecure',
            'auth.session-cookie-script-accessible',
            'auth.password-too-short',
            'auth.password-not-checked-for-leaks',
            'auth.sanctum-tokens-never-expire',
        ]);
});
