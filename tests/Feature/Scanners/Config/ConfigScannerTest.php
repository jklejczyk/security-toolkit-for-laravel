<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Config\ConfigScanner;

it('is registered by the service provider', function () {
    $ids = array_map(fn ($scanner) => $scanner->id(), app(ScannerRegistry::class)->all());

    expect($ids)->toContain('config');
});

it('skips every check outside production', function () {
    config(['app.debug' => true, 'app.key' => '']);

    $result = (new ConfigScanner)->scan(localContext());

    expect($result->findings)->toBe([])
        ->and(array_map(fn (SkippedCheck $skipped) => $skipped->checkId, $result->skipped))
        ->toBe(['config.debug-enabled', 'config.dashboard-open', 'config.app-key-missing', 'config.app-key-known']);
});
