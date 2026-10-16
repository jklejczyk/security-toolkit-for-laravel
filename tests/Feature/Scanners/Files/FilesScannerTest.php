<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Files\FilesScanner;

it('is registered by the service provider', function () {
    $ids = array_map(fn ($scanner) => $scanner->id(), app(ScannerRegistry::class)->all());

    expect($ids)->toContain('files');
});

it('skips every check outside production', function () {
    config(['filesystems.default' => 'public']);

    $result = (new FilesScanner)->scan(localContext());

    expect($result->findings)->toBe([])
        ->and(array_map(fn (SkippedCheck $skipped) => $skipped->checkId, $result->skipped))
        ->toBe(['files.private-storage-linked', 'files.default-disk-public']);
});
