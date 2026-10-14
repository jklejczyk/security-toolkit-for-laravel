<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\InstalledPackages;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

it('treats only the "production" environment as production', function (string $environment, bool $expected) {
    $context = new ScanContext($environment, '/app', InstalledPackages::fromList([]));

    expect($context->isProduction())->toBe($expected);
})->with([
    ['production', true],
    ['local', false],
    ['staging', false],
    ['prod', false],
]);

it('answers package queries from a given list', function () {
    $packages = InstalledPackages::fromList(['laravel/telescope']);

    expect($packages->isInstalled('laravel/telescope'))->toBeTrue()
        ->and($packages->isInstalled('laravel/horizon'))->toBeFalse();
});
