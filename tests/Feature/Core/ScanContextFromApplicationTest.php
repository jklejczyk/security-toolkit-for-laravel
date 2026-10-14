<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\ScanContext;

it('builds the context from the running application', function () {
    $context = ScanContext::fromApplication(app());

    expect($context->environment)->toBe('testing')
        ->and($context->isProduction())->toBeFalse()
        ->and($context->basePath)->toBe(base_path())
        ->and($context->packages->isInstalled('laravel/framework'))->toBeTrue()
        ->and($context->packages->isInstalled('acme/does-not-exist'))->toBeFalse();
});
