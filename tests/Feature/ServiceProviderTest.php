<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\SecurityToolkitServiceProvider;

it('registers the service provider', function () {
    expect(app()->getProviders(SecurityToolkitServiceProvider::class))->not->toBeEmpty();
});
