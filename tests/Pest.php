<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\InstalledPackages;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Tests\TestCase;

pest()->extend(TestCase::class)->in('Feature');

/**
 * @param  list<string>  $packages
 */
function productionContext(array $packages = []): ScanContext
{
    return new ScanContext('production', '/app', InstalledPackages::fromList($packages));
}

/**
 * @param  list<string>  $packages
 */
function localContext(array $packages = []): ScanContext
{
    return new ScanContext('local', '/app', InstalledPackages::fromList($packages));
}
