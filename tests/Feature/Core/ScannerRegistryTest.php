<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\UnknownScanner;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners\BrokenScanner;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners\FakeScanner;

/**
 * @param  list<Scanner>  $scanners
 * @return list<string>
 */
function scannerIds(array $scanners): array
{
    return array_map(fn (Scanner $scanner) => $scanner->id(), $scanners);
}

it('is a singleton in the container', function () {
    expect(app(ScannerRegistry::class))->toBe(app(ScannerRegistry::class));
});

it('resolves registered scanners through the container', function () {
    $registry = app(ScannerRegistry::class);
    $registry->register(FakeScanner::class);
    $registry->register(BrokenScanner::class);

    expect(scannerIds($registry->all()))->toContain('fake', 'broken');
});

it('ignores duplicate registrations', function () {
    $registry = app(ScannerRegistry::class);
    $registry->register(FakeScanner::class);
    $registry->register(FakeScanner::class);

    expect(array_count_values(scannerIds($registry->all()))['fake'])->toBe(1);
});

it('selects scanners by id', function () {
    $registry = app(ScannerRegistry::class);
    $registry->register(FakeScanner::class);
    $registry->register(BrokenScanner::class);

    expect(scannerIds($registry->only(['fake'])))->toBe(['fake']);
});

it('rejects unknown ids', function () {
    $registry = app(ScannerRegistry::class);
    $registry->register(FakeScanner::class);

    $registry->only(['fake', 'nope', 'missing']);
})->throws(UnknownScanner::class, 'Unknown scanner(s): nope, missing');

it('rejects a registered class that is not a scanner', function () {
    $registry = app(ScannerRegistry::class);
    $registry->register(stdClass::class);

    $registry->all();
})->throws(LogicException::class, 'stdClass must implement Jklejczyk\SecurityToolkit\Core\Contracts\Scanner');
