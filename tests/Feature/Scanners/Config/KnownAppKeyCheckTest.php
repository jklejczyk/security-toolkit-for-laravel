<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\KnownAppKeyCheck;

function knownKeysFile(string $contents): string
{
    $path = tempnam(sys_get_temp_dir(), 'known-keys');
    file_put_contents($path, $contents);

    return $path;
}

it('is a production-only check', function () {
    expect((new KnownAppKeyCheck)->onlyInProduction())->toBeTrue()
        ->and((new KnownAppKeyCheck)->id())->toBe('config.app-key-known');
});

it('reports a key from the bundled list', function () {
    config(['app.key' => 'SomeRandomString']);

    $findings = iterator_to_array((new KnownAppKeyCheck)->run(productionContext()), false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->cwe)->toBe([321])
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')
        ->and($findings[0]->description)->toContain('Laravel 5.0 .env.example');
});

it('warns against keeping a leaked key as a previous key', function () {
    config(['app.key' => 'SomeRandomString']);

    $findings = iterator_to_array((new KnownAppKeyCheck)->run(productionContext()), false);

    // Laravel still decrypts and verifies signatures with APP_PREVIOUS_KEYS, so a leaked key must not go there.
    expect($findings[0]->remediation)->toContain('Do not put the leaked key in APP_PREVIOUS_KEYS');
});

it('does not report an unknown key', function () {
    config(['app.key' => 'base64:'.base64_encode(random_bytes(32))]);

    expect(iterator_to_array((new KnownAppKeyCheck)->run(productionContext()), false))->toBe([]);
});

it('leaves an empty key to the app-key-missing check', function () {
    config(['app.key' => '']);

    expect(iterator_to_array((new KnownAppKeyCheck)->run(productionContext()), false))->toBe([]);
});

it('parses comments, blank lines and uppercase hashes', function () {
    $hash = strtoupper(hash('sha256', 'base64:leaked'));
    $path = knownKeysFile("# header\n\n   \n{$hash}  # Some tutorial\n");
    config(['app.key' => 'base64:leaked']);

    $findings = iterator_to_array((new KnownAppKeyCheck($path))->run(productionContext()), false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('Some tutorial');
});

it('skips when the list cannot be read', function () {
    config(['app.key' => 'base64:anything']);

    iterator_to_array((new KnownAppKeyCheck('/nonexistent/known-app-keys.txt'))->run(productionContext()), false);
})->throws(CheckSkipped::class, 'could not be read');
