<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;

it('computes the base score of a vector', function (string $vector, float $score) {
    expect(Cvss::fromVector($vector)->score)->toBe($score);
})->with([
    'NVD: unauthenticated network RCE' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    'NVD: reflected XSS, scope changed' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    'NVD: local privilege escalation' => ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    'scope changed, capped at 10' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    'scope changed, low privileges' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
    'scope changed, high privileges' => ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', 9.1],
    'config.app-key-known' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 9.1],
    'config.debug-enabled' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
    'config.app-key-missing' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N', 5.3],
    'config.dashboard-open, Horizon' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N', 7.1],
    'config.dashboard-open, Telescope and Log Viewer' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L', 7.6],
    'config.dashboard-open, Pulse' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 4.3],
    'files.private-storage-linked, private files' => ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
    'files.default-disk-public' => ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', 3.7],
    'auth.session-cookie-insecure' => ['CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N', 6.4],
]);

it('maps the score to a severity band', function (string $vector, float $score, Severity $severity) {
    $cvss = Cvss::fromVector($vector);

    expect($cvss->score)->toBe($score)
        ->and($cvss->severity())->toBe($severity);
})->with([
    'top of low' => ['CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L', 3.9, Severity::Low],
    'bottom of medium' => ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N', 4.0, Severity::Medium],
    'top of medium' => ['CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N', 6.9, Severity::Medium],
    'bottom of high' => ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L', 7.0, Severity::High],
    'top of high' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L', 8.9, Severity::High],
    'bottom of critical' => ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H', 9.0, Severity::Critical],
]);

it('keeps the vector and exposes its metrics without the prefix', function () {
    $cvss = Cvss::fromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');

    expect($cvss->vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
        ->and($cvss->metrics())->toBe('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
        ->and(Cvss::VERSION)->toBe('3.1');
});

it('rejects a vector it cannot score', function (string $vector, string $message) {
    expect(fn () => Cvss::fromVector($vector))->toThrow(InvalidArgumentException::class, $message);
})->with([
    'CVSS 3.0' => ['CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'only CVSS:3.1'],
    'no prefix' => ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'only CVSS:3.1'],
    'missing metric' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H', 'exactly the base metrics'],
    'temporal metric' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F', 'exactly the base metrics'],
    'wrong order' => ['CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H', 'expected AV'],
    'duplicate metric' => ['CVSS:3.1/AV:N/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H', 'expected AC'],
    'unknown value' => ['CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'invalid value "X" for AV'],
    'no impact' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 'no impact'],
]);
