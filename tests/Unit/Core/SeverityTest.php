<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Severity;

it('lists severities from most to least severe', function () {
    expect(Severity::cases())->toBe([
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]);
});

it('compares severities against a threshold', function () {
    expect(Severity::Critical->isAtLeast(Severity::High))->toBeTrue()
        ->and(Severity::High->isAtLeast(Severity::High))->toBeTrue()
        ->and(Severity::Medium->isAtLeast(Severity::High))->toBeFalse()
        ->and(Severity::Info->isAtLeast(Severity::Info))->toBeTrue();
});

it('is backed by lowercase names', function () {
    expect(Severity::from('critical'))->toBe(Severity::Critical)
        ->and(Severity::tryFrom('CRITICAL'))->toBeNull();
});
