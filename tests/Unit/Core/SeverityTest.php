<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Severity;

it('lists severities from most to least severe, with unrated last', function () {
    expect(Severity::cases())->toBe([
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
        Severity::Unknown,
    ]);
});

it('treats an unrated severity as meeting every threshold and sorts it last', function () {
    expect(Severity::Unknown->isAtLeast(Severity::Critical))->toBeTrue()
        ->and(Severity::Unknown->rank())->toBeLessThan(Severity::Info->rank())
        ->and(Severity::thresholds())->toBe([
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
