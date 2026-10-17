<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScannerFailure;
use Jklejczyk\SecurityToolkit\Core\ScanReport;

function reportFinding(string $ruleId, Severity $severity): Finding
{
    return new Finding($ruleId, $severity, 'Title', 'Description', 'Remediation');
}

it('sorts findings by severity and then by rule id', function () {
    $report = new ScanReport([
        reportFinding('b.low', Severity::Low),
        reportFinding('b.critical', Severity::Critical),
        reportFinding('a.critical', Severity::Critical),
        reportFinding('a.medium', Severity::Medium),
    ]);

    expect(array_map(fn (Finding $finding) => $finding->ruleId, $report->findings))
        ->toBe(['a.critical', 'b.critical', 'a.medium', 'b.low']);
});

it('counts and filters findings by severity', function () {
    $report = new ScanReport([
        reportFinding('a', Severity::Critical),
        reportFinding('b', Severity::High),
        reportFinding('c', Severity::High),
        reportFinding('d', Severity::Low),
    ]);

    expect($report->count(Severity::High))->toBe(2)
        ->and($report->count(Severity::Info))->toBe(0)
        ->and($report->findingsAtLeast(Severity::High))->toHaveCount(3)
        ->and($report->hasFindingsAtLeast(Severity::Critical))->toBeTrue()
        ->and((new ScanReport([reportFinding('d', Severity::Low)]))->hasFindingsAtLeast(Severity::Medium))->toBeFalse();
});

it('reports whether any scanner failed', function () {
    expect((new ScanReport)->hasErrors())->toBeFalse()
        ->and((new ScanReport(errors: [new ScannerFailure('x', 'boom')]))->hasErrors())->toBeTrue();
});

it('sorts unrated findings last but keeps them above every threshold', function () {
    $report = new ScanReport([
        reportFinding('a.unknown', Severity::Unknown),
        reportFinding('b.info', Severity::Info),
    ]);

    expect(array_map(fn (Finding $finding) => $finding->ruleId, $report->findings))->toBe(['b.info', 'a.unknown'])
        ->and($report->findingsAtLeast(Severity::Critical))->toHaveCount(1)
        ->and($report->count(Severity::Unknown))->toBe(1);
});

function locatedFinding(string $ruleId, Confidence $confidence, ?Location $location = new Location('app/A.php', 10)): Finding
{
    return new Finding($ruleId, Severity::Medium, 'Title', $confidence->value, 'Remediation', [], $location, confidence: $confidence);
}

it('replaces a suspicion with the confirmed finding of the same rule and location', function () {
    $report = new ScanReport([
        locatedFinding('routes.missing-authorization', Confidence::Suspected),
        locatedFinding('routes.missing-authorization', Confidence::Confirmed),
    ]);

    expect($report->findings)->toHaveCount(1)
        ->and($report->findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('keeps suspicions of another rule or at another location', function () {
    $report = new ScanReport([
        locatedFinding('routes.missing-authorization', Confidence::Confirmed),
        locatedFinding('routes.unscoped-nested-binding', Confidence::Suspected),
        locatedFinding('routes.missing-authorization', Confidence::Suspected, new Location('app/A.php', 11)),
        locatedFinding('routes.missing-authorization', Confidence::Suspected, new Location('app/B.php', 10)),
    ]);

    expect($report->findings)->toHaveCount(4);
});

it('keeps a suspicion nothing confirms', function () {
    expect((new ScanReport([locatedFinding('routes.missing-authorization', Confidence::Suspected)]))->findings)->toHaveCount(1);
});

it('replaces a certain finding a probe confirmed, so it is not reported twice', function () {
    $report = new ScanReport([
        locatedFinding('routes.csrf-excluded', Confidence::Certain),
        locatedFinding('routes.csrf-excluded', Confidence::Confirmed),
    ]);

    expect($report->findings)->toHaveCount(1)
        ->and($report->findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('keeps every confirmed finding at the same location', function () {
    $report = new ScanReport([
        locatedFinding('a.rule', Confidence::Confirmed),
        locatedFinding('a.rule', Confidence::Confirmed),
    ]);

    expect($report->findings)->toHaveCount(2);
});

it('never merges findings without a location', function () {
    $report = new ScanReport([
        locatedFinding('a.rule', Confidence::Suspected, null),
        locatedFinding('a.rule', Confidence::Confirmed, null),
    ]);

    expect($report->findings)->toHaveCount(2);
});
