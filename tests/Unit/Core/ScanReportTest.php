<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
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
