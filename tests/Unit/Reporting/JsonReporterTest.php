<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScannerFailure;
use Jklejczyk\SecurityToolkit\Core\ScanReport;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Core\UnavailableScanner;
use Jklejczyk\SecurityToolkit\Reporting\JsonReporter;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @return array<string, mixed>
 */
function renderJson(ScanReport $report, Severity $min = Severity::Info): array
{
    $output = new BufferedOutput;
    (new JsonReporter)->render($report, $min, $output);

    return json_decode($output->fetch(), true, flags: JSON_THROW_ON_ERROR);
}

it('renders the whole report as a single JSON document', function () {
    $json = renderJson(new ScanReport(
        [new Finding('a.rule', Severity::High, 'Title <x>', 'Desc', 'Fix', ['https://example.com'], new Location('app/A.php', 3))],
        [new SkippedCheck('a.prod', 'reason')],
        [new UnavailableScanner('zap', 'needs Docker')],
        [new ScannerFailure('broken', 'boom')],
    ));

    expect($json)->toBe([
        'findings' => [[
            'rule' => 'a.rule',
            'severity' => 'high',
            'title' => 'Title <x>',
            'description' => 'Desc',
            'remediation' => 'Fix',
            'references' => ['https://example.com'],
            'location' => ['file' => 'app/A.php', 'line' => 3],
        ]],
        'skipped' => [['check' => 'a.prod', 'reason' => 'reason']],
        'unavailable' => [['scanner' => 'zap', 'reason' => 'needs Docker']],
        'errors' => [['scanner' => 'broken', 'message' => 'boom']],
        'summary' => ['critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 0, 'info' => 0, 'hidden' => 0],
    ]);
});

it('uses null for a missing location', function () {
    $json = renderJson(new ScanReport([new Finding('a.rule', Severity::Low, 'T', 'D', 'R')]));

    expect($json['findings'][0]['location'])->toBeNull();
});

it('filters findings by minimum severity but keeps full counts', function () {
    $json = renderJson(new ScanReport([
        new Finding('a.high', Severity::High, 'T', 'D', 'R'),
        new Finding('a.low', Severity::Low, 'T', 'D', 'R'),
    ]), Severity::High);

    expect($json['findings'])->toHaveCount(1)
        ->and($json['summary']['low'])->toBe(1)
        ->and($json['summary']['hidden'])->toBe(1);
});
