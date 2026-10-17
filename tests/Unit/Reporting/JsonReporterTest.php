<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Notice;
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
            'confidence' => 'certain',
            'title' => 'Title <x>',
            'description' => 'Desc',
            'remediation' => 'Fix',
            'references' => ['https://example.com'],
            'cwe' => [],
            'cvss' => null,
            'cve' => [],
            'location' => ['file' => 'app/A.php', 'line' => 3],
            'reproduction' => null,
        ]],
        'skipped' => [['check' => 'a.prod', 'reason' => 'reason']],
        'unavailable' => [['scanner' => 'zap', 'reason' => 'needs Docker']],
        'errors' => [['scanner' => 'broken', 'message' => 'boom']],
        'notices' => [],
        'summary' => ['critical' => 0, 'high' => 1, 'medium' => 0, 'low' => 0, 'info' => 0, 'unknown' => 0, 'hidden' => 0],
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

it('renders the classification of a finding', function () {
    $json = renderJson(new ScanReport([
        new Finding(
            'a.rule',
            Severity::High,
            'T',
            'D',
            'R',
            cwe: [209, 489],
            cvss: Cvss::fromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
            cve: ['CVE-2021-3129'],
        ),
    ]));

    expect($json['findings'][0]['cwe'])->toBe(['CWE-209', 'CWE-489'])
        ->and($json['findings'][0]['cvss'])->toBe([
            'version' => '3.1',
            'vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'score' => 7.5,
        ])
        ->and($json['findings'][0]['cve'])->toBe(['CVE-2021-3129']);
});

it('includes how sure the toolkit is about each finding', function () {
    $output = new BufferedOutput;
    (new JsonReporter)->render(new ScanReport([
        new Finding('a.rule', Severity::Medium, 'T', 'D', 'R', confidence: Confidence::Suspected),
    ]), Severity::Info, $output);

    expect(json_decode($output->fetch(), true)['findings'][0]['confidence'])->toBe('suspected');
});

it('lists notices separately from findings', function () {
    $json = renderJson(new ScanReport(notices: [new Notice('probes', 'no probes yet')]));

    expect($json['notices'])->toBe([['scanner' => 'probes', 'message' => 'no probes yet']])
        ->and($json['findings'])->toBe([]);
});

it('renders the reproduction of a confirmed finding', function () {
    $finding = (new Finding('a.rule', Severity::High, 'T', 'D', 'R'))->withConfirmation(sampleReproduction(), 'it worked.');

    expect(renderJson(new ScanReport([$finding]))['findings'][0]['reproduction'])->toBe([
        'probe' => 'idor',
        'data' => 'factories',
        'actors' => [['name' => 'A', 'model' => 'App\\Models\\User', 'id' => 12, 'owner' => 'App\\Models\\Company#3']],
        'steps' => [[
            'actor' => 'A',
            'request' => 'DELETE /api/invoices/41',
            'resource' => 'App\\Models\\Invoice#41 (owner B)',
            'fields' => [],
            'expected' => '403 or 404',
            'received' => '204 (Invoice #41 deleted)',
        ]],
    ]);
});
