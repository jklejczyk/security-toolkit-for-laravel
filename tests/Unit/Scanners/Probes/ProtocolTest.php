<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Notice;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol\FindingCodec;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol\ProbeReport;

it('round-trips a finding without losing its classification', function () {
    $finding = new Finding(
        'routes.missing-authorization',
        Severity::Medium,
        'PUT /api/invoices/{invoice} does not authorize access',
        'description',
        'remediation',
        ['https://example.test'],
        new Location('app/Http/Controllers/InvoiceController.php', 42),
        [639],
        null,
        [],
        Confidence::Confirmed,
        new Reproduction(
            'idor',
            'existing',
            [['name' => 'A', 'model' => 'App\\Models\\User', 'id' => 12, 'owner' => 'App\\Models\\Company#3']],
            [new ReproductionStep('A', 'DELETE /api/invoices/41', 'App\\Models\\Invoice#41 (owner B)', [], '403 or 404', '204')],
        ),
    );

    $decoded = FindingCodec::decode(FindingCodec::encode($finding));

    expect($decoded->ruleId)->toBe($finding->ruleId)
        ->and($decoded->severity)->toBe($finding->severity)
        ->and($decoded->confidence)->toBe($finding->confidence)
        ->and($decoded->cwe)->toBe([639])
        ->and($decoded->location?->file)->toBe('app/Http/Controllers/InvoiceController.php')
        ->and($decoded->location?->line)->toBe(42)
        ->and($decoded->reproduction?->probe)->toBe('idor')
        ->and($decoded->reproduction?->actors)->toBe($finding->reproduction?->actors)
        ->and($decoded->reproduction?->steps[0]->received)->toBe('204');
});

it('round-trips a whole report through JSON', function () {
    $report = new ProbeReport(
        [new Finding('probes.idor', Severity::Medium, 'title', 'description', 'remediation', confidence: Confidence::Confirmed)],
        [new CoverageEntry('routes', 2, 1, [new CoverageTarget('GET /a', 'answered 403')], [new CoverageTarget('GET /b', 'no owner', 'set probes.owners')])],
        [new Notice('probes', 'no probes yet')],
    );

    $decoded = ProbeReport::fromJson($report->toJson());

    expect($decoded->findings)->toHaveCount(1)
        ->and($decoded->findings[0]->ruleId)->toBe('probes.idor')
        ->and($decoded->coverage[0]->checked)->toBe(2)
        ->and($decoded->coverage[0]->confirmed)->toBe(1)
        ->and($decoded->coverage[0]->notConfirmed[0]->target)->toBe('GET /a')
        ->and($decoded->coverage[0]->skipped[0]->hint)->toBe('set probes.owners')
        ->and($decoded->notices[0]->message)->toBe('no probes yet');
});

it('rejects invalid JSON', function () {
    ProbeReport::fromJson('not json');
})->throws(InvalidArgumentException::class);
