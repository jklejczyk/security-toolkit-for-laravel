<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Notice;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;
use Jklejczyk\SecurityToolkit\Core\ScanRunner;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;

/**
 * @param  Closure(): ScanResult  $scan
 */
function runnerScanner(string $id, Closure $scan, ?Availability $availability = null): Scanner
{
    return new class($id, $scan, $availability ?? Availability::available()) implements Scanner
    {
        public function __construct(
            private string $id,
            private Closure $scan,
            private Availability $availability,
        ) {}

        public function id(): string
        {
            return $this->id;
        }

        public function availability(): Availability
        {
            return $this->availability;
        }

        public function scan(ScanContext $context): ScanResult
        {
            return ($this->scan)();
        }
    };
}

it('merges findings and skips from all scanners', function () {
    $report = (new ScanRunner)->run([
        runnerScanner('a', fn () => new ScanResult(
            [new Finding('a.rule', Severity::High, 'T', 'D', 'R')],
            [new SkippedCheck('a.other', 'reason')],
        )),
        runnerScanner('b', fn () => new ScanResult([new Finding('b.rule', Severity::Low, 'T', 'D', 'R')])),
    ], localContext());

    expect($report->findings)->toHaveCount(2)
        ->and($report->skipped)->toHaveCount(1)
        ->and($report->errors)->toBe([]);
});

it('does not scan unavailable scanners and records the reason', function () {
    $report = (new ScanRunner)->run([
        runnerScanner('zap', fn () => throw new RuntimeException('must not run'), Availability::unavailable('Docker is not available')),
    ], localContext());

    expect($report->unavailable)->toHaveCount(1)
        ->and($report->unavailable[0]->scannerId)->toBe('zap')
        ->and($report->unavailable[0]->reason)->toBe('Docker is not available')
        ->and($report->errors)->toBe([]);
});

it('records a failing scanner and keeps running the others', function () {
    $report = (new ScanRunner)->run([
        runnerScanner('broken', fn () => throw new RuntimeException('boom')),
        runnerScanner('ok', fn () => new ScanResult([new Finding('ok.rule', Severity::High, 'T', 'D', 'R')])),
    ], localContext());

    expect($report->errors)->toHaveCount(1)
        ->and($report->errors[0]->scannerId)->toBe('broken')
        ->and($report->errors[0]->message)->toBe('boom')
        ->and($report->findings)->toHaveCount(1);
});

it('collects notices from every scanner', function () {
    $report = (new ScanRunner)->run([
        runnerScanner('a', fn () => new ScanResult(notices: [new Notice('a', 'hello')])),
        runnerScanner('b', fn () => new ScanResult),
    ], localContext());

    expect($report->notices)->toHaveCount(1)
        ->and($report->notices[0]->scannerId)->toBe('a')
        ->and($report->notices[0]->message)->toBe('hello');
});
