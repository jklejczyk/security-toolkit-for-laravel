<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Reporting;

use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Notice;
use Jklejczyk\SecurityToolkit\Core\ScannerFailure;
use Jklejczyk\SecurityToolkit\Core\ScanReport;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Core\UnavailableScanner;
use Symfony\Component\Console\Output\OutputInterface;

final class JsonReporter implements Reporter
{
    public function render(ScanReport $report, Severity $minSeverity, OutputInterface $output): void
    {
        $visible = $report->findingsAtLeast($minSeverity);

        $summary = [];
        foreach (Severity::cases() as $severity) {
            $summary[$severity->value] = $report->count($severity);
        }
        $summary['hidden'] = count($report->findings) - count($visible);

        $data = [
            'findings' => array_map(fn (Finding $finding): array => [
                'rule' => $finding->ruleId,
                'severity' => $finding->severity->value,
                'confidence' => $finding->confidence->value,
                'title' => $finding->title,
                'description' => $finding->description,
                'remediation' => $finding->remediation,
                'references' => $finding->references,
                'cwe' => array_map(fn (int $cwe): string => 'CWE-'.$cwe, $finding->cwe),
                'cvss' => $finding->cvss === null ? null : [
                    'version' => Cvss::VERSION,
                    'vector' => $finding->cvss->vector,
                    'score' => $finding->cvss->score,
                ],
                'cve' => $finding->cve,
                'location' => $finding->location === null ? null : [
                    'file' => $finding->location->file,
                    'line' => $finding->location->line,
                ],
                'reproduction' => $finding->reproduction === null ? null : [
                    'probe' => $finding->reproduction->probe,
                    'data' => $finding->reproduction->data,
                    'actors' => $finding->reproduction->actors,
                    'steps' => array_map(fn (ReproductionStep $step): array => [
                        'actor' => $step->actor,
                        'request' => $step->request,
                        'resource' => $step->resource,
                        'fields' => $step->fields,
                        'expected' => $step->expected,
                        'received' => $step->received,
                    ], $finding->reproduction->steps),
                ],
            ], $visible),
            'skipped' => array_map(fn (SkippedCheck $skipped): array => [
                'check' => $skipped->checkId,
                'reason' => $skipped->reason,
            ], $report->skipped),
            'unavailable' => array_map(fn (UnavailableScanner $unavailable): array => [
                'scanner' => $unavailable->scannerId,
                'reason' => $unavailable->reason,
            ], $report->unavailable),
            'errors' => array_map(fn (ScannerFailure $error): array => [
                'scanner' => $error->scannerId,
                'message' => $error->message,
            ], $report->errors),
            'notices' => array_map(fn (Notice $notice): array => [
                'scanner' => $notice->scannerId,
                'message' => $notice->message,
            ], $report->notices),
            'coverage' => array_map(fn (CoverageEntry $entry): array => [
                'probe' => $entry->probe,
                'checked' => $entry->checked,
                'confirmed' => $entry->confirmed,
                'not_confirmed' => array_map($this->target(...), $entry->notConfirmed),
                'skipped' => array_map($this->target(...), $entry->skipped),
            ], $report->coverage),
            'summary' => $summary,
        ];

        $output->writeln(
            json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
            OutputInterface::OUTPUT_RAW,
        );
    }

    /**
     * @return array{target: string, reason: string, hint: ?string}
     */
    private function target(CoverageTarget $target): array
    {
        return ['target' => $target->target, 'reason' => $target->reason, 'hint' => $target->hint];
    }
}
