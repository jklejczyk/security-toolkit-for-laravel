<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Console;

use Illuminate\Console\Command;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\ScanRunner;
use Jklejczyk\SecurityToolkit\Core\UnknownScanner;
use Jklejczyk\SecurityToolkit\Reporting\ConsoleReporter;
use Jklejczyk\SecurityToolkit\Reporting\JsonReporter;

final class ScanCommand extends Command
{
    protected $signature = 'security:scan
        {--only= : Comma-separated IDs of the scanners to run}
        {--list : List registered scanners without scanning}
        {--format=console : Output format: console or json}
        {--min-severity=info : Show only findings of this severity or higher}
        {--fail-on=high : Exit with code 1 when a finding of this severity or higher exists, or "none"}';

    protected $description = 'Scan the application for security issues';

    public function handle(ScannerRegistry $registry, ScanRunner $runner): int
    {
        if ($this->option('list') === true) {
            $this->listScanners($registry);

            return self::SUCCESS;
        }

        $format = $this->stringOption('format');
        $minSeverity = $this->threshold('min-severity');
        $failOnOption = $this->stringOption('fail-on');
        $failOn = $this->threshold('fail-on');

        if (! in_array($format, ['console', 'json'], true)) {
            return $this->invalid('The --format option must be "console" or "json".');
        }

        if ($minSeverity === null) {
            return $this->invalid('The --min-severity option must be one of: '.$this->severities().'.');
        }

        if ($failOn === null && $failOnOption !== 'none') {
            return $this->invalid('The --fail-on option must be one of: '.$this->severities().', none.');
        }

        try {
            $scanners = $this->selectScanners($registry);
        } catch (UnknownScanner $exception) {
            return $this->invalid($exception->getMessage());
        }

        if ($scanners === null) {
            return $this->invalid('The --only option must list at least one scanner ID.');
        }

        $report = $runner->run($scanners, ScanContext::fromApplication($this->laravel));

        $reporter = $format === 'json' ? new JsonReporter : new ConsoleReporter;
        $reporter->render($report, $minSeverity, $this->output);

        if ($report->hasErrors()) {
            return self::INVALID;
        }

        if ($failOn !== null && $report->hasFindingsAtLeast($failOn)) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * @return list<Scanner>|null null when --only is given without any ID
     *
     * @throws UnknownScanner
     */
    private function selectScanners(ScannerRegistry $registry): ?array
    {
        $only = $this->option('only');

        if (! is_string($only)) {
            // A bare --only (no value) is a mistake, e.g. an empty CI variable, not "scan everything".
            return $this->input->hasParameterOption('--only') ? null : $registry->all();
        }

        $ids = array_values(array_filter(
            array_map(trim(...), explode(',', $only)),
            fn (string $id): bool => $id !== '',
        ));

        return $ids === [] ? null : $registry->only($ids);
    }

    private function listScanners(ScannerRegistry $registry): void
    {
        $rows = array_map(function (Scanner $scanner): array {
            $availability = $scanner->availability();

            return [
                $scanner->id(),
                $availability->available ? 'available' : 'unavailable: '.$availability->reason,
                $scanner::class,
            ];
        }, $registry->all());

        $this->table(['Scanner', 'Status', 'Class'], $rows);
    }

    private function stringOption(string $name): string
    {
        $value = $this->option($name);

        return is_string($value) ? $value : '';
    }

    private function threshold(string $name): ?Severity
    {
        $severity = Severity::tryFrom($this->stringOption($name));

        return in_array($severity, Severity::thresholds(), true) ? $severity : null;
    }

    private function severities(): string
    {
        return implode(', ', array_map(fn (Severity $severity): string => $severity->value, Severity::thresholds()));
    }

    private function invalid(string $message): int
    {
        $this->output->getErrorStyle()->error($message);

        return self::INVALID;
    }
}
