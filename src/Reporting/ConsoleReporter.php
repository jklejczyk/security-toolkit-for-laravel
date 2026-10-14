<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Reporting;

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanReport;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;

final class ConsoleReporter implements Reporter
{
    private const INDENT = '           ';

    public function render(ScanReport $report, Severity $minSeverity, OutputInterface $output): void
    {
        $visible = $report->findingsAtLeast($minSeverity);

        foreach ($visible as $finding) {
            $this->renderFinding($finding, $output);
        }

        if ($visible === []) {
            $output->writeln(' <info>No findings to show.</info>');
            $output->writeln('');
        }

        $output->writeln(' '.$this->summary($report, $minSeverity, count($report->findings) - count($visible)));

        if ($report->skipped !== []) {
            $output->writeln('');
            $output->writeln(' <comment>Skipped:</comment>');

            foreach ($report->skipped as $skipped) {
                $output->writeln(sprintf('   %s  %s', $this->escape($skipped->checkId), $this->escape($skipped->reason)));
            }
        }

        if ($report->unavailable !== []) {
            $output->writeln('');
            $output->writeln(' <comment>Unavailable scanners:</comment>');

            foreach ($report->unavailable as $unavailable) {
                $output->writeln(sprintf('   %s  %s', $this->escape($unavailable->scannerId), $this->escape($unavailable->reason)));
            }
        }

        if ($report->errors !== []) {
            $output->writeln('');
            $output->writeln(' <error>Errors:</error>');

            foreach ($report->errors as $error) {
                $output->writeln(sprintf('   %s  %s', $this->escape($error->scannerId), $this->escape($error->message)));
            }
        }
    }

    private function renderFinding(Finding $finding, OutputInterface $output): void
    {
        $output->writeln(sprintf(
            ' <%s> %s </> <options=bold>%s</>  <fg=gray>%s</>',
            $this->style($finding->severity),
            strtoupper($finding->severity->value),
            $this->escape($finding->title),
            $this->escape($finding->ruleId),
        ));

        if ($finding->location !== null) {
            $location = $finding->location->file.($finding->location->line !== null ? ':'.$finding->location->line : '');
            $output->writeln(self::INDENT.$this->escape($location));
        }

        $output->writeln(self::INDENT.$this->escape($finding->description));
        $output->writeln(self::INDENT.'Fix: '.$this->escape($finding->remediation));

        foreach ($finding->references as $reference) {
            $output->writeln(self::INDENT.'→ '.$this->escape($reference));
        }

        $output->writeln('');
    }

    private function summary(ScanReport $report, Severity $minSeverity, int $hidden): string
    {
        $counts = array_map(
            fn (Severity $severity): string => $report->count($severity).' '.$severity->value,
            Severity::cases(),
        );

        $parts = ['Summary: '.implode(', ', $counts)];

        if ($hidden > 0) {
            $parts[] = sprintf('%d hidden by --min-severity=%s', $hidden, $minSeverity->value);
        }

        $parts[] = sprintf('%d %s skipped', count($report->skipped), count($report->skipped) === 1 ? 'check' : 'checks');
        $parts[] = sprintf('%d %s unavailable', count($report->unavailable), count($report->unavailable) === 1 ? 'scanner' : 'scanners');

        if ($report->errors !== []) {
            $parts[] = sprintf('%d %s', count($report->errors), count($report->errors) === 1 ? 'error' : 'errors');
        }

        return implode(' · ', $parts);
    }

    private function style(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => 'fg=white;bg=red',
            Severity::High => 'fg=red',
            Severity::Medium => 'fg=yellow',
            Severity::Low => 'fg=cyan',
            Severity::Info => 'fg=gray',
        };
    }

    private function escape(string $text): string
    {
        return OutputFormatter::escape($text);
    }
}
