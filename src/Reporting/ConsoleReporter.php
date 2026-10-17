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

        foreach ($this->group($visible) as $group) {
            count($group) === 1
                ? $this->renderFinding($group[0], $output)
                : $this->renderGroup($group, $output);
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

        $classification = $this->classification($finding);

        if ($classification !== '') {
            $output->writeln(self::INDENT.'<fg=gray>'.$this->escape($classification).'</>');
        }

        $output->writeln(self::INDENT.$this->escape($finding->description));
        $output->writeln(self::INDENT.'Fix: '.$this->escape($finding->remediation));

        foreach ($finding->references as $reference) {
            $output->writeln(self::INDENT.'→ '.$this->escape($reference));
        }

        $output->writeln('');
    }

    /**
     * Findings of the same rule with the same fix, e.g. every advisory of one package, in the
     * order of their first finding.
     *
     * @param  list<Finding>  $findings
     * @return list<non-empty-list<Finding>>
     */
    private function group(array $findings): array
    {
        $groups = [];

        foreach ($findings as $finding) {
            $groups[$finding->ruleId."\0".$finding->remediation][] = $finding;
        }

        return array_values($groups);
    }

    /**
     * @param  non-empty-list<Finding>  $group
     */
    private function renderGroup(array $group, OutputInterface $output): void
    {
        usort($group, fn (Finding $a, Finding $b): int => $b->severity->rank() <=> $a->severity->rank());
        $first = $group[0];

        $output->writeln(sprintf(
            ' <%s> %s </> <options=bold>%s</>  <fg=gray>%s</>',
            $this->style($first->severity),
            strtoupper($first->severity->value),
            $this->escape(sprintf('%d findings: %s', count($group), $this->commonTitle($group))),
            $this->escape($first->ruleId),
        ));

        if ($first->location !== null) {
            $location = $first->location->file.($first->location->line !== null ? ':'.$first->location->line : '');
            $output->writeln(self::INDENT.$this->escape($location));
        }

        foreach ($group as $finding) {
            $output->writeln(self::INDENT.sprintf(
                '<%s>%s</> %s',
                $this->style($finding->severity),
                str_pad(strtoupper($finding->severity->value), 8),
                $this->escape(implode('  ', [$finding->title, ...$finding->cve])),
            ));
        }

        $output->writeln(self::INDENT.'Fix: '.$this->escape($first->remediation));

        foreach (array_unique(array_merge(...array_map(fn (Finding $finding): array => $finding->references, $group))) as $reference) {
            $output->writeln(self::INDENT.'→ '.$this->escape($reference));
        }

        $output->writeln('');
    }

    /**
     * The part before ": " shared by every title ("dompdf/dompdf: …"), or the first title.
     *
     * @param  non-empty-list<Finding>  $group
     */
    private function commonTitle(array $group): string
    {
        $prefix = strstr($group[0]->title, ': ', true);

        foreach ($group as $finding) {
            if ($prefix === false || ! str_starts_with($finding->title, $prefix.': ')) {
                return $group[0]->title;
            }
        }

        return $prefix;
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

    /**
     * "CWE-209 · CVSS 7.5 AV:N/… · CVE-2021-3129", with only the parts the finding has.
     */
    private function classification(Finding $finding): string
    {
        $parts = array_map(fn (int $cwe): string => 'CWE-'.$cwe, $finding->cwe);

        if ($finding->cvss !== null) {
            $parts[] = sprintf('CVSS %.1f %s', $finding->cvss->score, $finding->cvss->metrics());
        }

        return implode(' · ', [...$parts, ...$finding->cve]);
    }

    private function style(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => 'fg=white;bg=red',
            Severity::High => 'fg=red',
            Severity::Medium => 'fg=yellow',
            Severity::Low => 'fg=cyan',
            Severity::Info => 'fg=gray',
            Severity::Unknown => 'fg=magenta',
        };
    }

    private function escape(string $text): string
    {
        return OutputFormatter::escape($text);
    }
}
