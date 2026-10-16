<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Dependencies;

use Illuminate\Support\Str;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use JsonException;
use RuntimeException;

/**
 * Maps the output of composer audit --format=json to findings.
 */
final class AuditFindings
{
    /**
     * @return list<Finding>
     *
     * @throws RuntimeException when Composer did not print an audit report
     */
    public function fromOutput(string $output, string $errorOutput = ''): array
    {
        $report = self::decode($output);

        // An older Composer on a newer PHP may print notices before the report, which starts on its own line.
        if ($report === null && preg_match('/^\{/m', $output, $match, PREG_OFFSET_CAPTURE) === 1) {
            $report = self::decode(substr($output, $match[0][1]));
        }

        // Composer before 2.7 does not report abandoned packages.
        if (! is_array($report) || ! is_array($report['advisories'] ?? null) || ! is_array($report['abandoned'] ?? [])) {
            $details = trim($errorOutput) !== '' ? $errorOutput : $output;

            throw new RuntimeException(sprintf('composer audit did not return a JSON report: %s', Str::limit(trim($details), 500)));
        }

        $findings = [];

        // An empty list is printed as [], a non-empty one as an object keyed by package name.
        foreach ($report['advisories'] as $package => $advisories) {
            foreach (is_string($package) && is_array($advisories) ? $advisories : [] as $advisory) {
                if (is_array($advisory)) {
                    $findings[] = $this->vulnerable($package, $advisory);
                }
            }
        }

        foreach ($report['abandoned'] ?? [] as $package => $replacement) {
            if (is_string($package)) {
                $findings[] = $this->abandoned($package, is_string($replacement) && $replacement !== '' ? $replacement : null);
            }
        }

        return $findings;
    }

    /**
     * @param  array<mixed>  $advisory
     */
    private function vulnerable(string $package, array $advisory): Finding
    {
        $title = self::title($package, self::string($advisory, 'title'));
        $cve = self::string($advisory, 'cve');
        $affected = self::string($advisory, 'affectedVersions');
        $severity = self::severity(self::string($advisory, 'severity'));

        $description = sprintf('The installed version of %s is affected by a published security advisory: %s.', $package, rtrim($title, '.'));

        $isCve = $cve !== null && preg_match(Finding::CVE_PATTERN, $cve) === 1;

        // Anything else in the cve field (for example a GHSA ID) stays readable without breaking the finding.
        if ($cve !== null && ! $isCve) {
            $description .= sprintf(' Identifier: %s.', $cve);
        }

        if ($affected !== null) {
            $description .= sprintf(' Affected versions: %s.', $affected);
        }

        if ($severity === Severity::Unknown) {
            $description .= ' The advisory source did not publish a severity, so read the advisory to judge the impact.';
        }

        $references = [];

        if (($link = self::string($advisory, 'link')) !== null) {
            $references[] = $link;
        }

        if ($isCve) {
            $references[] = 'https://www.cve.org/CVERecord?id='.$cve;
        }

        return new Finding(
            'dependencies.vulnerable-package',
            $severity,
            sprintf('%s: %s', $package, $title),
            $description,
            sprintf('Update %1$s to a version outside the affected range with composer update %1$s. If it is not a direct dependency, run composer why %1$s and update the package that requires it.', $package),
            $references,
            new Location('composer.lock'),
            cwe: [1395],
            cve: $isCve ? [$cve] : [],
        );
    }

    private function abandoned(string $package, ?string $replacement): Finding
    {
        return new Finding(
            'dependencies.abandoned-package',
            Severity::Info,
            sprintf('%s is abandoned', $package),
            sprintf('The maintainers of %s no longer support it, so future security issues may never be fixed or even published as advisories.', $package),
            $replacement !== null
                ? sprintf('Replace it with %s, which the maintainers recommend.', $replacement)
                : 'Find a maintained alternative and plan the migration.',
            ['https://getcomposer.org/doc/03-cli.md#audit'],
            new Location('composer.lock'),
            cwe: [1104],
        );
    }

    private static function decode(string $json): mixed
    {
        try {
            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
    }

    /**
     * The advisory title without stray spaces or a leading package name, which the finding title adds.
     */
    private static function title(string $package, ?string $title): string
    {
        $title = trim($title ?? '');
        foreach ([$package, Str::afterLast($package, '/')] as $prefix) {
            if (stripos($title, $prefix.':') === 0) {
                $title = ltrim(substr($title, strlen($prefix) + 1));
            }
        }

        return $title !== '' ? $title : 'Security advisory';
    }

    private static function severity(?string $value): Severity
    {
        return match ($value === null ? null : strtolower($value)) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'medium', 'moderate' => Severity::Medium,
            'low' => Severity::Low,
            default => Severity::Unknown,
        };
    }

    /**
     * @param  array<mixed>  $data
     */
    private static function string(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
