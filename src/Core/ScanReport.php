<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;

final readonly class ScanReport
{
    /**
     * Sorted from the most severe, then by rule ID.
     *
     * @var list<Finding>
     */
    public array $findings;

    /**
     * @param  list<Finding>  $findings
     * @param  list<SkippedCheck>  $skipped
     * @param  list<UnavailableScanner>  $unavailable
     * @param  list<ScannerFailure>  $errors
     * @param  list<Notice>  $notices
     * @param  list<CoverageEntry>  $coverage
     */
    public function __construct(
        array $findings = [],
        public array $skipped = [],
        public array $unavailable = [],
        public array $errors = [],
        public array $notices = [],
        public array $coverage = [],
    ) {
        usort(
            $findings,
            fn (Finding $a, Finding $b): int => [$b->severity->rank(), $a->ruleId] <=> [$a->severity->rank(), $b->ruleId],
        );

        $this->findings = $findings;
    }

    public function count(Severity $severity): int
    {
        return count(array_filter($this->findings, fn (Finding $finding): bool => $finding->severity === $severity));
    }

    /**
     * @return list<Finding>
     */
    public function findingsAtLeast(Severity $min): array
    {
        return array_values(array_filter(
            $this->findings,
            fn (Finding $finding): bool => $finding->severity->isAtLeast($min),
        ));
    }

    public function hasFindingsAtLeast(Severity $threshold): bool
    {
        return $this->findingsAtLeast($threshold) !== [];
    }

    public function hasErrors(): bool
    {
        return $this->errors !== [];
    }
}
