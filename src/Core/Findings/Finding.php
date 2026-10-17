<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

use InvalidArgumentException;

final readonly class Finding
{
    public const CVE_PATTERN = '/^CVE-\d{4}-\d{4,}\z/';

    /**
     * @param  list<string>  $references
     * @param  list<int>  $cwe  CWE numbers, e.g. [614] for CWE-614
     * @param  ?Cvss  $cvss  set only when the finding can be exploited on its own; it then dictates the severity
     * @param  list<string>  $cve  CVE IDs the application is affected by, not CVEs mentioned for context
     * @param  Confidence  $confidence  suspected for conclusions drawn from code, confirmed when a probe reproduced the attack
     *
     * @throws InvalidArgumentException when the classification is inconsistent
     */
    public function __construct(
        public string $ruleId,
        public Severity $severity,
        public string $title,
        public string $description,
        public string $remediation,
        public array $references = [],
        public ?Location $location = null,
        public array $cwe = [],
        public ?Cvss $cvss = null,
        public array $cve = [],
        public Confidence $confidence = Confidence::Certain,
    ) {
        if ($cvss !== null && $cvss->severity() !== $severity) {
            throw new InvalidArgumentException(sprintf(
                'Finding %s is rated %s, but its CVSS score %.1f means %s.',
                $ruleId,
                $severity->value,
                $cvss->score,
                $cvss->severity()->value,
            ));
        }

        foreach ($cwe as $id) {
            if ($id < 1) {
                throw new InvalidArgumentException(sprintf('Finding %s has an invalid CWE number %d.', $ruleId, $id));
            }
        }

        foreach ($cve as $id) {
            if (preg_match(self::CVE_PATTERN, $id) !== 1) {
                throw new InvalidArgumentException(sprintf('Finding %s has an invalid CVE ID "%s".', $ruleId, $id));
            }
        }
    }
}
