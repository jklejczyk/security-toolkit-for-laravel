<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

final readonly class Finding
{
    /**
     * @param  list<string>  $references
     */
    public function __construct(
        public string $ruleId,
        public Severity $severity,
        public string $title,
        public string $description,
        public string $remediation,
        public array $references = [],
        public ?Location $location = null,
    ) {}
}
