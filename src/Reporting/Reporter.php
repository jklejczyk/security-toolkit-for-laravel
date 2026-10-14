<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Reporting;

use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanReport;
use Symfony\Component\Console\Output\OutputInterface;

interface Reporter
{
    public function render(ScanReport $report, Severity $minSeverity, OutputInterface $output): void;
}
