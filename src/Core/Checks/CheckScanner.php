<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Checks;

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;

abstract class CheckScanner implements Scanner
{
    /**
     * @return list<Check>
     */
    abstract protected function checks(): array;

    public function availability(): Availability
    {
        return Availability::available();
    }

    public function scan(ScanContext $context): ScanResult
    {
        $findings = [];
        $skipped = [];

        foreach ($this->checks() as $check) {
            if ($check->onlyInProduction() && ! $context->isProduction()) {
                $skipped[] = new SkippedCheck(
                    $check->id(),
                    sprintf('only relevant in production (current environment: %s)', $context->environment),
                );

                continue;
            }

            try {
                foreach ($check->run($context) as $finding) {
                    $findings[] = $finding;
                }
            } catch (CheckSkipped $skip) {
                $skipped[] = new SkippedCheck($check->id(), $skip->getMessage());
            }
        }

        return new ScanResult($findings, $skipped);
    }
}
