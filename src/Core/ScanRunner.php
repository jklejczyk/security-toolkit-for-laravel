<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Throwable;

final class ScanRunner
{
    /**
     * @param  list<Scanner>  $scanners
     */
    public function run(array $scanners, ScanContext $context): ScanReport
    {
        $findings = [];
        $skipped = [];
        $unavailable = [];
        $errors = [];
        $notices = [];
        $coverage = [];

        foreach ($scanners as $scanner) {
            $availability = $scanner->availability();

            if (! $availability->available) {
                $unavailable[] = new UnavailableScanner($scanner->id(), $availability->reason ?? 'unavailable');

                continue;
            }

            try {
                $result = $scanner->scan($context);
            } catch (Throwable $exception) {
                $errors[] = new ScannerFailure($scanner->id(), $exception->getMessage());

                continue;
            }

            array_push($findings, ...$result->findings);
            array_push($skipped, ...$result->skipped);
            array_push($notices, ...$result->notices);
            array_push($coverage, ...$result->coverage);
        }

        return new ScanReport($findings, $skipped, $unavailable, $errors, $notices, $coverage);
    }
}
