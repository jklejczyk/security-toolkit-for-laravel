<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners;

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;
use RuntimeException;

final class BrokenScanner implements Scanner
{
    public function id(): string
    {
        return 'broken';
    }

    public function availability(): Availability
    {
        return Availability::available();
    }

    public function scan(ScanContext $context): ScanResult
    {
        throw new RuntimeException('boom');
    }
}
