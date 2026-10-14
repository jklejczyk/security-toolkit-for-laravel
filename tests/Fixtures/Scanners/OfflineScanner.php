<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners;

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;
use LogicException;

final class OfflineScanner implements Scanner
{
    public function id(): string
    {
        return 'offline';
    }

    public function availability(): Availability
    {
        return Availability::unavailable('needs Docker');
    }

    public function scan(ScanContext $context): ScanResult
    {
        throw new LogicException('An unavailable scanner must not be run.');
    }
}
