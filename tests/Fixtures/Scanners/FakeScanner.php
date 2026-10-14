<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Scanners;

use Jklejczyk\SecurityToolkit\Core\Availability;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Core\ScanResult;

final class FakeScanner implements Scanner
{
    public function id(): string
    {
        return 'fake';
    }

    public function availability(): Availability
    {
        return Availability::available();
    }

    public function scan(ScanContext $context): ScanResult
    {
        return new ScanResult([
            new Finding(
                'fake.rule',
                Severity::High,
                'Fake <finding> title',
                'Fake description.',
                'Fake remediation.',
                ['https://example.com/fake'],
                new Location('app/Fake.php', 12),
            ),
        ]);
    }
}
