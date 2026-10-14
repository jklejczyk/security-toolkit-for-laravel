<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Config;

use Jklejczyk\SecurityToolkit\Core\Checks\CheckScanner;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\AppKeyMissingCheck;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\DashboardOpenCheck;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\DebugEnabledCheck;
use Jklejczyk\SecurityToolkit\Scanners\Config\Checks\KnownAppKeyCheck;

final class ConfigScanner extends CheckScanner
{
    public function id(): string
    {
        return 'config';
    }

    protected function checks(): array
    {
        return [
            new DebugEnabledCheck,
            new DashboardOpenCheck,
            new AppKeyMissingCheck,
            new KnownAppKeyCheck,
        ];
    }
}
