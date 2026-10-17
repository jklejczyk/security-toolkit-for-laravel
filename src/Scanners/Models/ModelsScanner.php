<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Models;

use Jklejczyk\SecurityToolkit\Core\Checks\CheckScanner;
use Jklejczyk\SecurityToolkit\Scanners\Models\Checks\GuardedEmptyCheck;
use Jklejczyk\SecurityToolkit\Scanners\Models\Checks\UnguardedCheck;

final class ModelsScanner extends CheckScanner
{
    public function id(): string
    {
        return 'models';
    }

    protected function checks(): array
    {
        return [
            new UnguardedCheck,
            new GuardedEmptyCheck,
        ];
    }
}
