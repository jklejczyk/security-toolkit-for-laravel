<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes;

use Jklejczyk\SecurityToolkit\Core\Checks\CheckScanner;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\CsrfExcludedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\MissingAuthenticationCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\MissingAuthorizationCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\UnscopedNestedBindingCheck;

final class RoutesScanner extends CheckScanner
{
    public function id(): string
    {
        return 'routes';
    }

    protected function checks(): array
    {
        $source = new ActionSource;

        return [
            new MissingAuthenticationCheck,
            new MissingAuthorizationCheck($source),
            new UnscopedNestedBindingCheck($source),
            new CsrfExcludedCheck,
        ];
    }
}
