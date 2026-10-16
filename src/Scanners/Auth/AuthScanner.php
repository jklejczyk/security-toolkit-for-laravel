<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth;

use Jklejczyk\SecurityToolkit\Core\Checks\CheckScanner;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\PasswordNotCheckedForLeaksCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\PasswordTooShortCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\SanctumTokensNeverExpireCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\SessionCookieInsecureCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\SessionCookieScriptAccessibleCheck;

final class AuthScanner extends CheckScanner
{
    public function id(): string
    {
        return 'auth';
    }

    protected function checks(): array
    {
        $passwords = new PasswordDefaults;

        return [
            new SessionCookieInsecureCheck,
            new SessionCookieScriptAccessibleCheck,
            new PasswordTooShortCheck($passwords),
            new PasswordNotCheckedForLeaksCheck($passwords),
            new SanctumTokensNeverExpireCheck,
        ];
    }
}
