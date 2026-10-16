<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Auth\PasswordDefaults;

final class PasswordNotCheckedForLeaksCheck implements Check
{
    public function __construct(
        private readonly PasswordDefaults $defaults = new PasswordDefaults,
    ) {}

    public function id(): string
    {
        return 'auth.password-not-checked-for-leaks';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        if ($this->defaults->rules($context)['uncompromised']) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                'Default password rule accepts passwords known from data breaches',
                'Password::defaults() does not call uncompromised(), so users can choose passwords that already appear in public breach lists. Attackers try exactly those passwords first in credential-stuffing attacks, and NIST SP 800-63B requires rejecting them.',
                'Add ->uncompromised() to Password::defaults(). It checks the password against Have I Been Pwned with k-anonymity: only the first five characters of the password\'s SHA-1 hash leave the server.',
                [
                    'https://laravel.com/docs/validation#validating-passwords',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls',
                ],
                $this->defaults->location($context),
                cwe: [521],
            ),
        ];
    }
}
