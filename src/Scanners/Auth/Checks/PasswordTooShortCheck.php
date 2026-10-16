<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Auth\PasswordDefaults;

final class PasswordTooShortCheck implements Check
{
    /**
     * Minimum length required by OWASP ASVS and NIST SP 800-63B.
     */
    private const MIN_LENGTH = 8;

    public function __construct(
        private readonly PasswordDefaults $defaults = new PasswordDefaults,
    ) {}

    public function id(): string
    {
        return 'auth.password-too-short';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        $min = $this->defaults->rules($context)['min'];

        if ($min >= self::MIN_LENGTH) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                sprintf('Default password rule accepts passwords shorter than %d characters', self::MIN_LENGTH),
                sprintf('Password::defaults() requires only %d characters. Short passwords fall quickly to guessing and credential-stuffing attacks; OWASP ASVS and NIST SP 800-63B require at least %d characters, and more when the password is the only authentication factor.', $min, self::MIN_LENGTH),
                'Raise the minimum in Password::defaults(), for example Password::min(12)->uncompromised(), in the production branch of AppServiceProvider.',
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
