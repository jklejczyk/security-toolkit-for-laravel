<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

final class SessionCookieScriptAccessibleCheck implements Check
{
    public function id(): string
    {
        return 'auth.session-cookie-script-accessible';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        // Laravel uses $config['http_only'] ?? true, so a missing option keeps the flag.
        $httpOnly = config('session.http_only');

        if ($httpOnly === null || (bool) $httpOnly) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                'Session cookie is readable by JavaScript',
                'session.http_only is disabled, so any script on the page can read the session cookie through document.cookie. A single XSS vulnerability or a compromised third-party script is then enough to steal sessions and act as other users.',
                'Set SESSION_HTTP_ONLY=true (the Laravel default) or remove the override from config/session.php.',
                [
                    'https://laravel.com/docs/session#configuration',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#httponly-attribute',
                ],
                new Location('config/session.php'),
                cwe: [1004],
            ),
        ];
    }
}
