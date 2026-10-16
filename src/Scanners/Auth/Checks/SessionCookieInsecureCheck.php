<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

final class SessionCookieInsecureCheck implements Check
{
    public function id(): string
    {
        return 'auth.session-cookie-insecure';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        // Laravel passes the value to the cookie as is, so any truthy value sets the flag.
        if ((bool) config('session.secure')) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                'Session cookie is also sent over unencrypted HTTP',
                'session.secure is not enabled, so browsers send the session cookie over plain HTTP too: on a request typed without https://, through an http:// link or redirect, or before HSTS takes effect. Anyone on the same network, for example public Wi-Fi, can copy the cookie and take over the session.',
                'Set SESSION_SECURE_COOKIE=true in production and serve the application only over HTTPS, ideally with HSTS.',
                [
                    'https://laravel.com/docs/session#configuration',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#secure-attribute',
                ],
                new Location('config/session.php'),
                cwe: [614],
                cvss: Cvss::fromVector('CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N'),
            ),
        ];
    }
}
