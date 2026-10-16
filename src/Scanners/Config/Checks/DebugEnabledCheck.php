<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Config\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

final class DebugEnabledCheck implements Check
{
    public function id(): string
    {
        return 'config.debug-enabled';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        // Same truthiness Laravel uses to decide whether to render debug pages.
        if (! (bool) config('app.debug')) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::High,
                'Debug mode is enabled in production',
                'With APP_DEBUG enabled, every error renders a detailed page with the stack trace, source code, SQL queries with their values and request data such as headers, cookies and form fields. Secrets leak whenever they end up in an exception message (for example an API key in a failed request URL), and older Laravel versions and Ignition also exposed environment variables or allowed remote code execution (CVE-2021-3129).',
                'Set APP_DEBUG=false in the production environment.',
                [
                    'https://laravel.com/docs/configuration#debug-mode',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html',
                ],
                new Location('config/app.php'),
                cwe: [209],
                cvss: Cvss::fromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
            ),
        ];
    }
}
