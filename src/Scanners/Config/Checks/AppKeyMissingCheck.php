<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Config\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

final class AppKeyMissingCheck implements Check
{
    public function id(): string
    {
        return 'config.app-key-missing';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        $key = config('app.key');

        if (is_string($key) && trim($key) !== '') {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Critical,
                'Application key is not set',
                'APP_KEY is empty. Laravel cannot encrypt cookies or sessions, so requests that need them fail with an error, and signed URLs are signed with an empty key: anyone can forge a valid signature for routes that work without the encrypter, such as API routes.',
                'Generate a key with "php artisan key:generate" and set APP_KEY in the production environment.',
                ['https://laravel.com/docs/encryption#configuration'],
                new Location('config/app.php'),
            ),
        ];
    }
}
