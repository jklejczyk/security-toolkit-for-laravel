<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Config\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

final class KnownAppKeyCheck implements Check
{
    public function __construct(
        private readonly ?string $listPath = null,
    ) {}

    public function id(): string
    {
        return 'config.app-key-known';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        $key = config('app.key');

        if (! is_string($key) || trim($key) === '') {
            return [];
        }

        $source = $this->knownKeys()[hash('sha256', $key)] ?? null;

        if ($source === null) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Critical,
                'Application key is publicly known',
                sprintf(
                    'APP_KEY matches a key published as: %s. Anyone who knows it can decrypt everything the application encrypts (cookies, encrypted model attributes, encrypted jobs) and forge signed URLs and encrypted payloads. If the application decrypts attacker-controlled data with unserialization, for example decrypt() on request input, the cookie session driver with PHP serialization, or Laravel before 5.6.30, this leads to remote code execution, which is how hundreds of real applications were found exploitable.',
                    $source === '' ? 'a public source' : $source,
                ),
                'Generate a new key with "php artisan key:generate". Do not put the leaked key in APP_PREVIOUS_KEYS: Laravel would keep decrypting cookies and accepting signed URLs made with it. Re-encrypt stored encrypted data in a one-off migration that reads it with the old key, expect existing sessions to be logged out, and never commit keys to version control.',
                [
                    'https://laravel.com/docs/encryption#gracefully-rotating-encryption-keys',
                    'https://blog.gitguardian.com/exploiting-public-app_key-leaks/',
                ],
                new Location('config/app.php'),
                cwe: [321],
                cvss: Cvss::fromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),
            ),
        ];
    }

    /**
     * @return array<string, string> lowercase SHA-256 hash => source
     *
     * @throws CheckSkipped
     */
    private function knownKeys(): array
    {
        $path = $this->listPath ?? dirname(__DIR__, 4).'/resources/data/known-app-keys.txt';
        $contents = is_file($path) ? file_get_contents($path) : false;

        if ($contents === false) {
            throw CheckSkipped::because(sprintf('the list of known application keys could not be read (%s)', $path));
        }

        $keys = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            [$hash, $source] = array_pad(explode('#', $line, 2), 2, '');
            $keys[strtolower(trim($hash))] = trim($source);
        }

        return $keys;
    }
}
