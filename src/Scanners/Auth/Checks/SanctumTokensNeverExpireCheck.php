<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Auth\AppSource;

final class SanctumTokensNeverExpireCheck implements Check
{
    private const HAS_API_TOKENS = 'Laravel\Sanctum\HasApiTokens';

    private const CREATES_TOKEN = '/createToken\(/';

    /**
     * A createToken() call, capturing its parenthesized arguments with balanced nesting.
     */
    private const TOKEN_CALL = '/createToken\s*(\((?:[^()]++|(?1))*\))/';

    public function __construct(
        private readonly AppSource $source = new AppSource,
    ) {}

    public function id(): string
    {
        return 'auth.sanctum-tokens-never-expire';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    public function run(ScanContext $context): iterable
    {
        if (! $context->packages->isInstalled('laravel/sanctum') || config('sanctum.expiration') !== null) {
            return [];
        }

        if (! $context->isProduction() && $this->expirationFromEnv($context)) {
            throw CheckSkipped::because('sanctum.expiration comes from env(), so the production value is unknown here; run the scan in production');
        }

        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! class_exists($model)) {
            throw CheckSkipped::because('the user model (auth.providers.users.model) could not be resolved');
        }

        if (! in_array(self::HAS_API_TOKENS, class_uses_recursive($model), true)) {
            throw CheckSkipped::because(sprintf('the user model %s does not issue API tokens (no HasApiTokens trait)', $model));
        }

        // Jetstream and SPA-only apps add the trait without ever creating a token.
        if (! $this->issuesTokens($context)) {
            throw CheckSkipped::because('no code in app/ creates API tokens (createToken()) and Jetstream API features are off');
        }

        if ($this->createsTokensWithExpiry()) {
            throw CheckSkipped::because('tokens may be created with their own expiry date (createToken() with an expiresAt argument in app/)');
        }

        $published = is_file(rtrim($context->basePath, '/').'/config/sanctum.php');

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                'Sanctum API tokens never expire',
                'sanctum.expiration is null and no token is created with its own expiry date, so personal access tokens stay valid until someone deletes them. A token leaked through logs, a browser extension, a mobile app backup or a former employee keeps working indefinitely.',
                sprintf(
                    '%s \'expiration\' in config/sanctum.php to a lifetime in minutes (for example 60 * 24 * 7) or pass an expiry date to createToken(), and schedule php artisan sanctum:prune-expired.',
                    $published ? 'Set' : 'Publish the Sanctum config with php artisan vendor:publish --tag=sanctum-config, then set',
                ),
                [
                    'https://laravel.com/docs/sanctum#token-expiration',
                    'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',
                ],
                $published ? new Location('config/sanctum.php') : null,
                cwe: [613],
            ),
        ];
    }

    private function issuesTokens(ScanContext $context): bool
    {
        // Jetstream creates tokens in its own code when the "api" feature is on.
        $jetstream = config('jetstream.features', []);

        return (is_array($jetstream) && in_array('api', $jetstream, true))
            || $this->source->contains(self::CREATES_TOKEN);
    }

    /**
     * @throws CheckSkipped
     */
    private function createsTokensWithExpiry(): bool
    {
        return $this->source->any(function (string $code, string $file): bool {
            if (preg_match_all(self::TOKEN_CALL, $code, $calls) === false) {
                throw CheckSkipped::because(sprintf('could not search %s: %s', $file, preg_last_error_msg()));
            }

            foreach ($calls[1] as $arguments) {
                if ($this->hasExpiryArgument($arguments)) {
                    return true;
                }
            }

            return false;
        });
    }

    /**
     * A third argument or a named expiresAt argument at the top level of the call.
     */
    private function hasExpiryArgument(string $arguments): bool
    {
        // Strings and nested brackets are removed, so only the call's own commas are left.
        $flat = (string) preg_replace('/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"/s', "''", substr($arguments, 1, -1));

        do {
            $flat = (string) preg_replace('/\([^()\[\]{}]*\)|\[[^()\[\]{}]*\]|\{[^()\[\]{}]*\}/', '', $flat, -1, $replaced);
        } while ($replaced > 0);

        $flat = rtrim(trim($flat), ',');

        return substr_count($flat, ',') >= 2 || preg_match('/(?:^|,)\s*expiresAt\s*:/', $flat) === 1;
    }

    /**
     * @throws CheckSkipped
     */
    private function expirationFromEnv(ScanContext $context): bool
    {
        $path = rtrim($context->basePath, '/').'/config/sanctum.php';

        if (! is_file($path)) {
            return false;
        }

        $config = is_readable($path) ? file_get_contents($path) : false;

        if ($config === false) {
            throw CheckSkipped::because('could not read config/sanctum.php');
        }

        return preg_match('/[\'"]expiration[\'"]\s*=>\s*env\s*\(/', $config) === 1;
    }
}
