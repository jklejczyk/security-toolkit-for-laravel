<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Routes\CsrfExclusions;

final class CsrfExcludedCheck implements Check
{
    private const VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N';

    public function __construct(
        private readonly CsrfExclusions $csrf = new CsrfExclusions,
    ) {}

    public function id(): string
    {
        return 'routes.csrf-excluded';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    /**
     * An excluded URI matters only for a route that changes data for a session user. A webhook
     * has no session, and with SameSite=lax or strict the browser does not send the session
     * cookie with a cross-site POST, so in both cases there is nothing to forge.
     */
    public function run(ScanContext $context): iterable
    {
        $exposed = [];

        foreach ($context->map->routes() as $route) {
            if (! $route->inApp || ! $route->isWrite() || ! $this->csrf->usesMiddleware($route) || ! $this->csrf->usesSession($route)) {
                continue;
            }

            foreach ($this->csrf->exclusions($route) as $pattern => $source) {
                if ($this->csrf->matches($pattern, $route)) {
                    $exposed[$pattern]['source'] = $source;
                    $exposed[$pattern]['routes'][] = implode('|', $route->methods).' /'.$route->uri;
                }
            }
        }

        if ($exposed === []) {
            return;
        }

        $sameSite = config('session.same_site');

        if (in_array(is_string($sameSite) ? strtolower($sameSite) : $sameSite, ['lax', 'strict'], true)) {
            return;
        }

        if (! $context->isProduction() && $this->sameSiteFromEnv($context)) {
            throw CheckSkipped::because('session.same_site comes from env(), so the production value is unknown here; run the scan with --env=production');
        }

        foreach ($exposed as $pattern => ['source' => $source, 'routes' => $routes]) {
            yield $this->finding((string) $pattern, $source, array_values(array_unique($routes)), $sameSite, $context);
        }
    }

    private function sameSiteFromEnv(ScanContext $context): bool
    {
        $path = rtrim($context->basePath, '/').'/config/session.php';

        // Without a published config the framework default, env('SESSION_SAME_SITE', 'lax'), applies.
        if (! is_file($path)) {
            return true;
        }

        $config = is_readable($path) ? file_get_contents($path) : false;

        if ($config === false) {
            throw CheckSkipped::because('could not read config/session.php');
        }

        return preg_match('/[\'"]same_site[\'"]\s*=>\s*env\s*\(/', $config) === 1;
    }

    /**
     * @param  list<string>  $routes
     */
    private function finding(string $pattern, ?string $source, array $routes, mixed $sameSite, ScanContext $context): Finding
    {
        $cvss = Cvss::fromVector(self::VECTOR);

        return new Finding(
            $this->id(),
            $cvss->severity(),
            sprintf('"%s" is excluded from CSRF protection for logged-in routes', $pattern),
            sprintf(
                'The URI pattern "%s" skips the CSRF token check, and it matches routes that change data for a user signed in with a session cookie: %s. session.same_site is %s, so the browser sends the session cookie with a request from another site, and a page the user visits can submit these requests in their name.',
                $pattern,
                implode(', ', $routes),
                is_string($sameSite) ? "'".$sameSite."'" : 'null',
            ),
            'Remove the pattern from validateCsrfTokens(except: [...]) and send the token with the request (the @csrf directive, or the X-XSRF-TOKEN header). Exclude only routes called without a session, such as webhooks, and set session.same_site to "lax".',
            [
                'https://laravel.com/docs/csrf#csrf-excluding-uris',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
            ],
            $this->csrf->location($pattern, $source, $context->basePath),
            cwe: [352],
            cvss: $cvss,
        );
    }
}
