<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use ReflectionProperty;

/**
 * Sends requests through the application kernel without PHPUnit: Request::create() → handle().
 * Guards and scoped instances are cleared between requests so one probe cannot leak its login
 * into the next.
 */
final class HttpClient
{
    public function __construct(
        private readonly Kernel $kernel,
    ) {}

    /**
     * @param  array<array-key, mixed>  $parameters
     * @param  array<string, string>  $headers
     * @param  array<string, string>  $cookies  sent back the way a browser would, e.g. a session id
     * @param  bool  $verifyCsrf  false for probes that ask about authorization: the attacker is a
     *                            user with a token of their own, so the CSRF check is not a defence there
     */
    public function request(
        string $method,
        string $uri,
        array $parameters = [],
        ?Authenticatable $user = null,
        ?string $guard = null,
        array $headers = [],
        array $cookies = [],
        bool $verifyCsrf = true,
    ): HttpResponse {
        $request = Request::create($uri, $method, $parameters, $cookies);
        $excludedBefore = $verifyCsrf ? null : $this->excludeFromCsrf($request->path());
        $request->headers->set('Accept', 'application/json');

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        if ($user !== null) {
            Auth::guard($guard)->setUser($user);

            if ($guard !== null) {
                Auth::shouldUse($guard);
            }
        }

        try {
            $response = $this->kernel->handle($request);
        } finally {
            Auth::forgetGuards();
            app()->forgetScopedInstances();

            if ($excludedBefore !== null) {
                $this->restoreCsrf($excludedBefore);
            }
        }

        $content = $response->getContent();

        $set = [];

        foreach ($response->headers->getCookies() as $cookie) {
            $set[$cookie->getName()] = $cookie->getValue() ?? '';
        }

        return new HttpResponse($response->getStatusCode(), $content === false ? '' : $content, $set);
    }

    /**
     * Adds one path to the CSRF exclusions; the list is static and shared by PreventRequestForgery,
     * VerifyCsrfToken and the application's own subclasses.
     *
     * @return list<string> the exclusions before
     */
    private function excludeFromCsrf(string $path): array
    {
        // Read without an instance, which would need the encrypter and so an application key.
        $excluded = (new ReflectionProperty(VerifyCsrfToken::class, 'neverVerify'))->getValue();
        $before = is_array($excluded) ? array_values(array_filter($excluded, is_string(...))) : [];

        VerifyCsrfToken::except([$path]);

        return $before;
    }

    /**
     * @param  list<string>  $before
     */
    private function restoreCsrf(array $before): void
    {
        VerifyCsrfToken::flushState();

        if ($before !== []) {
            VerifyCsrfToken::except($before);
        }
    }
}
