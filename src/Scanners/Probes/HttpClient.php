<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

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
     */
    public function request(
        string $method,
        string $uri,
        array $parameters = [],
        ?Authenticatable $user = null,
        ?string $guard = null,
        array $headers = [],
        array $cookies = [],
    ): HttpResponse {
        $request = Request::create($uri, $method, $parameters, $cookies);
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
        }

        $content = $response->getContent();

        $set = [];

        foreach ($response->headers->getCookies() as $cookie) {
            $set[$cookie->getName()] = $cookie->getValue() ?? '';
        }

        return new HttpResponse($response->getStatusCode(), $content === false ? '' : $content, $set);
    }
}
