<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Takes a parameter but never denies the request.
 */
final class SetLocale
{
    public function handle(Request $request, Closure $next, string $locale = 'en'): mixed
    {
        app()->setLocale($locale);

        return $next($request);
    }
}
