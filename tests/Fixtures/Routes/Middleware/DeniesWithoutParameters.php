<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Redirects without a parameter on the route: a redirect alone is not evidence of authorization.
 */
final class DeniesWithoutParameters
{
    public function handle(Request $request, Closure $next): mixed
    {
        if (! $request->hasSession()) {
            return redirect('/');
        }

        return $next($request);
    }
}
