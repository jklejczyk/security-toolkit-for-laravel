<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * No parameters, but Laravel's authorization API.
 */
final class EnsureAdmin
{
    public function handle(Request $request, Closure $next): mixed
    {
        abort_unless($request->user()?->is_admin, 403);

        return $next($request);
    }
}
