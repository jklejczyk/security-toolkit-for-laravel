<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Area named on the route ("area:admin"), denied with a redirect.
 */
final class BackOffice
{
    public function handle(Request $request, Closure $next, ?string $area = null): mixed
    {
        if ($area === 'admin' && $request->user()?->context !== 'admin') {
            return redirect('/panel');
        }

        return $next($request);
    }
}
