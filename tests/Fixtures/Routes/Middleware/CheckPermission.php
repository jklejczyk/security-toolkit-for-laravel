<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Permission named on the route ("permission:posts.edit"), checked without Laravel's authorization API.
 */
final class CheckPermission
{
    public function handle(Request $request, Closure $next, string ...$permissions): mixed
    {
        if ($request->user()?->permissions === $permissions) {
            return $next($request);
        }

        return response()->json(['message' => 'No permission'], 403);
    }
}
