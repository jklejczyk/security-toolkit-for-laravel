<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

/**
 * Guests are turned away by a closure middleware the controller registers itself.
 */
final class ClosureGuardedPostController extends Controller
{
    public function __construct()
    {
        $this->middleware(function ($request, $next) {
            if (! Auth::user()) {
                return redirect('/');
            }

            return $next($request);
        });
    }

    public function update(Post $post): string
    {
        return 'updated';
    }
}
