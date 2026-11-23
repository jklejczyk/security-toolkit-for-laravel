<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Routing\Controller;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

/**
 * A closure middleware that has nothing to do with the login.
 */
final class LocaleClosurePostController extends Controller
{
    public function __construct()
    {
        $this->middleware(function ($request, $next) {
            app()->setLocale('pl');

            return $next($request);
        });
    }

    public function update(Post $post): string
    {
        return 'updated';
    }
}
