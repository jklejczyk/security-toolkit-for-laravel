<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

/**
 * Routes without the auth middleware whose actions check the login themselves.
 */
final class SelfCheckingPostController
{
    public function viaCheck(Post $post): mixed
    {
        if (! Auth::check() || $post->id === 0) {
            return redirect('/login');
        }

        return 'updated';
    }

    public function viaUser(Post $post): string
    {
        if (Auth::user()) {
            return 'updated';
        }

        return 'nothing';
    }

    public function viaHelper(Request $request, Post $post): string
    {
        abort_unless(auth()->check(), 401);

        return 'updated';
    }

    public function viaRequest(Request $request, Post $post): mixed
    {
        if ($request->user() === null) {
            return redirect('/login');
        }

        return 'updated';
    }

    public function onlyLogsTheUser(Post $post): string
    {
        Log::info('updated by '.Auth::id());

        return 'updated';
    }
}
