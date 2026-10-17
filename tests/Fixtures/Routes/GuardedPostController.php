<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

/**
 * Each action authorizes in a different way the check must recognise.
 */
final class GuardedPostController
{
    public function viaGate(Post $post): string
    {
        Gate::authorize('update', $post);

        return 'updated';
    }

    public function viaAbort(Post $post): string
    {
        abort_unless($post->getAttribute('author_id') === auth()->id(), 403);

        return 'updated';
    }

    public function viaUserCan(Post $post): string
    {
        if (request()->user()?->cannot('update', $post)) {
            abort(403);
        }

        return 'updated';
    }

    public function viaFormRequest(CheckingPostRequest $request, Post $post): string
    {
        return 'updated';
    }
}
