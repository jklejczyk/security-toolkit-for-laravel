<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Comment;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

final class CommentController
{
    /**
     * Authorizes the post only, so any comment id passes.
     */
    public function show(Post $post, Comment $comment): string
    {
        Gate::authorize('view', $post);

        return 'comment';
    }

    public function showChecked(Post $post, Comment $comment): string
    {
        Gate::authorize('view', $post);
        abort_unless($comment->post_id === $post->id, 404);

        return 'comment';
    }
}
