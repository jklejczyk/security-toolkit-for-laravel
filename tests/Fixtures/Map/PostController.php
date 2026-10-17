<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Map;

final class PostController
{
    public function index(): string
    {
        return 'posts';
    }

    public function update(Post $post): string
    {
        return 'updated';
    }

    public function showComment(Post $post, Comment $comment, string $format = 'html'): string
    {
        return 'comment';
    }
}
