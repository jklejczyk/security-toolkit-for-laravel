<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

/**
 * Actions that load a post and never check who may touch it.
 */
final class OpenPostController
{
    public function show(Post $post): string
    {
        return 'post';
    }

    public function update(Post $post): string
    {
        return 'updated';
    }

    public function destroy(Post $post): string
    {
        return 'deleted';
    }

    public function store(): string
    {
        return 'created';
    }

    public function updateWithRequest(TrustingPostRequest $request, Post $post): string
    {
        return 'updated';
    }
}
