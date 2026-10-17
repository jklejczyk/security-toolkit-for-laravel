<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;

final class ResourcePostController
{
    use AuthorizesRequests;

    public function __construct()
    {
        $this->authorizeResource(Post::class, 'post');
    }

    public function update(Post $post): string
    {
        return 'updated';
    }
}
