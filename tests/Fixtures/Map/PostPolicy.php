<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Map;

final class PostPolicy
{
    public function update(Author $author, Post $post): bool
    {
        return $post->getAttribute('author_id') === $author->getKey();
    }
}
