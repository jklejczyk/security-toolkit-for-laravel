<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Map;

final class InvokableController
{
    public function __invoke(Post $post): string
    {
        return 'invoked';
    }
}
