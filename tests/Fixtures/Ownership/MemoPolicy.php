<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

final class MemoPolicy
{
    public function view(User $user, Memo $memo): bool
    {
        return $user->id === $memo->user_id;
    }
}
