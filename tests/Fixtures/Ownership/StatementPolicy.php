<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

final class StatementPolicy
{
    public function view(User $user, Statement $statement): bool
    {
        return $user->company_id === $statement->company_id;
    }

    public function update(User $user, Statement $statement): bool
    {
        return $user->company_id === $statement->company_id;
    }

    public function delete(User $user, Statement $statement): bool
    {
        return $user->company_id === $statement->company_id;
    }
}
