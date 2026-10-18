<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

/**
 * A receipt is visible to the users of the company that owns its client, so a receipt reached through
 * another client belongs to someone else.
 */
final class ReceiptPolicy
{
    public function view(User $user, Receipt $receipt): bool
    {
        return $user->company_id === $receipt->client?->company_id;
    }

    public function update(User $user, Receipt $receipt): bool
    {
        return $user->company_id === $receipt->client?->company_id;
    }

    public function delete(User $user, Receipt $receipt): bool
    {
        return $user->company_id === $receipt->client?->company_id;
    }
}
