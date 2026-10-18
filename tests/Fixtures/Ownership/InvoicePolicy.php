<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

/**
 * Records of a company are visible to the users of that company only, so the probe should treat a
 * record of another company as off limits for A.
 */
final class InvoicePolicy
{
    public function view(User $user, Invoice $invoice): bool
    {
        return $user->company_id === $invoice->company_id;
    }

    public function update(User $user, Invoice $invoice): bool
    {
        return $user->company_id === $invoice->company_id;
    }

    public function delete(User $user, Invoice $invoice): bool
    {
        return $user->company_id === $invoice->company_id;
    }
}
