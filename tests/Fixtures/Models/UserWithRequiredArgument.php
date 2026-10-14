<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Models;

use Illuminate\Foundation\Auth\User;

final class UserWithRequiredArgument extends User
{
    public function __construct(string $tenant)
    {
        parent::__construct(['tenant' => $tenant]);
    }
}
