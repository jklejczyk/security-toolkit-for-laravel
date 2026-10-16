<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Models;

use Illuminate\Foundation\Auth\User;
use Laravel\Sanctum\HasApiTokens;

final class UserWithApiTokens extends User
{
    use HasApiTokens;
}
