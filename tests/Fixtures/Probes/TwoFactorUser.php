<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Fortify\TwoFactorAuthenticatable;

/**
 * A second factor able user of the users table, for the probes that log in through Fortify.
 */
final class TwoFactorUser extends Authenticatable
{
    /** @use HasFactory<TwoFactorUserFactory> */
    use HasFactory, Notifiable, TwoFactorAuthenticatable;

    protected $table = 'users';

    protected $guarded = [];

    protected static function newFactory(): TwoFactorUserFactory
    {
        return TwoFactorUserFactory::new();
    }
}
