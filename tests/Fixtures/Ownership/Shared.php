<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

final class Shared extends Model
{
    /**
     * @return BelongsTo<User, $this>
     */
    public function holder(): BelongsTo
    {
        return $this->belongsTo(User::class, 'holder_id');
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function keeper(): BelongsTo
    {
        return $this->belongsTo(User::class, 'keeper_id');
    }
}
