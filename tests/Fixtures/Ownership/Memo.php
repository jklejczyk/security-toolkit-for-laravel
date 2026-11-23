<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Owned by a user and listed under a client that a company owns: the parent has another kind of owner.
 */
final class Memo extends Model
{
    /** @use HasFactory<MemoFactory> */
    use HasFactory;

    protected $guarded = [];

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * @return BelongsTo<Client, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class);
    }

    protected static function newFactory(): MemoFactory
    {
        return MemoFactory::new();
    }
}
