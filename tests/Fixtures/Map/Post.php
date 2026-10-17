<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Map;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class Post extends Model
{
    /**
     * @return BelongsTo<Author, $this>
     */
    public function author(): BelongsTo
    {
        return $this->belongsTo(Author::class, 'author_id');
    }

    // No return type: found by the $this->belongsTo( call in its body.
    public function editor()
    {
        return $this->belongsTo(Author::class, 'editor_id');
    }

    /**
     * @return HasMany<Comment, $this>
     */
    public function comments(): HasMany
    {
        return $this->hasMany(Comment::class);
    }

    public function broken(): BelongsTo
    {
        throw new \RuntimeException('not a relation');
    }

    public function withArgument(string $type): BelongsTo
    {
        return $this->belongsTo(Author::class);
    }
}
