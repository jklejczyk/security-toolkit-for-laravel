<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Map;

use Illuminate\Database\Eloquent\Model;

/**
 * A belongsTo relation, e.g. Post::user() → User via user_id.
 */
final readonly class BelongsToInfo
{
    /**
     * @param  class-string<Model>  $related
     */
    public function __construct(
        public string $method,
        public string $related,
        public string $foreignKey,
    ) {}
}
