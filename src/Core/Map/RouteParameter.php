<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Map;

use Illuminate\Database\Eloquent\Model;

/**
 * A route parameter bound to an Eloquent model, e.g. {post} or {post:slug}.
 */
final readonly class RouteParameter
{
    /**
     * @param  class-string<Model>  $model
     * @param  ?string  $field  the custom binding key ({post:slug} → "slug"), null for the route key
     */
    public function __construct(
        public string $name,
        public string $model,
        public ?string $field = null,
    ) {}
}
