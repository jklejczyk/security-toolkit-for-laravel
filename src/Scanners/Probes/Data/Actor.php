<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Data;

use Illuminate\Database\Eloquent\Model;

/**
 * One signed-in user a probe acts as, with the group they belong to when the resource is owned by
 * a group. A and B never share an owner, so an IDOR between them is a real one.
 */
final readonly class Actor
{
    public function __construct(
        public string $name,
        public Model $user,
        public ?Model $group = null,
    ) {}

    public function id(): int|string|null
    {
        return $this->keyOf($this->user);
    }

    /**
     * The id of the owner: the group when there is one, otherwise the user.
     */
    public function ownerId(): int|string|null
    {
        return $this->keyOf($this->group ?? $this->user);
    }

    private function keyOf(Model $record): int|string|null
    {
        $key = $record->getKey();

        return is_int($key) || is_string($key) ? $key : null;
    }
}
