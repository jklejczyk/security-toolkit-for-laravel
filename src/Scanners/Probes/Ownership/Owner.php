<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership;

use Illuminate\Database\Eloquent\Model;

/**
 * How a model reaches its owner: a belongsTo path from the model to the user model (a person owns
 * their own records) or to a group model (everyone in the group owns the group's records).
 *
 * The relations and foreign keys are aligned: relation i goes from the model reached after i-1 hops
 * to the next one, using foreign key i on that source model.
 */
final readonly class Owner
{
    /**
     * @param  class-string<Model>  $model  the owner model (a user or a group)
     * @param  list<string>  $relations  belongsTo method names, at most two
     * @param  list<string>  $foreignKeys  the foreign key column per hop, on the source model
     */
    public function __construct(
        public OwnerKind $kind,
        public string $model,
        public array $relations,
        public array $foreignKeys,
    ) {}

    /**
     * The foreign key on the checked model itself, e.g. company_id — set only for a direct owner.
     */
    public function directForeignKey(): ?string
    {
        return count($this->foreignKeys) === 1 ? $this->foreignKeys[0] : null;
    }
}
