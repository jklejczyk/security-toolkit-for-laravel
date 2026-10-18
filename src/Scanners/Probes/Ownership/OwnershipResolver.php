<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership;

use Illuminate\Database\Eloquent\Model;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\BelongsToInfo;

/**
 * Works out who owns a record of a model: the signed-in user, or the group the user belongs to.
 * A configured relation path wins; then a group shared by the user and the model; then a direct
 * relation to the user; then a chain through a parent. Anything ambiguous is skipped rather than
 * guessed, so an IDOR is never reported against a shared resource by mistake.
 */
final class OwnershipResolver
{
    /**
     * Group columns, most specific first, used to pick between several group relations.
     */
    private const GROUP_COLUMNS = ['team_id', 'company_id', 'organization_id', 'tenant_id', 'account_id', 'workspace_id'];

    /**
     * Author columns, most specific first, used to pick between several user relations.
     */
    private const USER_COLUMNS = ['user_id', 'owner_id', 'author_id', 'created_by'];

    private const MAX_LINKS = 2;

    /**
     * @param  array<string, string>  $configured  model => belongsTo path, from probes.owners
     * @param  class-string<Model>  $userModel
     */
    public function __construct(
        private readonly ApplicationMap $map,
        private readonly array $configured,
        private readonly string $userModel,
    ) {}

    /**
     * @return class-string<Model>
     */
    public function userModel(): string
    {
        return $this->userModel;
    }

    /**
     * @param  class-string<Model>  $model
     */
    public function for(string $model, int $depth = 0): OwnerResolution
    {
        if ($model === $this->userModel) {
            return OwnerResolution::found(new Owner(OwnerKind::User, $model, [], []));
        }

        if ($depth > self::MAX_LINKS - 1) {
            return OwnerResolution::skipped(
                sprintf('the owner of %s is more than %d relations away', class_basename($model), self::MAX_LINKS),
                'set probes.owners',
            );
        }

        if (isset($this->configured[$model]) && trim($this->configured[$model]) !== '') {
            return $this->fromConfiguration($model, $this->configured[$model]);
        }

        $group = $this->group($model);

        if ($group !== null) {
            return OwnerResolution::found($group);
        }

        $direct = $this->direct($model);

        if ($direct !== null) {
            return $direct;
        }

        return $this->chain($model, $depth);
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function fromConfiguration(string $model, string $path): OwnerResolution
    {
        $relations = array_values(array_filter(array_map(trim(...), explode('.', $path)), fn (string $part): bool => $part !== ''));

        if ($relations === []) {
            return OwnerResolution::skipped('probes.owners for '.class_basename($model).' is empty', 'give a belongsTo path');
        }

        $current = $model;
        $foreignKeys = [];

        foreach ($relations as $relation) {
            $match = $this->relation($current, $relation);

            if ($match === null) {
                return OwnerResolution::skipped(
                    sprintf('probes.owners points %s at the relation "%s", which does not exist', class_basename($model), $relation),
                    'fix probes.owners',
                );
            }

            $foreignKeys[] = $match->foreignKey;
            $current = $match->related;
        }

        return OwnerResolution::found(new Owner(
            $this->isUser($current) ? OwnerKind::User : OwnerKind::Group,
            $current,
            $relations,
            $foreignKeys,
        ));
    }

    /**
     * A group both the model and the user belong to.
     *
     * @param  class-string<Model>  $model
     */
    private function group(string $model): ?Owner
    {
        $candidates = [];

        foreach ($this->map->belongsTo($model) as $modelRelation) {
            if ($this->isUser($modelRelation->related)) {
                continue;
            }

            foreach ($this->map->belongsTo($this->userModel) as $userRelation) {
                if ($modelRelation->related === $userRelation->related) {
                    $candidates[] = $modelRelation;

                    continue 2;
                }
            }
        }

        if ($candidates === []) {
            return null;
        }

        $picked = $this->preferByColumn($candidates, self::GROUP_COLUMNS) ?? $candidates[0];

        return new Owner(OwnerKind::Group, $picked->related, [$picked->method], [$picked->foreignKey]);
    }

    /**
     * A belongsTo relation directly to the user model, or a skip when several are equally likely.
     *
     * @param  class-string<Model>  $model
     */
    private function direct(string $model): ?OwnerResolution
    {
        $candidates = array_values(array_filter(
            $this->map->belongsTo($model),
            fn (BelongsToInfo $relation): bool => $this->isUser($relation->related),
        ));

        if ($candidates === []) {
            return null;
        }

        $named = $this->preferByColumn($candidates, self::USER_COLUMNS);

        if ($named !== null) {
            return OwnerResolution::found(new Owner(OwnerKind::User, $this->userModel, [$named->method], [$named->foreignKey]));
        }

        if (count($candidates) > 1) {
            return OwnerResolution::skipped(
                sprintf('%s has several relations to %s (%s)', class_basename($model), class_basename($this->userModel), implode(', ', array_map(fn (BelongsToInfo $relation): string => $relation->method, $candidates))),
                'set probes.owners',
            );
        }

        return OwnerResolution::found(new Owner(OwnerKind::User, $this->userModel, [$candidates[0]->method], [$candidates[0]->foreignKey]));
    }

    /**
     * The owner of a parent, prepended with the relation that reaches that parent.
     *
     * @param  class-string<Model>  $model
     */
    private function chain(string $model, int $depth): OwnerResolution
    {
        foreach ($this->map->belongsTo($model) as $relation) {
            if ($this->isUser($relation->related) || $relation->related === $model) {
                continue;
            }

            $parent = $this->for($relation->related, $depth + 1);

            if ($parent->owner !== null) {
                return OwnerResolution::found(new Owner(
                    $parent->owner->kind,
                    $parent->owner->model,
                    [$relation->method, ...$parent->owner->relations],
                    [$relation->foreignKey, ...$parent->owner->foreignKeys],
                ));
            }
        }

        return OwnerResolution::skipped(
            sprintf('no owner could be determined for %s', class_basename($model)),
            'set probes.owners',
        );
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function relation(string $model, string $method): ?BelongsToInfo
    {
        foreach ($this->map->belongsTo($model) as $relation) {
            if ($relation->method === $method) {
                return $relation;
            }
        }

        return null;
    }

    /**
     * @param  list<BelongsToInfo>  $candidates
     * @param  list<string>  $columns
     */
    private function preferByColumn(array $candidates, array $columns): ?BelongsToInfo
    {
        $best = null;
        $bestIndex = PHP_INT_MAX;

        foreach ($candidates as $candidate) {
            $index = array_search($candidate->foreignKey, $columns, true);

            if ($index !== false && $index < $bestIndex) {
                $best = $candidate;
                $bestIndex = $index;
            }
        }

        return $best;
    }

    private function isUser(string $model): bool
    {
        return $model === $this->userModel || is_a($model, $this->userModel, true);
    }
}
