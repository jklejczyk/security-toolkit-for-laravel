<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Data;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\Owner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnerKind;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use ReflectionMethod;
use RuntimeException;
use Throwable;

/**
 * Picks the two non-overlapping owners a probe acts as and the records it works on. In "existing"
 * mode it reads two owners that already have rows and their users; in "factories" mode it builds
 * them through the application factories; "auto" tries factories first. Anything it cannot build is
 * reported as a skip, never guessed.
 */
final class DataSelector
{
    public function __construct(
        private readonly ProbesConfig $config,
        private readonly OwnershipResolver $ownership,
        private readonly ApplicationMap $map = new ApplicationMap,
    ) {}

    /**
     * @param  class-string<Model>  $model
     */
    public function for(string $model, Owner $owner): DataSelection
    {
        return match ($this->config->data) {
            'existing' => $this->existing($model, $owner),
            'factories' => $this->factories($model, $owner),
            default => $this->automatic($model, $owner),
        };
    }

    /**
     * The two accounts a probe acts as without any record they own: the rate limit probe logs in as
     * A, the 2FA probe challenges it. Same modes as records, same "no guessing" rule.
     */
    public function actors(): DataSelection
    {
        return match ($this->config->data) {
            'existing' => $this->existingActors(),
            'factories' => $this->factoryActors(),
            default => $this->automaticActors(),
        };
    }

    private function automaticActors(): DataSelection
    {
        $factories = $this->factoryActors();

        if ($factories->isFound()) {
            return $factories;
        }

        return $this->existingActors();
    }

    private function factoryActors(): DataSelection
    {
        $userModel = $this->ownership->userModel();

        if (! $this->hasFactory($userModel)) {
            return DataSelection::skipped('no factory for '.class_basename($userModel), 'add a factory or set probes.data=existing');
        }

        try {
            return DataSelection::found(new ProbeData(
                'factories',
                new Actor('A', $this->create($userModel)),
                new Actor('B', $this->create($userModel)),
            ));
        } catch (Throwable $exception) {
            return DataSelection::skipped(
                'the factory failed: '.$exception->getMessage(),
                'fix the factory or set probes.data=existing',
            );
        }
    }

    private function existingActors(): DataSelection
    {
        $userModel = $this->ownership->userModel();
        $key = $userModel::query()->getModel()->getKeyName();
        $users = $userModel::query()->orderBy($key)->limit(2)->get()->values();

        $userA = $users->get(0);
        $userB = $users->get(1);

        if (! $userA instanceof Model || ! $userB instanceof Model) {
            return DataSelection::skipped(
                'fewer than two '.class_basename($userModel).' records to act as',
                'seed two users or set probes.data=factories',
            );
        }

        return DataSelection::found(new ProbeData(
            'existing',
            new Actor('A', $userA),
            new Actor('B', $userB),
        ));
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function automatic(string $model, Owner $owner): DataSelection
    {
        $factories = $this->factories($model, $owner);

        if ($factories->isFound()) {
            return $factories;
        }

        $existing = $this->existing($model, $owner);

        if ($existing->isFound()) {
            return $existing;
        }

        return DataSelection::skipped(
            'no factory and too few records to build data for '.class_basename($model),
            'add a factory or seed two owners with '.class_basename($model).' records, or set probes.data',
        );
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function existing(string $model, Owner $owner): DataSelection
    {
        $records = $this->sample($model);

        /** @var array<string, list<Model>> $byOwner */
        $byOwner = [];

        foreach ($records as $record) {
            $ownerId = $this->ownerIdOf($record, $owner);

            if ($ownerId !== null) {
                $byOwner[(string) $ownerId][] = $record;
            }
        }

        if (count($byOwner) < 2) {
            return DataSelection::skipped(
                'fewer than two owners have '.class_basename($model).' records',
                'seed records for two owners or set probes.data=factories',
            );
        }

        $owners = array_values($byOwner);

        foreach ($owners as $index => $ownerRecords) {
            if ($index === 0) {
                continue;
            }

            foreach (array_slice($ownerRecords, 0, $this->config->candidates) as $recordB) {
                $selection = $this->fromRecords('existing', $owner, $owners[0][0], $recordB);

                if ($selection->isFound()) {
                    return $selection;
                }
            }
        }

        return DataSelection::skipped(
            'could not build users of both owners for '.class_basename($model),
            'check the owner relations or set probes.owners',
        );
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function factories(string $model, Owner $owner): DataSelection
    {
        $userModel = $this->ownership->userModel();

        if (! $this->hasFactory($model)) {
            return DataSelection::skipped('no factory for '.class_basename($model), 'add a factory or set probes.data=existing');
        }

        if (! $this->hasFactory($userModel)) {
            return DataSelection::skipped('no factory for '.class_basename($userModel), 'add a factory or set probes.data=existing');
        }

        try {
            if ($owner->kind === OwnerKind::Group) {
                $groupModel = $owner->model;

                if (! $this->hasFactory($groupModel)) {
                    return DataSelection::skipped('no factory for the group '.class_basename($groupModel), 'set probes.data=existing');
                }

                $groupA = $this->create($groupModel);
                $groupB = $this->create($groupModel);
                $foreignKey = $this->userGroupForeignKey($owner);

                if ($foreignKey === null) {
                    return DataSelection::skipped('could not find how a user joins '.class_basename($groupModel), 'set probes.owners');
                }

                $actorA = new Actor('A', $this->create($userModel, [$foreignKey => $groupA->getKey()]), $groupA);
                $actorB = new Actor('B', $this->create($userModel, [$foreignKey => $groupB->getKey()]), $groupB);
            } else {
                $actorA = new Actor('A', $this->create($userModel));
                $actorB = new Actor('B', $this->create($userModel));
            }

            return DataSelection::found(new ProbeData(
                'factories',
                $actorA,
                $actorB,
                $this->createRecord($model, $owner, $actorA),
                $this->createRecord($model, $owner, $actorB),
            ));
        } catch (Throwable $exception) {
            return DataSelection::skipped(
                'the factory failed: '.$exception->getMessage(),
                'fix the factory or set probes.data=existing',
            );
        }
    }

    private function fromRecords(string $mode, Owner $owner, Model $recordA, Model $recordB): DataSelection
    {
        $actorA = $this->actorFor($recordA, $owner, 'A');
        $actorB = $this->actorFor($recordB, $owner, 'B');

        if ($actorA === null || $actorB === null) {
            return DataSelection::skipped('could not find a user of one of the owners', 'set probes.owners');
        }

        return DataSelection::found(new ProbeData($mode, $actorA, $actorB, $recordA, $recordB));
    }

    /**
     * @param  class-string<Model>  $model
     * @return Collection<int, Model>
     */
    private function sample(string $model): Collection
    {
        $query = $model::query();

        return $query->orderBy($query->getModel()->getKeyName())->limit(max($this->config->candidates, 5) * 20)->get();
    }

    /**
     * @param  class-string<Model>  $model
     * @param  array<string, mixed>  $attributes
     */
    private function create(string $model, array $attributes = []): Model
    {
        $factory = (new ReflectionMethod($model, 'factory'))->invoke(null);

        if (! $factory instanceof Factory) {
            throw new RuntimeException(sprintf('%s has no factory', class_basename($model)));
        }

        $record = $factory->create($attributes);

        if (! $record instanceof Model) {
            throw new RuntimeException(sprintf('the factory for %s did not return a single model', class_basename($model)));
        }

        return $record;
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function createRecord(string $model, Owner $owner, Actor $actor): Model
    {
        if (count($owner->relations) === 1) {
            return $this->create($model, [$owner->foreignKeys[0] => $actor->ownerId()]);
        }

        $parentModel = $this->relatedModel($model, $owner->relations[0]);
        $parentOwner = new Owner(
            $owner->kind,
            $owner->model,
            array_slice($owner->relations, 1),
            array_slice($owner->foreignKeys, 1),
        );

        $parent = $this->createRecord($parentModel, $parentOwner, $actor);

        return $this->create($model, [$owner->foreignKeys[0] => $parent->getKey()]);
    }

    private function actorFor(Model $record, Owner $owner, string $name): ?Actor
    {
        $ownerRecord = $this->ownerRecord($record, $owner);

        if (! $ownerRecord instanceof Model) {
            return null;
        }

        if ($owner->kind === OwnerKind::User) {
            return new Actor($name, $ownerRecord);
        }

        $foreignKey = $this->userGroupForeignKey($owner);

        if ($foreignKey === null) {
            return null;
        }

        $userModel = $this->ownership->userModel();
        $user = $userModel::query()->where($foreignKey, $ownerRecord->getKey())->orderBy($userModel::query()->getModel()->getKeyName())->first();

        return $user instanceof Model ? new Actor($name, $user, $ownerRecord) : null;
    }

    private function ownerRecord(Model $record, Owner $owner): ?Model
    {
        $current = $record;

        foreach ($owner->relations as $relation) {
            $value = $current->getRelationValue($relation);

            if (! $value instanceof Model) {
                return null;
            }

            $current = $value;
        }

        return $current;
    }

    private function ownerIdOf(Model $record, Owner $owner): int|string|null
    {
        $key = $this->ownerRecord($record, $owner)?->getKey();

        return is_int($key) || is_string($key) ? $key : null;
    }

    /**
     * @param  class-string<Model>  $model
     * @return class-string<Model>
     */
    private function relatedModel(string $model, string $relation): string
    {
        foreach ($this->map->belongsTo($model) as $belongsTo) {
            if ($belongsTo->method === $relation) {
                return $belongsTo->related;
            }
        }

        throw new RuntimeException(sprintf('%s has no relation "%s"', class_basename($model), $relation));
    }

    private function userGroupForeignKey(Owner $owner): ?string
    {
        $userModel = $this->ownership->userModel();

        foreach ($this->map->belongsTo($userModel) as $relation) {
            if ($relation->related === $owner->model) {
                return $relation->foreignKey;
            }
        }

        return null;
    }

    /**
     * @param  class-string<Model>  $model
     */
    private function hasFactory(string $model): bool
    {
        return method_exists($model, 'factory');
    }
}
