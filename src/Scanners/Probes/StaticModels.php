<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Illuminate\Database\Eloquent\Model;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Models\AppModels;
use Jklejczyk\SecurityToolkit\Scanners\Models\Checks\GuardedEmptyCheck;
use Jklejczyk\SecurityToolkit\Scanners\Models\Checks\UnguardedCheck;
use Throwable;

/**
 * The static mass-assignment findings the probe can confirm, recomputed inside the probe process the
 * way the routes checks are recomputed for targets. A global unguard applies to every model; a
 * models.guarded-empty finding is matched to a model by the location the check assigns it.
 */
class StaticModels
{
    public function __construct(
        private readonly AppModels $models = new AppModels,
    ) {}

    /**
     * The models.unguarded finding, when mass assignment is disabled globally.
     */
    public function unguarded(ScanContext $context): ?Finding
    {
        $finding = $this->first(new UnguardedCheck, $context);

        return $finding;
    }

    /**
     * The models.guarded-empty finding for the model, or null when the model is not reported.
     *
     * @param  class-string<Model>  $model
     */
    public function guardedEmpty(ScanContext $context, string $model): ?Finding
    {
        $byFile = [];

        try {
            foreach ($this->models->all() as ['class' => $class, 'file' => $file]) {
                $byFile[$file] = $class;
            }
        } catch (Throwable) {
            return null;
        }

        $check = new GuardedEmptyCheck;

        try {
            foreach ($check->run($context) as $finding) {
                $class = $finding->location === null ? null : ($byFile[$finding->location->file] ?? null);

                if ($class === $model) {
                    return $finding;
                }
            }
        } catch (CheckSkipped) {
            return null;
        } catch (Throwable) {
            return null;
        }

        return null;
    }

    private function first(UnguardedCheck|GuardedEmptyCheck $check, ScanContext $context): ?Finding
    {
        try {
            foreach ($check->run($context) as $finding) {
                return $finding;
            }
        } catch (CheckSkipped) {
            return null;
        } catch (Throwable) {
            return null;
        }

        return null;
    }
}
