<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;

/**
 * Collects what a single probe did, so the engine can turn it into a CoverageEntry.
 */
final class CoverageCollector
{
    private int $checked = 0;

    private int $confirmed = 0;

    /** @var list<CoverageTarget> */
    private array $notConfirmed = [];

    /** @var list<CoverageTarget> */
    private array $skipped = [];

    /**
     * A target the probe reached but did not confirm, e.g. a route that answered 403.
     */
    public function checked(CoverageTarget $target): void
    {
        $this->checked++;
        $this->notConfirmed[] = $target;
    }

    /**
     * A target the probe reproduced an attack on.
     */
    public function confirmed(): void
    {
        $this->checked++;
        $this->confirmed++;
    }

    /**
     * A target the probe could not check, with the reason and how to fix it.
     */
    public function skipped(CoverageTarget $target): void
    {
        $this->skipped[] = $target;
    }

    public function entry(string $probe): CoverageEntry
    {
        return new CoverageEntry($probe, $this->checked, $this->confirmed, $this->notConfirmed, $this->skipped);
    }
}
