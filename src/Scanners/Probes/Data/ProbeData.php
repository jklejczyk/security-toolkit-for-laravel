<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Data;

use Illuminate\Database\Eloquent\Model;

/**
 * The actors and records a probe works with: A owns recordA, B owns recordB. recordA is the record
 * A is allowed to touch; recordB is the other owner's record an IDOR would reach.
 */
final readonly class ProbeData
{
    public function __construct(
        public string $mode,
        public Actor $a,
        public Actor $b,
        public ?Model $recordA = null,
        public ?Model $recordB = null,
    ) {}
}
