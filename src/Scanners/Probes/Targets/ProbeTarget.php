<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Targets;

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;

/**
 * One route a probe should try, together with the static suspicion that pointed at it. The probe
 * keeps the suspicion's rule id, severity, CWE and location when it confirms the attack.
 */
final readonly class ProbeTarget
{
    public function __construct(
        public RouteInfo $route,
        public Finding $suspicion,
    ) {}

    public function label(): string
    {
        return implode('|', $this->route->methods).' /'.$this->route->uri;
    }
}
