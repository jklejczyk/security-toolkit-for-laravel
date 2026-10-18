<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\PayloadBuilder;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;

/**
 * What a probe is given to do its work: the HTTP client, the application map, the validated probe
 * configuration, the actors/records selector and the route suspicions to work from. Everything the
 * probe reports (checked, confirmed, skipped) goes through the coverage collector.
 */
final class ProbeContext
{
    public function __construct(
        private readonly HttpClient $client,
        private readonly ApplicationMap $map,
        private readonly CoverageCollector $coverage,
        private readonly ProbesConfig $config,
        private readonly ScanContext $scanContext,
        private readonly ?OwnershipResolver $ownership,
        private readonly ?DataSelector $data,
        private readonly ProbeTargets $targets,
    ) {}

    public function client(): HttpClient
    {
        return $this->client;
    }

    public function map(): ApplicationMap
    {
        return $this->map;
    }

    public function coverage(): CoverageCollector
    {
        return $this->coverage;
    }

    public function config(): ProbesConfig
    {
        return $this->config;
    }

    public function scanContext(): ScanContext
    {
        return $this->scanContext;
    }

    public function ownership(): ?OwnershipResolver
    {
        return $this->ownership;
    }

    public function data(): ?DataSelector
    {
        return $this->data;
    }

    public function targets(): ProbeTargets
    {
        return $this->targets;
    }

    /**
     * Builds the request-body generator on demand; null when the user model could not be resolved, in
     * which case probes that need a body report it in their coverage.
     */
    public function payload(): ?PayloadBuilder
    {
        if ($this->ownership === null) {
            return null;
        }

        return new PayloadBuilder(app(), $this->map, $this->ownership, $this->config);
    }
}
