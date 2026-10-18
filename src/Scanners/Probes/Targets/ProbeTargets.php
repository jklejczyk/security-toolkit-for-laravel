<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Targets;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Routes\ActionSource;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\MissingAuthenticationCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\MissingAuthorizationCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\UnscopedNestedBindingCheck;
use Throwable;

/**
 * The route suspicions a probe works from. It runs the routes.* checks in the probe process (so
 * `--only=probes` finds the same targets as a full scan) and pairs every suspected finding with the
 * route at the same location. One finding can point at several routes that share an action.
 */
final class ProbeTargets
{
    /**
     * @param  array<string, list<ProbeTarget>>  $byRule
     */
    private function __construct(
        private readonly array $byRule,
    ) {}

    public static function of(ProbeTarget ...$targets): self
    {
        $byRule = [];

        foreach ($targets as $target) {
            $byRule[$target->suspicion->ruleId][] = $target;
        }

        return new self($byRule);
    }

    public static function fromSuspicions(ScanContext $context): self
    {
        /** @var array<string, list<RouteInfo>> $routesByLocation */
        $routesByLocation = [];

        foreach ($context->map->routes() as $route) {
            if ($route->file !== null && $route->line !== null) {
                $routesByLocation[$route->file.':'.$route->line][] = $route;
            }
        }

        /** @var array<string, array<string, ProbeTarget>> $byRule */
        $byRule = [];

        foreach (self::findings($context) as $finding) {
            $location = $finding->location;

            if ($location === null || $location->line === null) {
                continue;
            }

            foreach ($routesByLocation[$location->file.':'.$location->line] ?? [] as $route) {
                // Two routes can share one action, and the check reports each of them at the same
                // location; key by route so every route becomes one target, not one per finding.
                $key = implode('|', $route->methods).' /'.$route->uri;
                $byRule[$finding->ruleId][$key] ??= new ProbeTarget($route, $finding);
            }
        }

        $grouped = [];

        foreach ($byRule as $ruleId => $targets) {
            $grouped[$ruleId] = array_values($targets);
        }

        return new self($grouped);
    }

    /**
     * @return list<ProbeTarget>
     */
    public function forRule(string $ruleId): array
    {
        return $this->byRule[$ruleId] ?? [];
    }

    /**
     * @return list<Finding>
     */
    private static function findings(ScanContext $context): array
    {
        $source = new ActionSource;

        /** @var list<Check> $checks */
        $checks = [
            new MissingAuthenticationCheck,
            new MissingAuthorizationCheck($source),
            new UnscopedNestedBindingCheck($source),
        ];

        $findings = [];

        foreach ($checks as $check) {
            try {
                foreach ($check->run($context) as $finding) {
                    $findings[] = $finding;
                }
            } catch (CheckSkipped) {
                continue;
            } catch (Throwable) {
                continue;
            }
        }

        return $findings;
    }
}
