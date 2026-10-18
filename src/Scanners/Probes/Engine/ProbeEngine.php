<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Engine;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Notice;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\CoverageCollector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol\ProbeReport;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;

/**
 * Runs the probes inside the child process and turns what they did into a report. The child owns
 * the deadline: when it runs out, the remaining probes are reported as skipped instead of losing
 * the results gathered so far.
 */
final class ProbeEngine
{
    /**
     * @param  list<Probe>  $probes
     */
    public function __construct(
        private readonly Application $app,
        private readonly ProbeDatabase $database = new ProbeDatabase,
        private readonly ProbeEnvironment $environment = new ProbeEnvironment,
        private readonly array $probes = [],
    ) {}

    public function run(ProbesConfig $config, int $deadline): ProbeReport
    {
        $this->database->prepare($config);
        $this->environment->install();

        $map = new ApplicationMap;
        $client = new HttpClient($this->app->make(Kernel::class));
        $scanContext = ScanContext::fromApplication($this->app);
        $targets = ProbeTargets::fromSuspicions($scanContext);

        $userModel = $this->userModel();
        $ownership = $userModel === null ? null : new OwnershipResolver($map, $config->owners, $userModel);
        $data = $ownership === null ? null : new DataSelector($config, $ownership, $map);

        $findings = [];
        $coverage = [];
        $notices = [];

        if ($this->probes === []) {
            $notices[] = new Notice('probes', 'no probes yet');
        }

        $deadlineAt = microtime(true) + $deadline;
        $connection = DB::connection($config->connection);

        foreach ($this->probes as $probe) {
            if (microtime(true) > $deadlineAt) {
                $coverage[] = new CoverageEntry(
                    $probe->id(),
                    0,
                    0,
                    [],
                    [new CoverageTarget('all remaining targets', 'time limit')],
                );

                continue;
            }

            $collector = new CoverageCollector;
            $context = new ProbeContext($client, $map, $collector, $config, $scanContext, $ownership, $data, $targets);

            // Every probe runs in a transaction that is always rolled back, so the probe database
            // is left the way it was found (application code then works on savepoints).
            $connection->beginTransaction();

            try {
                foreach ($probe->run($context) as $finding) {
                    $findings[] = $finding;
                }
            } finally {
                $connection->rollBack();
            }

            $coverage[] = $collector->entry($probe->id());
        }

        return new ProbeReport($findings, $coverage, $notices);
    }

    /**
     * The user model of the application, from the default guard's provider. Null when it cannot be
     * resolved, in which case probes that need owners and records report it in their coverage.
     *
     * @return ?class-string<Model>
     */
    private function userModel(): ?string
    {
        $guard = config('auth.defaults.guard');
        $provider = is_string($guard) ? config('auth.guards.'.$guard.'.provider') : null;
        $model = is_string($provider) ? config('auth.providers.'.$provider.'.model') : null;
        $model ??= config('auth.providers.users.model');

        if (is_string($model) && class_exists($model) && is_subclass_of($model, Model::class)) {
            return $model;
        }

        return null;
    }
}
