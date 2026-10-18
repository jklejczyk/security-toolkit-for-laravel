<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Engine;

use Illuminate\Support\Facades\Artisan;
use Jklejczyk\SecurityToolkit\Scanners\Models\AppModels;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use RuntimeException;
use Throwable;

/**
 * Prepares the probe database inside the child process: verifies that the application default
 * connection really is the probes connection, refuses models that write elsewhere, and runs
 * migrations when asked. It never wipes a database.
 */
final class ProbeDatabase
{
    public function __construct(
        private readonly AppModels $models = new AppModels,
    ) {}

    public function prepare(ProbesConfig $config): void
    {
        $default = config('database.default');

        if ($default !== $config->connection) {
            throw new RuntimeException(sprintf(
                'the probe process uses connection "%s", but the application default is "%s"; the overrides did not take effect',
                (string) $config->connection,
                is_string($default) ? $default : 'null',
            ));
        }

        $foreign = $this->modelsWithForeignConnection((string) $config->connection);

        if ($foreign !== []) {
            throw new RuntimeException(
                'these models write through a different connection than the probes, so their writes would leave the probe database: '.implode(', ', $foreign),
            );
        }

        if ($config->migrate) {
            Artisan::call('migrate', ['--database' => $config->connection, '--force' => true]);
        }
    }

    /**
     * @return list<class-string>
     */
    private function modelsWithForeignConnection(string $connection): array
    {
        try {
            $models = $this->models->all();
        } catch (Throwable) {
            return [];
        }

        $foreign = [];

        foreach ($models as $model) {
            try {
                $name = (new $model['class'])->getConnectionName();
            } catch (Throwable) {
                continue;
            }

            if (is_string($name) && $name !== $connection) {
                $foreign[] = $model['class'];
            }
        }

        return $foreign;
    }
}
