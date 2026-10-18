<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Throwable;

/**
 * The reasons probes refuse to run, in order, and the same-database comparison behind them. Each
 * returns a message the scan reports as a skipped check instead of running the probe process.
 */
final class ProbeBlocker
{
    public function reason(ScanContext $context, ProbesConfig $config): ?string
    {
        if ($context->isProduction()) {
            return 'refusing to run probes in the production environment';
        }

        if (file_exists($context->basePath.'/bootstrap/cache/config.php')) {
            return 'the configuration is cached; run "php artisan config:clear" so the probe process can override it';
        }

        $connections = config('database.connections');
        $connections = is_array($connections) ? $connections : [];

        if (! array_key_exists((string) $config->connection, $connections)) {
            return sprintf('the connection "%s" is not defined in config/database.php', $config->connection);
        }

        if ($this->sharesWithApplication($config)) {
            if (! $config->allowAppDatabase) {
                return sprintf(
                    'the connection "%s" is the application database; set probes.allow_app_database to run against it on purpose',
                    $config->connection,
                );
            }
        } elseif ($config->migrate && $this->hasTables($config)) {
            return 'the probe database is not empty; migrations only run on an empty database (they never wipe data)';
        }

        return null;
    }

    /**
     * True when the probe connection points at the same database as the application default.
     */
    public function sharesWithApplication(ProbesConfig $config): bool
    {
        $connections = config('database.connections');
        $connections = is_array($connections) ? $connections : [];

        $default = config('database.default');

        $probe = $this->connection($connections, (string) $config->connection);
        $defaultConnection = $this->connection($connections, is_string($default) ? $default : '');

        if ($probe === null || $defaultConnection === null) {
            return false;
        }

        return $this->sameDatabase($probe, $defaultConnection);
    }

    /**
     * @param  array<array-key, mixed>  $connections
     * @return array<array-key, mixed>|null
     */
    private function connection(array $connections, string $name): ?array
    {
        if ($name === '') {
            return null;
        }

        $connection = $connections[$name] ?? null;

        return is_array($connection) ? $connection : null;
    }

    /**
     * @param  array<array-key, mixed>  $a
     * @param  array<array-key, mixed>  $b
     */
    private function sameDatabase(array $a, array $b): bool
    {
        if (($a['driver'] ?? null) !== ($b['driver'] ?? null)) {
            return false;
        }

        if (($a['driver'] ?? null) === 'sqlite') {
            $path = $this->sqlitePath($a);

            return $path !== ':memory:' && $path === $this->sqlitePath($b);
        }

        return ($a['host'] ?? null) === ($b['host'] ?? null)
            && ($a['port'] ?? null) === ($b['port'] ?? null)
            && ($a['database'] ?? null) === ($b['database'] ?? null);
    }

    /**
     * @param  array<array-key, mixed>  $connection
     */
    private function sqlitePath(array $connection): string
    {
        $database = $connection['database'] ?? ':memory:';

        if (! is_string($database) || $database === ':memory:') {
            return ':memory:';
        }

        $resolved = realpath($database);

        return $resolved === false ? $database : $resolved;
    }

    private function hasTables(ProbesConfig $config): bool
    {
        try {
            return Schema::connection($config->connection)->getTableListing() !== [];
        } catch (Throwable) {
            // A database that cannot be read yet is treated as empty, so migrations may create it.
            return false;
        }
    }
}
