<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Config\Checks;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use ReflectionFunction;
use Throwable;

final class DashboardOpenCheck implements Check
{
    /**
     * Composer package => [dashboard name, gate ability, what the dashboard exposes, documentation URL, config key that switches the dashboard off].
     *
     * @var array<string, array{string, string, string, string, string|null}>
     */
    private const DASHBOARDS = [
        'laravel/telescope' => [
            'Telescope',
            'viewTelescope',
            'In production Telescope records exceptions, failed requests, failed jobs and scheduled tasks with their payloads and context (passwords, cookies and the Authorization header are hidden by default), and its Monitoring page lets anyone start recording every request of a chosen user by tag.',
            'https://laravel.com/docs/telescope#dashboard-authorization',
            'telescope.enabled',
        ],
        'laravel/horizon' => [
            'Horizon',
            'viewHorizon',
            'Horizon shows the data of pending, completed and failed jobs, which often includes personal data and tokens, and lets the user retry failed jobs.',
            'https://laravel.com/docs/horizon#dashboard-authorization',
            null,
        ],
        'laravel/pulse' => [
            'Pulse',
            'viewPulse',
            'Pulse shows the most active users with their names and email addresses, slow requests and queries, and exceptions, revealing user identities and internals of the application.',
            'https://laravel.com/docs/pulse#dashboard-authorization',
            null,
        ],
        'opcodesio/log-viewer' => [
            'Log Viewer',
            'viewLogViewer',
            'Log Viewer lets the user read and download the application logs, which often contain personal data, tokens and exception details, and by default also delete them, which can hide traces of an attack.',
            'https://github.com/opcodesio/log-viewer',
            'log-viewer.enabled',
        ],
    ];

    public function id(): string
    {
        return 'config.dashboard-open';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        $failures = [];

        foreach (self::DASHBOARDS as $package => [$dashboard, $ability, $exposure, $documentation, $enabledKey]) {
            if (! $context->packages->isInstalled($package) || ! Gate::has($ability)) {
                continue;
            }

            // A switched-off dashboard registers no routes, so its gate exposes nothing.
            if ($enabledKey !== null && ! (bool) config($enabledKey, true)) {
                continue;
            }

            $user = $this->anyUser();

            try {
                $allowed = Gate::forUser($user)->allows($ability);
            } catch (Throwable $exception) {
                $failures[] = sprintf('could not evaluate the %s gate: %s', $ability, $exception->getMessage());

                continue;
            }

            if ($allowed) {
                yield $this->finding($dashboard, $ability, $exposure, $documentation, $context);
            }
        }

        if ($failures !== []) {
            throw CheckSkipped::because(implode('; ', $failures));
        }
    }

    /**
     * A fresh, unsaved user: if the gate lets this user in, it lets every logged-in user in.
     *
     * @throws CheckSkipped
     */
    private function anyUser(): Authenticatable
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! class_exists($model)) {
            throw CheckSkipped::because('the user model (auth.providers.users.model) could not be resolved');
        }

        try {
            $user = new $model;
        } catch (Throwable $exception) {
            throw CheckSkipped::because(sprintf('could not instantiate the user model %s: %s', $model, $exception->getMessage()));
        }

        if (! $user instanceof Authenticatable) {
            throw CheckSkipped::because(sprintf('the user model %s is not Authenticatable', $model));
        }

        return $user;
    }

    private function finding(string $dashboard, string $ability, string $exposure, string $documentation, ScanContext $context): Finding
    {
        return new Finding(
            $this->id(),
            Severity::High,
            sprintf('%s dashboard is open to every logged-in user', $dashboard),
            sprintf('The %s gate allows any logged-in user, so every account holder can open the %s dashboard. %s', $ability, $dashboard, $exposure),
            sprintf('Allow only specific users in the %s gate, for example by email or role, or do not run %s in production.', $ability, $dashboard),
            [$documentation],
            $this->gateLocation($ability, $context),
        );
    }

    private function gateLocation(string $ability, ScanContext $context): ?Location
    {
        $callback = Gate::abilities()[$ability] ?? null;

        if (! $callback instanceof Closure) {
            return null;
        }

        $reflection = new ReflectionFunction($callback);
        $file = $reflection->getFileName();

        if ($file === false) {
            return null;
        }

        $prefix = rtrim($context->basePath, '/').'/';

        return new Location(
            str_starts_with($file, $prefix) ? substr($file, strlen($prefix)) : $file,
            $reflection->getStartLine() ?: null,
        );
    }
}
