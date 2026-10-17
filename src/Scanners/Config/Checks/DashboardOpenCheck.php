<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Config\Checks;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Throwable;

final class DashboardOpenCheck implements Check
{
    /**
     * Composer package => [dashboard name, gate ability, what the dashboard exposes, documentation URL,
     * config key that switches the dashboard off, CVSS vector for a logged-in user who should not get in].
     *
     * @var array<string, array{string, string, string, string, string|null, string}>
     */
    private const DASHBOARDS = [
        'laravel/telescope' => [
            'Telescope',
            'viewTelescope',
            'In production Telescope records exceptions, failed requests, failed jobs and scheduled tasks with their payloads and context (passwords, cookies and the Authorization header are hidden by default), and its Monitoring page lets anyone start recording every request of a chosen user by tag.',
            'https://laravel.com/docs/telescope#dashboard-authorization',
            'telescope.enabled',
            'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L',
        ],
        'laravel/horizon' => [
            'Horizon',
            'viewHorizon',
            'Horizon shows the data of pending, completed and failed jobs, which often includes personal data and tokens, and lets the user retry failed jobs.',
            'https://laravel.com/docs/horizon#dashboard-authorization',
            null,
            'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',
        ],
        'laravel/pulse' => [
            'Pulse',
            'viewPulse',
            'Pulse shows the most active users with their names and email addresses, slow requests and queries, and exceptions, revealing user identities and internals of the application.',
            'https://laravel.com/docs/pulse#dashboard-authorization',
            null,
            'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
        ],
        'opcodesio/log-viewer' => [
            'Log Viewer',
            'viewLogViewer',
            'Log Viewer lets the user read and download the application logs, which often contain personal data, tokens and exception details, and by default also delete them, which can hide traces of an attack.',
            'https://github.com/opcodesio/log-viewer',
            'log-viewer.enabled',
            'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L',
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

        foreach (self::DASHBOARDS as $package => [$dashboard, $ability, $exposure, $documentation, $enabledKey, $vector]) {
            if (! $context->packages->isInstalled($package)) {
                continue;
            }

            // A switched-off dashboard registers no routes, so its gate exposes nothing.
            if ($enabledKey !== null && ! (bool) config($enabledKey, true)) {
                continue;
            }

            if (! Gate::has($ability)) {
                try {
                    if ($package === 'opcodesio/log-viewer' && $this->logViewerOpenWithoutGate()) {
                        yield $this->openToEveryoneWithoutGate($dashboard, $ability, $exposure, $documentation, $vector);
                    }
                } catch (CheckSkipped $skipped) {
                    $failures[] = $skipped->getMessage();
                }

                continue;
            }

            try {
                // The gate only lets guests in when its callback accepts a null user, like the
                // `function ($user = null)` in the Horizon stub.
                if (Gate::forUser(null)->allows($ability)) {
                    yield $this->openToEveryone($dashboard, $ability, $exposure, $documentation, $vector, $context);

                    continue;
                }

                $allowed = Gate::forUser($this->anyUser())->allows($ability);
            } catch (CheckSkipped $skipped) {
                throw $skipped;
            } catch (Throwable $exception) {
                $failures[] = sprintf('could not evaluate the %s gate: %s', $ability, $exception->getMessage());

                continue;
            }

            if ($allowed) {
                yield $this->finding($dashboard, $ability, $exposure, $documentation, $vector, $context);
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

    private function finding(string $dashboard, string $ability, string $exposure, string $documentation, string $vector, ScanContext $context): Finding
    {
        $cvss = Cvss::fromVector($vector);

        return new Finding(
            $this->id(),
            $cvss->severity(),
            sprintf('%s dashboard is open to every logged-in user', $dashboard),
            sprintf('The %s gate allows any logged-in user, so every account holder can open the %s dashboard. %s', $ability, $dashboard, $exposure),
            sprintf('Allow only specific users in the %s gate, for example by email or role, or do not run %s in production.', $ability, $dashboard),
            [$documentation],
            $this->gateLocation($ability, $context),
            cwe: [862],
            cvss: $cvss,
        );
    }

    private function openToEveryone(string $dashboard, string $ability, string $exposure, string $documentation, string $vector, ScanContext $context): Finding
    {
        $cvss = Cvss::fromVector($this->withoutPrivileges($vector));

        return new Finding(
            $this->id(),
            $cvss->severity(),
            sprintf('%s dashboard is open to everyone', $dashboard),
            sprintf('The %s gate accepts a guest (its user parameter is nullable) and allows them, so anyone who knows the URL can open the %s dashboard without logging in. %s', $ability, $dashboard, $exposure),
            sprintf('Make the user parameter of the %s gate required and allow only specific users, for example by email or role, or do not run %s in production.', $ability, $dashboard),
            [$documentation],
            $this->gateLocation($ability, $context),
            cwe: [862],
            cvss: $cvss,
        );
    }

    private function openToEveryoneWithoutGate(string $dashboard, string $ability, string $exposure, string $documentation, string $vector): Finding
    {
        $cvss = Cvss::fromVector($this->withoutPrivileges($vector));

        return new Finding(
            $this->id(),
            $cvss->severity(),
            sprintf('%s dashboard is open to everyone', $dashboard),
            sprintf('There is no %s gate and no LogViewer::auth() callback, and log-viewer.require_auth_in_production is false, so anyone who knows the URL can open the %s dashboard without logging in. %s', $ability, $dashboard, $exposure),
            sprintf('Define the %s gate allowing only specific users, and set log-viewer.require_auth_in_production to true.', $ability),
            [$documentation],
            cwe: [862],
            cvss: $cvss,
        );
    }

    /**
     * Log Viewer refuses to open in production without a gate or an auth callback, unless
     * require_auth_in_production is false; the default mirrors its AuthorizeLogViewer middleware.
     */
    private function logViewerOpenWithoutGate(): bool
    {
        if ((bool) config('log-viewer.require_auth_in_production', false)) {
            return false;
        }

        $facade = 'Opcodes\LogViewer\Facades\LogViewer';
        $hasAuthCallback = [$facade, 'hasAuthCallback'];

        if (! class_exists($facade) || ! is_callable($hasAuthCallback)) {
            throw CheckSkipped::because('could not check whether Log Viewer has an auth callback');
        }

        return ! (bool) call_user_func($hasAuthCallback);
    }

    /**
     * The same attack without an account: the vector of a dashboard open to every logged-in user
     * with no privileges required.
     */
    private function withoutPrivileges(string $vector): string
    {
        return str_replace('/PR:L/', '/PR:N/', $vector);
    }

    private function gateLocation(string $ability, ScanContext $context): ?Location
    {
        $callback = Gate::abilities()[$ability] ?? null;

        return $callback instanceof Closure ? Location::ofClosure($callback, $context->basePath) : null;
    }
}
