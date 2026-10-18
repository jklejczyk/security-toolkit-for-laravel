<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Notice;
use Jklejczyk\SecurityToolkit\Core\ScanRunner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesScanner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol\ProbeReport;

describe('availability', function () {
    it('is unavailable without a configured connection', function () {
        config(['security-toolkit.probes.connection' => null]);

        $availability = (new ProbesScanner)->availability();

        expect($availability->available)->toBeFalse()
            ->and($availability->reason)->toContain('SECURITY_TOOLKIT_PROBES_CONNECTION');
    });

    it('is unavailable with an unknown data mode', function () {
        config([
            'security-toolkit.probes.connection' => 'probes',
            'security-toolkit.probes.data' => 'nope',
        ]);

        expect((new ProbesScanner)->availability()->available)->toBeFalse();
    });

    it('is available with a connection and a known data mode', function () {
        config([
            'security-toolkit.probes.connection' => 'probes',
            'security-toolkit.probes.data' => 'auto',
        ]);

        expect((new ProbesScanner)->availability()->available)->toBeTrue();
    });

    it('never starts the probe process without a connection', function () {
        config(['security-toolkit.probes.connection' => null]);

        $report = (new ScanRunner)->run([new ProbesScanner], localContext());

        expect($report->unavailable)->toHaveCount(1)
            ->and($report->unavailable[0]->scannerId)->toBe('probes');

        Process::assertNothingRan();
    });
});

describe('blocks', function () {
    it('refuses in production', function () {
        config(['security-toolkit.probes.connection' => 'probes']);

        $result = (new ProbesScanner)->scan(productionContext());

        expect($result->skipped)->toHaveCount(1)
            ->and($result->skipped[0]->checkId)->toBe('probes')
            ->and($result->skipped[0]->reason)->toContain('production');

        Process::assertNothingRan();
    });

    it('refuses when the configuration is cached', function () {
        $root = sys_get_temp_dir().'/security-toolkit-'.bin2hex(random_bytes(6));
        mkdir($root.'/bootstrap/cache', 0777, true);
        touch($root.'/bootstrap/cache/config.php');

        config(['security-toolkit.probes.connection' => 'probes']);

        try {
            $result = (new ProbesScanner)->scan(localContext(basePath: $root));

            expect($result->skipped[0]->reason)->toContain('config:clear');
        } finally {
            File::deleteDirectory($root);
        }

        Process::assertNothingRan();
    });

    it('refuses an unknown connection', function () {
        config(['security-toolkit.probes.connection' => 'does-not-exist']);

        $result = (new ProbesScanner)->scan(localContext());

        expect($result->skipped[0]->reason)->toContain('not defined');

        Process::assertNothingRan();
    });

    it('refuses the application database without the flag', function () {
        config([
            'database.default' => 'app',
            'database.connections.app' => ['driver' => 'mysql', 'host' => 'db', 'port' => '3306', 'database' => 'shop'],
            'database.connections.probes' => ['driver' => 'mysql', 'host' => 'db', 'port' => '3306', 'database' => 'shop'],
            'security-toolkit.probes.connection' => 'probes',
        ]);

        $result = (new ProbesScanner)->scan(localContext());

        expect($result->skipped[0]->reason)->toContain('allow_app_database');

        Process::assertNothingRan();
    });

    it('treats another sqlite file as a different database', function () {
        config([
            'database.default' => 'app',
            'database.connections.app' => ['driver' => 'sqlite', 'database' => '/tmp/a.sqlite'],
            'database.connections.probes' => ['driver' => 'sqlite', 'database' => '/tmp/b.sqlite'],
            'security-toolkit.probes.connection' => 'probes',
        ]);

        Process::fake(fn () => Process::result(output: '{}'));

        (new ProbesScanner)->scan(localContext());

        Process::assertRan(fn ($process) => true);
    });

    it('refuses migrations on a database that already has tables', function () {
        config([
            'security-toolkit.probes.connection' => 'testing',
            'security-toolkit.probes.migrate' => true,
            'security-toolkit.probes.allow_app_database' => false,
        ]);

        Schema::connection('testing')->create('probe_existing', fn ($table) => $table->id());

        try {
            $result = (new ProbesScanner)->scan(localContext());

            expect($result->skipped[0]->reason)->toContain('not empty');
        } finally {
            Schema::connection('testing')->drop('probe_existing');
        }

        Process::assertNothingRan();
    });
});

describe('running', function () {
    it('runs the child process and maps its report', function () {
        config(['security-toolkit.probes.connection' => 'testing']);

        $json = (new ProbeReport(
            [new Finding('probes.idor', Severity::Medium, 'IDOR', 'description', 'remediation')],
            [new CoverageEntry('routes', 1, 1)],
            [new Notice('probes', 'no probes yet')],
        ))->toJson();

        Process::fake(fn () => Process::result(output: "noise\n".$json));

        $result = (new ProbesScanner)->scan(localContext());

        expect($result->findings)->toHaveCount(1)
            ->and($result->findings[0]->ruleId)->toBe('probes.idor')
            ->and($result->coverage[0]->probe)->toBe('routes')
            ->and($result->notices[0]->message)->toBe('no probes yet');

        Process::assertRan(fn ($process) => in_array('security:probe', $process->command, true)
            && in_array('--internal', $process->command, true));
    });

    it('reports a warning when it ran against the application database on purpose', function () {
        config([
            'database.default' => 'app',
            'database.connections.app' => ['driver' => 'sqlite', 'database' => '/tmp/same.sqlite'],
            'database.connections.probes' => ['driver' => 'sqlite', 'database' => '/tmp/same.sqlite'],
            'security-toolkit.probes.connection' => 'probes',
            'security-toolkit.probes.allow_app_database' => true,
        ]);

        Process::fake(fn () => Process::result(output: '{}'));

        $result = (new ProbesScanner)->scan(localContext());

        expect($result->skipped)->toBe([])
            ->and($result->notices[0]->message)->toContain('application database');
    });

    it('fails the scan when the child process fails', function () {
        config(['security-toolkit.probes.connection' => 'testing']);

        Process::fake(fn () => Process::result(output: '', errorOutput: 'boom', exitCode: 1));

        (new ProbesScanner)->scan(localContext());
    })->throws(RuntimeException::class, 'boom');
});
