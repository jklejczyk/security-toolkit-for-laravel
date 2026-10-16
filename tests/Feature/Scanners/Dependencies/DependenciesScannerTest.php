<?php

declare(strict_types=1);

use Illuminate\Process\PendingProcess;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;
use Jklejczyk\SecurityToolkit\Core\ScannerRegistry;
use Jklejczyk\SecurityToolkit\Core\SkippedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Dependencies\ComposerLocator;
use Jklejczyk\SecurityToolkit\Scanners\Dependencies\DependenciesScanner;
use Symfony\Component\Process\ExecutableFinder;

function composerAt(?string $path): ComposerLocator
{
    return new ComposerLocator(new class($path) extends ExecutableFinder
    {
        public function __construct(private readonly ?string $path) {}

        public function find(string $name, ?string $default = null, array $extraDirs = []): ?string
        {
            return $this->path;
        }
    });
}

it('is registered by the service provider', function () {
    $ids = array_map(fn ($scanner) => $scanner->id(), app(ScannerRegistry::class)->all());

    expect($ids)->toContain('dependencies');
});

it('runs composer audit in the application directory, in any environment', function () {
    Process::fake(['*' => Process::result(output: auditReport(), errorOutput: 'Warning: the lock file is not up to date', exitCode: 3)]);

    $result = (new DependenciesScanner(app(), composerAt('/usr/bin/composer')))->scan(localContext());

    expect($result->findings)->toHaveCount(4)
        ->and($result->skipped)->toBe([]);

    Process::assertRan(fn (PendingProcess $process): bool => $process->command === [
        '/usr/bin/composer', 'audit', '--format=json', '--no-interaction', '--working-dir=/app',
    ]);
});

it('fails when composer audit does not return a report', function () {
    Process::fake(['*' => Process::result(output: '', errorOutput: 'No network', exitCode: 100)]);

    expect(fn () => (new DependenciesScanner(app(), composerAt('/usr/bin/composer')))->scan(productionContext()))
        ->toThrow(RuntimeException::class, 'No network');
});

// Composer 2.2 LTS (e.g. from Ubuntu 22.04 packages) has no audit command.
it('skips the audit on a Composer without the audit command', function () {
    Process::fake(['*' => Process::result(output: '', errorOutput: 'Command "audit" is not defined.', exitCode: 1)]);

    $result = (new DependenciesScanner(app(), composerAt('/usr/bin/composer')))->scan(productionContext());

    expect($result->findings)->toBe([])
        ->and(array_map(fn (SkippedCheck $skipped) => $skipped->checkId, $result->skipped))
        ->toBe(['dependencies.vulnerable-package', 'dependencies.abandoned-package'])
        ->and($result->skipped[0]->reason)->toContain('Composer 2.4');
});

describe('availability', function () {
    beforeEach(function () {
        $this->root = temporaryApp();
        mkdir($this->root.'/vendor/composer', 0777, true);
        file_put_contents($this->root.'/vendor/composer/installed.json', '{"packages": []}');
        file_put_contents($this->root.'/composer.json', '{}');
        app()->setBasePath($this->root);
    });

    afterEach(function () {
        File::deleteDirectory($this->root);
    });

    it('is available with Composer and installed packages', function () {
        expect((new DependenciesScanner(app(), composerAt('/usr/bin/composer')))->availability()->available)->toBeTrue();
    });

    it('is unavailable without a Composer executable', function () {
        $availability = (new DependenciesScanner(app(), composerAt(null)))->availability();

        expect($availability->available)->toBeFalse()
            ->and($availability->reason)->toContain('composer executable not found');
    });

    it('falls back to composer.phar in the application directory', function () {
        touch($this->root.'/composer.phar');

        expect(composerAt(null)->command($this->root))->toBe([PHP_BINARY, $this->root.'/composer.phar'])
            ->and(composerAt('/usr/bin/composer')->command($this->root))->toBe(['/usr/bin/composer']);
    });

    it('is unavailable without composer.json, e.g. in an image that ships only vendor/', function () {
        unlink($this->root.'/composer.json');

        $availability = (new DependenciesScanner(app(), composerAt('/usr/bin/composer')))->availability();

        expect($availability->available)->toBeFalse()
            ->and($availability->reason)->toContain('composer.json');
    });

    it('is unavailable without installed packages', function () {
        unlink($this->root.'/vendor/composer/installed.json');

        $availability = (new DependenciesScanner(app(), composerAt('/usr/bin/composer')))->availability();

        expect($availability->available)->toBeFalse()
            ->and($availability->reason)->toContain('installed.json');
    });
});
