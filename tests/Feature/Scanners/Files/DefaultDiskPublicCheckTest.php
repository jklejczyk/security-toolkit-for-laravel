<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Files\Checks\DefaultDiskPublicCheck;

beforeEach(function () {
    $this->root = temporaryApp();
});

afterEach(function () {
    File::deleteDirectory($this->root);
});

/**
 * @return list<Finding>
 */
function defaultDiskFindings(string $root): array
{
    return iterator_to_array((new DefaultDiskPublicCheck)->run(productionContext(basePath: $root)), false);
}

it('is a production-only check', function () {
    expect((new DefaultDiskPublicCheck)->onlyInProduction())->toBeTrue()
        ->and((new DefaultDiskPublicCheck)->id())->toBe('files.default-disk-public');
});

it('reports a default disk served through the storage link', function () {
    config(['filesystems.default' => 'public']);

    $findings = defaultDiskFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('files.default-disk-public')
        ->and($findings[0]->severity)->toBe(Severity::Low)
        ->and($findings[0]->cwe)->toBe([552])
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N')
        ->and($findings[0]->title)->toContain('"public"')
        ->and($findings[0]->location?->file)->toBe('config/filesystems.php');
});

it('reports a default disk inside the public directory', function () {
    config([
        'filesystems.default' => 'uploads',
        'filesystems.disks.uploads' => ['driver' => 'local', 'root' => $this->root.'/public/uploads'],
    ]);

    expect(defaultDiskFindings($this->root))->toHaveCount(1);
});

it('does not report a default disk the web server does not serve', function (string $disk) {
    config(['filesystems.default' => $disk]);

    expect(defaultDiskFindings($this->root))->toBe([]);
})->with(['local', 's3', 'missing']);

it('does not report a public disk that is not linked', function () {
    config(['filesystems.default' => 'public', 'filesystems.links' => []]);

    expect(defaultDiskFindings($this->root))->toBe([]);
});
