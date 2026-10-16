<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Files\Checks\PrivateStorageLinkedCheck;

beforeEach(function () {
    $this->root = temporaryApp();
});

afterEach(function () {
    File::deleteDirectory($this->root);
});

/**
 * @return list<Finding>
 */
function linkedStorageFindings(string $root): array
{
    return iterator_to_array((new PrivateStorageLinkedCheck)->run(productionContext(basePath: $root)), false);
}

it('is a production-only check', function () {
    expect((new PrivateStorageLinkedCheck)->onlyInProduction())->toBeTrue()
        ->and((new PrivateStorageLinkedCheck)->id())->toBe('files.private-storage-linked');
});

it('accepts the default link to the public disk', function () {
    symlink($this->root.'/storage/app/public', $this->root.'/public/storage');

    expect(linkedStorageFindings($this->root))->toBe([]);
});

it('reports a configured link that exposes a private disk', function () {
    config(['filesystems.links' => [$this->root.'/public/backups' => $this->root.'/storage/app']]);

    $findings = linkedStorageFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('files.private-storage-linked')
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([552])
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N')
        ->and($findings[0]->title)->toContain('public/backups')
        ->and($findings[0]->description)->toContain('"local"')
        ->and($findings[0]->location?->file)->toBe('config/filesystems.php');
});

it('reports a link to logs, sessions or cache as high', function () {
    config(['filesystems.links' => [$this->root.'/public/files' => $this->root.'/storage']]);

    $findings = linkedStorageFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');
});

it('reports a symlink created by hand with a relative target', function () {
    config(['filesystems.links' => []]);
    symlink('../storage/app/private', $this->root.'/public/files');

    $findings = linkedStorageFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->location?->file)->toBe('public/files');
});

it('reports a link found both in the config and on disk once', function () {
    config(['filesystems.links' => [$this->root.'/public/backups' => $this->root.'/storage/app']]);
    symlink($this->root.'/storage/app', $this->root.'/public/backups');

    $findings = linkedStorageFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->location?->file)->toBe('config/filesystems.php');
});

it('ignores dangling symlinks and links outside storage', function () {
    mkdir($this->root.'/docs');
    symlink($this->root.'/missing', $this->root.'/public/broken');
    config(['filesystems.links' => [$this->root.'/public/docs' => $this->root.'/docs']]);

    expect(linkedStorageFindings($this->root))->toBe([]);
});

it('treats a disk inside a public disk, or with a URL, as public', function (string $root, array $extra) {
    mkdir($this->root.'/'.$root, 0777, true);
    config([
        'filesystems.disks.extra' => ['driver' => 'local', 'root' => $this->root.'/'.$root, ...$extra],
        'filesystems.links' => [$this->root.'/public/storage' => $this->root.'/storage/app/public', $this->root.'/public/downloads' => $this->root.'/storage/app/downloads'],
    ]);

    expect(linkedStorageFindings($this->root))->toBe([]);
})->with([
    'nested in the public disk, no visibility' => ['storage/app/public/avatars', []],
    'own link and a URL' => ['storage/app/downloads', ['url' => 'https://example.com/downloads']],
]);

it('rates a link by how easily its files are found', function (string $directory, Severity $severity, string $vector) {
    config(['filesystems.links' => [$this->root.'/public/internal' => $this->root.'/storage/'.$directory]]);

    $findings = linkedStorageFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe($severity)
        ->and($findings[0]->cvss?->vector)->toBe($vector)
        ->and($findings[0]->description)->toContain('storage/'.$directory);
})->with([
    // storage/logs/laravel.log has a well-known name.
    'logs' => ['logs', Severity::High, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'],
    // Session files are named by random IDs and cache files by hashes, so they have to be guessed.
    'framework only' => ['framework', Severity::Medium, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'],
]);

it('still checks configured links when the public directory cannot be listed', function () {
    config(['filesystems.links' => [$this->root.'/public/backups' => $this->root.'/storage/app']]);
    chmod($this->root.'/public', 0000);

    try {
        expect(linkedStorageFindings($this->root))->toHaveCount(1);
    } finally {
        chmod($this->root.'/public', 0755);
    }
});
