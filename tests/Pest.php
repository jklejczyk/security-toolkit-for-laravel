<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\InstalledPackages;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Tests\TestCase;

pest()->extend(TestCase::class)->in('Feature');

/**
 * @param  list<string>  $packages
 */
function productionContext(array $packages = [], string $basePath = '/app'): ScanContext
{
    return new ScanContext('production', $basePath, InstalledPackages::fromList($packages));
}

/**
 * @param  list<string>  $packages
 */
function localContext(array $packages = [], string $basePath = '/app'): ScanContext
{
    return new ScanContext('local', $basePath, InstalledPackages::fromList($packages));
}

/**
 * Creates a temporary application directory with the default public and storage layout
 * and points app_path(), public_path() and storage_path() at it. Delete it with File::deleteDirectory().
 */
function temporaryApp(): string
{
    $root = sys_get_temp_dir().'/security-toolkit-'.bin2hex(random_bytes(6));

    foreach (['app', 'public', 'storage/app/public', 'storage/app/private', 'storage/logs', 'storage/framework'] as $directory) {
        mkdir($root.'/'.$directory, 0777, true);
    }

    // Resolved paths, so the expected values match what the checks compute when /tmp is a symlink.
    $root = (string) realpath($root);

    app()->useAppPath($root.'/app');
    app()->usePublicPath($root.'/public');
    app()->useStoragePath($root.'/storage');

    config([
        'filesystems.disks' => [
            'local' => ['driver' => 'local', 'root' => $root.'/storage/app/private'],
            'public' => ['driver' => 'local', 'root' => $root.'/storage/app/public', 'visibility' => 'public'],
            's3' => ['driver' => 's3', 'bucket' => 'files'],
        ],
        'filesystems.links' => [$root.'/public/storage' => $root.'/storage/app/public'],
    ]);

    return $root;
}
