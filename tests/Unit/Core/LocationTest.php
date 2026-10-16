<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Location;

it('stores files inside the application relative to its root', function () {
    expect(Location::inApplication('/app/config/session.php', '/app'))
        ->toEqual(new Location('config/session.php'))
        ->and(Location::inApplication('/app/routes/web.php', '/app/', 7))
        ->toEqual(new Location('routes/web.php', 7));
});

it('keeps files outside the application absolute', function () {
    expect(Location::inApplication('/srv/shared/web.php', '/app'))->toEqual(new Location('/srv/shared/web.php'))
        ->and(Location::inApplication('/application/web.php', '/app'))->toEqual(new Location('/application/web.php'));
});

it('points at the line where a closure is defined', function () {
    $line = __LINE__ + 1;
    $closure = fn (): bool => true;

    expect(Location::ofClosure($closure, dirname(__DIR__, 3)))
        ->toEqual(new Location('tests/Unit/Core/LocationTest.php', $line));
});

// Envoyer and Forge deploy to releases/N and point a "current" symlink at it.
it('stores files relative to an application root reached through a symlink', function () {
    $root = sys_get_temp_dir().'/security-toolkit-location-'.bin2hex(random_bytes(6));
    mkdir($root.'/releases/42/public', 0777, true);
    symlink($root.'/releases/42', $root.'/current');

    try {
        expect(Location::inApplication((string) realpath($root.'/releases/42/public').'/backups', $root.'/current'))
            ->toEqual(new Location('public/backups'));
    } finally {
        unlink($root.'/current');
        rmdir($root.'/releases/42/public');
        rmdir($root.'/releases/42');
        rmdir($root.'/releases');
        rmdir($root);
    }
});
