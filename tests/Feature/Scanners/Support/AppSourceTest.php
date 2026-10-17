<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Scanners\Support\AppSource;

beforeEach(function () {
    $this->root = temporaryApp();
});

afterEach(function () {
    File::deleteDirectory($this->root);
});

it('searches PHP files in nested directories of the app path', function () {
    mkdir($this->root.'/app/Http/Controllers', 0777, true);
    file_put_contents($this->root.'/app/Http/Controllers/TokenController.php', '<?php $user->createToken("api");');
    file_put_contents($this->root.'/app/notes.txt', 'Password::default()');

    expect((new AppSource)->contains('/createToken\(/'))->toBeTrue()
        ->and((new AppSource)->contains('/Password::default\(\)/'))->toBeFalse();
});

it('follows a custom application path', function () {
    mkdir($this->root.'/src/Domain', 0777, true);
    file_put_contents($this->root.'/src/Domain/Rules.php', '<?php Password::default();');
    app()->useAppPath($this->root.'/src');

    expect((new AppSource)->contains('/Password::default\(\)/'))->toBeTrue();
});

it('finds nothing without an app directory', function () {
    File::deleteDirectory($this->root.'/app');

    expect((new AppSource)->contains('/x/'))->toBeFalse();
});

// An unread file may hold the evidence, so the result would be a guess.
it('skips instead of guessing when a file cannot be read', function () {
    file_put_contents($this->root.'/app/Secret.php', '<?php');
    chmod($this->root.'/app/Secret.php', 0000);

    expect(fn () => (new AppSource)->contains('/x/'))->toThrow(CheckSkipped::class, 'could not read');
});

it('skips instead of guessing when a directory cannot be read', function () {
    mkdir($this->root.'/app/Locked');
    chmod($this->root.'/app/Locked', 0000);

    try {
        expect(fn () => (new AppSource)->contains('/x/'))->toThrow(CheckSkipped::class, 'could not read');
    } finally {
        chmod($this->root.'/app/Locked', 0755);
    }
});

it('skips instead of guessing when the search itself fails', function () {
    file_put_contents($this->root.'/app/Big.php', '<?php // '.str_repeat('a', 50).'c');
    // The JIT ignores the backtrack limit, so it is switched off to force the failure.
    $limit = ini_get('pcre.backtrack_limit');
    $jit = ini_get('pcre.jit');
    ini_set('pcre.backtrack_limit', '10');
    ini_set('pcre.jit', '0');

    try {
        expect(fn () => (new AppSource)->contains('/(a+)+$/'))->toThrow(CheckSkipped::class, 'could not search');
    } finally {
        ini_set('pcre.backtrack_limit', (string) $limit);
        ini_set('pcre.jit', (string) $jit);
    }
});
