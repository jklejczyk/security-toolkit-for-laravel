<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Scanners\Support\PublicRegistration;

beforeEach(function () {
    config([
        'auth.defaults.guard' => 'web',
        'auth.guards.web' => ['driver' => 'session', 'provider' => 'users'],
        'auth.guards.admin' => ['driver' => 'session', 'provider' => 'admins'],
    ]);
});

function routeNamed(string $name): RouteInfo
{
    foreach ((new ApplicationMap)->routes() as $route) {
        if ($route->name === $name) {
            return $route;
        }
    }

    throw new RuntimeException("no route {$name}");
}

it('finds a public registration route and labels it', function () {
    Route::middleware(['web', 'guest'])->post('register', fn () => 'ok')->name('register.store');

    $registration = (new PublicRegistration)->route((new ApplicationMap)->routes());

    expect($registration)->not->toBeNull()
        ->and((new PublicRegistration)->label($registration))->toBe('POST /register');
});

it('ignores registration that needs a login', function () {
    Route::middleware(['web', 'auth'])->post('register', fn () => 'ok')->name('register.store');

    expect((new PublicRegistration)->route((new ApplicationMap)->routes()))->toBeNull();
});

it('reaches routes behind the default guard, a listed guard or sanctum', function (string $middleware) {
    Route::middleware($middleware)->get('posts', fn () => 'ok')->name('posts');

    expect((new PublicRegistration)->reaches(routeNamed('posts')))->toBeTrue();
})->with(['auth', 'auth:admin,web', 'auth:sanctum']);

it('reaches the default guard when it is not web', function () {
    config([
        'auth.defaults.guard' => 'api',
        'auth.guards.api' => ['driver' => 'session', 'provider' => 'users'],
    ]);
    Route::middleware('auth')->get('posts', fn () => 'ok')->name('posts');

    expect((new PublicRegistration)->reaches(routeNamed('posts')))->toBeTrue();
});

it('does not reach other providers or unknown guards', function (string $middleware) {
    config(['auth.guards.custom' => ['driver' => 'custom']]);
    Route::middleware($middleware)->get('posts', fn () => 'ok')->name('posts');

    expect((new PublicRegistration)->reaches(routeNamed('posts')))->toBeFalse();
})->with(['auth:admin', 'auth:custom', 'auth:missing']);
