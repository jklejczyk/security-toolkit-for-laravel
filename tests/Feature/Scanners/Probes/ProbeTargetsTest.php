<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\PostController;

beforeEach(function () {
    app()->useAppPath(dirname(__DIR__, 3).'/Fixtures/Map');
});

it('builds a target for a route behind a suspicion', function () {
    Route::put('posts/{post}', [PostController::class, 'update'])->name('posts.update');

    $targets = ProbeTargets::fromSuspicions(localContext());

    $found = $targets->forRule('routes.missing-authentication');

    expect($found)->toHaveCount(1)
        ->and($found[0]->route->uri)->toBe('posts/{post}')
        ->and($found[0]->route->methods)->toBe(['PUT'])
        ->and($found[0]->suspicion->ruleId)->toBe('routes.missing-authentication');
});

it('returns nothing for a rule without suspicions', function () {
    Route::put('posts/{post}', [PostController::class, 'update']);

    $targets = ProbeTargets::fromSuspicions(localContext());

    expect($targets->forRule('routes.csrf-excluded'))->toBeEmpty();
});

it('makes one target per route even when two routes share an action', function () {
    Route::put('posts/{post}', [PostController::class, 'update']);
    Route::patch('posts/{post}', [PostController::class, 'update']);

    $targets = ProbeTargets::fromSuspicions(localContext());

    expect($targets->forRule('routes.missing-authentication'))->toHaveCount(2);
});

it('leaves out a write route that is protected', function () {
    Route::middleware('auth')->put('posts/{post}', [PostController::class, 'update']);

    $targets = ProbeTargets::fromSuspicions(localContext());

    expect($targets->forRule('routes.missing-authentication'))->toBeEmpty();
});
