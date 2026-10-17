<?php

declare(strict_types=1);

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\BelongsToInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Author;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Comment;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\InvokableController;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\PostController;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\PostPolicy;

function mappedRoute(string $uri): RouteInfo
{
    foreach ((new ApplicationMap)->routes() as $route) {
        if ($route->uri === $uri) {
            return $route;
        }
    }

    throw new RuntimeException("Route {$uri} is not mapped.");
}

describe('routes', function () {
    it('describes a controller route with its methods, middleware and action', function () {
        Route::middleware(['web', 'auth'])->put('posts/{post}', [PostController::class, 'update'])->name('posts.update');

        $route = mappedRoute('posts/{post}');

        expect($route->methods)->toBe(['PUT'])
            ->and($route->name)->toBe('posts.update')
            ->and($route->controller)->toBe(PostController::class)
            ->and($route->action)->toBe('update')
            ->and($route->file)->toEndWith('tests/Fixtures/Map/PostController.php')
            ->and($route->line)->toBeInt()
            ->and($route->isWrite())->toBeTrue()
            ->and($route->usesMiddleware(Authenticate::class))->toBeTrue()
            ->and($route->usesMiddleware(SubstituteBindings::class))->toBeTrue();
    });

    it('resolves middleware aliases and keeps their parameters', function () {
        Route::middleware(['auth:sanctum', 'can:update,post'])->patch('posts/{post}', [PostController::class, 'update']);

        $route = mappedRoute('posts/{post}');

        expect($route->middleware)->toContain(Authenticate::class.':sanctum')
            ->and($route->middlewareParameters(Authorize::class))->toBe(['update,post']);
    });

    it('lists model parameters in the order of the URI, with custom binding keys', function () {
        Route::get('posts/{post:slug}/comments/{comment}', [PostController::class, 'showComment']);

        // Laravel keeps the binding key out of the URI.
        $models = mappedRoute('posts/{post}/comments/{comment}')->models;

        expect($models)->toHaveCount(2)
            ->and($models[0]->name)->toBe('post')
            ->and($models[0]->model)->toBe(Post::class)
            ->and($models[0]->field)->toBe('slug')
            ->and($models[1]->model)->toBe(Comment::class)
            ->and($models[1]->field)->toBeNull();
    });

    it('records whether the route enforces or prevents scoped bindings', function () {
        Route::scopeBindings()->get('a/{post}/{comment}', [PostController::class, 'showComment']);
        Route::get('b/{post}/{comment}', [PostController::class, 'showComment'])->withoutScopedBindings();

        expect(mappedRoute('a/{post}/{comment}')->enforcesScopedBindings)->toBeTrue()
            ->and(mappedRoute('b/{post}/{comment}')->preventsScopedBindings)->toBeTrue();
    });

    it('maps invokable controllers and closures', function () {
        Route::delete('invoke/{post}', InvokableController::class);
        Route::post('closure/{post}', fn (Post $post) => 'ok');

        $invokable = mappedRoute('invoke/{post}');
        $closure = mappedRoute('closure/{post}');

        expect($invokable->controller)->toBe(InvokableController::class)
            ->and($invokable->action)->toBe('__invoke')
            ->and($invokable->models[0]->model)->toBe(Post::class)
            ->and($closure->controller)->toBeNull()
            ->and($closure->action)->toBeNull()
            ->and($closure->models[0]->model)->toBe(Post::class)
            ->and($closure->file)->toEndWith('ApplicationMapTest.php');
    });

    it('marks only actions defined in app/ as part of the application', function () {
        Route::get('posts', [PostController::class, 'index']);

        expect(mappedRoute('posts')->inApp)->toBeFalse();

        app()->useAppPath(dirname(__DIR__, 2).'/Fixtures/Map');

        expect(mappedRoute('posts')->inApp)->toBeTrue();
    });

    it('treats GET routes as reads', function () {
        Route::get('posts', [PostController::class, 'index']);

        expect(mappedRoute('posts')->methods)->toBe(['GET'])
            ->and(mappedRoute('posts')->isWrite())->toBeFalse();
    });
});

it('finds the policy of a model', function () {
    Gate::policy(Post::class, PostPolicy::class);

    expect((new ApplicationMap)->policyFor(Post::class))->toBe(PostPolicy::class)
        ->and((new ApplicationMap)->policyFor(Comment::class))->toBeNull();
});

it('lists guards with their drivers', function () {
    config(['auth.guards' => ['web' => ['driver' => 'session'], 'api' => ['driver' => 'sanctum'], 'broken' => 'x']]);

    expect((new ApplicationMap)->guards())->toBe(['web' => 'session', 'api' => 'sanctum']);
});

it('finds belongsTo relations by return type or by the call in the body', function () {
    $relations = (new ApplicationMap)->belongsTo(Post::class);

    expect($relations)->toEqual([
        new BelongsToInfo('author', Author::class, 'author_id'),
        new BelongsToInfo('editor', Author::class, 'editor_id'),
    ])->and((new ApplicationMap)->belongsTo(Comment::class))->toEqual([
        new BelongsToInfo('post', Post::class, 'post_id'),
    ]);
});
