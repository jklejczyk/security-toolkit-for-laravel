<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\CsrfExcludedCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\MissingAuthenticationCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\MissingAuthorizationCheck;
use Jklejczyk\SecurityToolkit\Scanners\Routes\Checks\UnscopedNestedBindingCheck;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\PostController;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\PostPolicy;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\CommentController;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\GuardedPostController;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\OpenPostController;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes\ResourcePostController;

beforeEach(function () {
    // The fixture controllers stand in for app/: only routes defined there are checked.
    app()->useAppPath(dirname(__DIR__, 3).'/Fixtures/Routes');
});

/**
 * @return list<Finding>
 */
function routeFindings(object $check, ?ScanContext $context = null): array
{
    return iterator_to_array($check->run($context ?? localContext()), false);
}

/**
 * Sets the URIs excluded from CSRF the way validateCsrfTokens(except:) does.
 *
 * @param  list<string>  $uris
 */
function excludeFromCsrf(array $uris): void
{
    foreach (['Illuminate\Foundation\Http\Middleware\PreventRequestForgery', 'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken'] as $class) {
        if (class_exists($class) && property_exists($class, 'neverVerify')) {
            (new ReflectionClass($class))->setStaticPropertyValue('neverVerify', $uris);

            return;
        }
    }
}

afterEach(function () {
    excludeFromCsrf([]);
});

describe('routes.missing-authentication', function () {
    it('reports writes to a bound model without login, as suspected', function (string $method, string $action) {
        Route::middleware('web')->{$method}('posts/{post}', [OpenPostController::class, $action]);

        $findings = routeFindings(new MissingAuthenticationCheck);

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->severity)->toBe(Severity::High)
            ->and($findings[0]->confidence)->toBe(Confidence::Suspected)
            ->and($findings[0]->cwe)->toBe([306])
            ->and($findings[0]->title)->toContain('/posts/{post}', 'Post')
            ->and($findings[0]->location?->file)->toEndWith('OpenPostController.php')
            ->and($findings[0]->location?->line)->toBeInt();
    })->with([['put', 'update'], ['patch', 'update'], ['delete', 'destroy'], ['post', 'update']]);

    it('does not report protected, read-only or model-less routes', function () {
        Route::middleware('auth')->put('a/{post}', [OpenPostController::class, 'update']);
        Route::middleware('auth:sanctum')->delete('b/{post}', [OpenPostController::class, 'destroy']);
        Route::middleware('auth.basic')->put('c/{post}', [OpenPostController::class, 'update']);
        Route::middleware('signed')->delete('d/{post}', [OpenPostController::class, 'destroy']);
        Route::middleware('can:update,post')->put('e/{post}', [OpenPostController::class, 'update']);
        Route::get('f/{post}', [OpenPostController::class, 'show']);
        Route::post('webhooks/payments', [OpenPostController::class, 'store']);
        Route::delete('g/{post}', fn (Post $post) => 'closure');

        expect(routeFindings(new MissingAuthenticationCheck))->toBe([]);
    });

    it('ignores controllers outside app/', function () {
        Route::put('posts/{post}', [PostController::class, 'update']);

        expect(routeFindings(new MissingAuthenticationCheck))->toBe([]);
    });

    it('runs in every environment', function () {
        expect((new MissingAuthenticationCheck)->onlyInProduction())->toBeFalse();
    });
});

describe('routes.missing-authorization', function () {
    it('reports a logged-in route that never authorizes the bound model', function () {
        Route::middleware('auth')->put('posts/{post}', [OpenPostController::class, 'update']);

        $findings = routeFindings(new MissingAuthorizationCheck);

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->severity)->toBe(Severity::Medium)
            ->and($findings[0]->confidence)->toBe(Confidence::Suspected)
            ->and($findings[0]->cwe)->toBe([639])
            ->and($findings[0]->description)->toContain('Post has no policy');
    });

    it('names the unused policy when the model has one', function () {
        Gate::policy(Post::class, PostPolicy::class);
        Route::middleware('auth')->get('posts/{post}', [OpenPostController::class, 'show']);

        expect(routeFindings(new MissingAuthorizationCheck)[0]->description)->toContain('PostPolicy exists but is not used here');
    });

    it('treats a form request that always returns true as no authorization', function () {
        Route::middleware('auth')->put('posts/{post}', [OpenPostController::class, 'updateWithRequest']);

        expect(routeFindings(new MissingAuthorizationCheck))->toHaveCount(1);
    });

    it('recognises authorization in the action, a form request, the constructor or the route', function () {
        Route::middleware('auth')->group(function () {
            Route::put('a/{post}', [GuardedPostController::class, 'viaGate']);
            Route::put('b/{post}', [GuardedPostController::class, 'viaAbort']);
            Route::put('c/{post}', [GuardedPostController::class, 'viaUserCan']);
            Route::put('d/{post}', [GuardedPostController::class, 'viaFormRequest']);
            Route::put('e/{post}', [ResourcePostController::class, 'update']);
            Route::put('f/{post}', [OpenPostController::class, 'update'])->can('update', 'post');
        });

        expect(routeFindings(new MissingAuthorizationCheck))->toBe([]);
    });

    it('leaves routes without login to routes.missing-authentication', function () {
        Route::put('posts/{post}', [OpenPostController::class, 'update']);
        Route::middleware('auth')->post('posts', [OpenPostController::class, 'store']);

        expect(routeFindings(new MissingAuthorizationCheck))->toBe([]);
    });
});

describe('routes.unscoped-nested-binding', function () {
    it('reports a nested child that belongs to its parent but is not scoped', function () {
        Route::get('posts/{post}/comments/{comment}', [CommentController::class, 'show']);

        $findings = routeFindings(new UnscopedNestedBindingCheck);

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->confidence)->toBe(Confidence::Suspected)
            ->and($findings[0]->cwe)->toBe([639])
            ->and($findings[0]->description)->toContain('post_id');
    });

    it('reports a route that turns scoping off', function () {
        Route::get('posts/{post}/comments/{comment:id}', [CommentController::class, 'show'])->withoutScopedBindings();

        expect(routeFindings(new UnscopedNestedBindingCheck))->toHaveCount(1);
    });

    it('does not report scoped bindings, a custom child key or a check in the action', function () {
        Route::scopeBindings()->get('a/{post}/comments/{comment}', [CommentController::class, 'show']);
        Route::get('b/{post}/comments/{comment:id}', [CommentController::class, 'show']);
        Route::get('c/{post}/comments/{comment}', [CommentController::class, 'showChecked']);

        expect(routeFindings(new UnscopedNestedBindingCheck))->toBe([]);
    });
});

describe('routes.csrf-excluded', function () {
    beforeEach(function () {
        config(['session.same_site' => 'none']);
    });

    it('reports an exclusion that matches a logged-in write route', function () {
        excludeFromCsrf(['posts/*']);
        Route::middleware(['web', 'auth'])->post('posts/{post}/publish', [OpenPostController::class, 'update']);

        $findings = routeFindings(new CsrfExcludedCheck, productionContext());

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->severity)->toBe(Severity::Medium)
            ->and($findings[0]->confidence)->toBe(Confidence::Certain)
            ->and($findings[0]->cvss?->score)->toBe(6.5)
            ->and($findings[0]->cwe)->toBe([352])
            ->and($findings[0]->description)->toContain('POST /posts/{post}/publish', "'none'");
    });

    it('does not report a webhook, a GET route, an API route or a different path', function () {
        excludeFromCsrf(['webhooks/*', 'posts/*', 'api/*']);
        Route::middleware('web')->post('webhooks/payments', [OpenPostController::class, 'store']);
        Route::middleware(['web', 'auth'])->get('posts/{post}', [OpenPostController::class, 'show']);
        Route::middleware(['api', 'auth:sanctum'])->post('api/posts/{post}', [OpenPostController::class, 'update']);
        Route::middleware(['web', 'auth'])->post('drafts/{post}', [OpenPostController::class, 'update']);

        expect(routeFindings(new CsrfExcludedCheck, productionContext()))->toBe([]);
    });

    it('does not report when SameSite blocks the cross-site cookie', function (string $sameSite) {
        config(['session.same_site' => $sameSite]);
        excludeFromCsrf(['posts/*']);
        Route::middleware(['web', 'auth'])->post('posts/{post}/publish', [OpenPostController::class, 'update']);

        expect(routeFindings(new CsrfExcludedCheck, productionContext()))->toBe([]);
    })->with(['lax', 'strict', 'Lax']);

    it('skips outside production when SameSite comes from env()', function () {
        excludeFromCsrf(['posts/*']);
        Route::middleware(['web', 'auth'])->post('posts/{post}/publish', [OpenPostController::class, 'update']);

        // No published config/session.php: the framework default reads SESSION_SAME_SITE.
        routeFindings(new CsrfExcludedCheck, localContext(basePath: sys_get_temp_dir().'/no-app'));
    })->throws(CheckSkipped::class, 'session.same_site comes from env()');

    it('reports nothing and skips nothing without a matching exclusion', function () {
        Route::middleware(['web', 'auth'])->post('posts/{post}/publish', [OpenPostController::class, 'update']);

        expect(routeFindings(new CsrfExcludedCheck, localContext()))->toBe([]);
    });
});
