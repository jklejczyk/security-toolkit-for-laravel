<?php

declare(strict_types=1);

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Routing\Middleware\ValidateSignature;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\CustomAuthenticate;

/**
 * @param  list<string>  $methods
 * @param  list<string>  $middleware
 */
function routeInfo(array $methods = ['GET'], array $middleware = []): RouteInfo
{
    return new RouteInfo($methods, 'posts/{post}', null, $middleware, null, null, null, null, [], false, false, true);
}

it('treats POST, PUT, PATCH and DELETE as writes', function (string $method, bool $write) {
    expect(routeInfo([$method])->isWrite())->toBe($write);
})->with([['GET', false], ['OPTIONS', false], ['POST', true], ['PUT', true], ['PATCH', true], ['DELETE', true]]);

it('matches middleware by class, whatever its parameters, and by subclass', function () {
    expect(routeInfo(middleware: [Authenticate::class.':sanctum'])->usesMiddleware(Authenticate::class))->toBeTrue()
        ->and(routeInfo(middleware: [CustomAuthenticate::class])->usesMiddleware(Authenticate::class))->toBeTrue()
        ->and(routeInfo(middleware: ['auth'])->usesMiddleware(Authenticate::class))->toBeFalse()
        ->and(routeInfo(middleware: [ValidateSignature::class])->usesMiddleware(Authenticate::class, ValidateSignature::class))->toBeTrue();
});

it('returns the parameters of every middleware of a class', function () {
    $route = routeInfo(middleware: [Authorize::class.':update,post', Authorize::class.':view,post', Authenticate::class]);

    expect($route->middlewareParameters(Authorize::class))->toBe(['update,post', 'view,post'])
        ->and($route->middlewareParameters(ValidateSignature::class))->toBe([]);
});
