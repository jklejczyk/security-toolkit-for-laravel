<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Routes;

use Illuminate\Foundation\Http\FormRequest;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use ReflectionClass;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use ReflectionNamedType;
use Throwable;

/**
 * The code of a route action and of the places that authorize it: application middleware, the
 * controller constructor and the authorize() method of form requests the action receives.
 */
final class ActionSource
{
    /**
     * Calls that authorize a request, e.g. $this->authorize(), Gate::allows() or abort_unless().
     */
    private const AUTHORIZATION = '/(?:\bauthorize\w*\(|\bGate::|->(?:can|cannot|canAny|allows|denies|authorize)\(|\babort_(?:if|unless)\(|\babort\(\s*(?:403|404|Response::HTTP_(?:FORBIDDEN|NOT_FOUND))|AuthorizationException|AccessDeniedHttpException|Response::deny)/';

    /**
     * The login checked in a condition, e.g. if (! Auth::check()), if (Auth::user()) or
     * abort_unless(auth()->check(), 401); a mention of the user elsewhere is not a check.
     */
    private const LOGIN_CHECK = '/\b(?:if|abort_if|abort_unless)\s*\(\s*!?\s*(?:Auth::(?:check|guest|user|id)\(\)|auth\(\)->(?:check|guest|user|id)\(\)|\$request->user\(\)|request\(\)->user\(\))/';

    /**
     * Ways a middleware turns a request away: a 401/403 status, abort(), a redirect or an exception.
     */
    private const DENIAL = '/(?:\b40[13]\b|HTTP_(?:FORBIDDEN|UNAUTHORIZED)|\babort\w*\(|\bredirect\(|\bto_route\(|\bthrow\s+new\b)/';

    /**
     * Code of the action method, without its doc comment; null for a closure or an unreadable file.
     */
    public function action(RouteInfo $route): ?string
    {
        if ($route->controller === null || $route->action === null) {
            return null;
        }

        try {
            return $this->body(new ReflectionMethod($route->controller, $route->action));
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * True when the action, its controller constructor or a form request it receives authorizes
     * the request; null when the code cannot be read, so the caller can skip instead of guessing.
     */
    public function authorizes(RouteInfo $route): ?bool
    {
        if ($this->middlewareAuthorizes($route)) {
            return true;
        }

        $action = $this->action($route);

        if ($action === null) {
            return null;
        }

        if (preg_match(self::AUTHORIZATION, $action) === 1) {
            return true;
        }

        return $this->constructorAuthorizes($route) || $this->formRequestAuthorizes($route);
    }

    /**
     * True when the action, or a closure middleware its controller registers in the constructor,
     * checks that the user is logged in, so a route without the auth middleware is still protected.
     */
    public function checksLogin(RouteInfo $route): bool
    {
        $action = $this->action($route);

        if ($action !== null && preg_match(self::LOGIN_CHECK, $action) === 1) {
            return true;
        }

        $constructor = $this->constructor($route);

        return $constructor !== null
            && preg_match('/->middleware\(\s*(?:static\s+)?(?:function|fn)\b/', $constructor) === 1
            && preg_match(self::LOGIN_CHECK, $constructor) === 1;
    }

    /**
     * An application middleware that authorizes: its handle() uses Laravel's authorization API, or
     * the route names what to check ("permission:posts.edit", "area:admin") and handle() can turn
     * the request away. A parameter that never leads to a denial (e.g. a locale) is not authorization.
     */
    private function middlewareAuthorizes(RouteInfo $route): bool
    {
        foreach ($route->middleware as $middleware) {
            [$class, $parameters] = array_pad(explode(':', $middleware, 2), 2, '');

            $code = $this->applicationHandle($class);

            if ($code === null) {
                continue;
            }

            if (preg_match(self::AUTHORIZATION, $code) === 1 || ($parameters !== '' && preg_match(self::DENIAL, $code) === 1)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Code of handle() of a middleware class declared in app/; null for framework and package middleware.
     */
    private function applicationHandle(string $class): ?string
    {
        if (! class_exists($class) || ! method_exists($class, 'handle')) {
            return null;
        }

        $handle = new ReflectionMethod($class, 'handle');
        $file = $handle->getFileName();

        if ($file === false || ! str_starts_with($file, app_path().DIRECTORY_SEPARATOR)) {
            return null;
        }

        return $this->body($handle);
    }

    /**
     * authorizeResource() in the constructor, or a "can:" middleware the controller adds itself
     * (the map already includes controller middleware, so only authorizeResource is left).
     */
    private function constructorAuthorizes(RouteInfo $route): bool
    {
        $code = $this->constructor($route);

        return $code !== null && str_contains($code, 'authorizeResource(');
    }

    /**
     * Code of the controller constructor; null without a controller, a constructor or a readable file.
     */
    private function constructor(RouteInfo $route): ?string
    {
        if ($route->controller === null) {
            return null;
        }

        try {
            $constructor = (new ReflectionClass($route->controller))->getConstructor();
        } catch (Throwable) {
            return null;
        }

        return $constructor === null ? null : $this->body($constructor);
    }

    /**
     * A FormRequest parameter whose authorize() does more than return true. Laravel lets a form
     * request without authorize() through, so that counts as no authorization.
     */
    private function formRequestAuthorizes(RouteInfo $route): bool
    {
        try {
            $parameters = (new ReflectionMethod((string) $route->controller, (string) $route->action))->getParameters();
        } catch (Throwable) {
            return false;
        }

        foreach ($parameters as $parameter) {
            $type = $parameter->getType();

            if (! $type instanceof ReflectionNamedType || $type->isBuiltin() || ! is_subclass_of($type->getName(), FormRequest::class)) {
                continue;
            }

            try {
                $authorize = new ReflectionMethod($type->getName(), 'authorize');
            } catch (Throwable) {
                continue;
            }

            $code = $this->body($authorize);

            if ($code !== null && preg_match('/\{\s*return\s+true\s*;\s*\}\s*$/', $code) !== 1) {
                return true;
            }
        }

        return false;
    }

    private function body(ReflectionFunctionAbstract $function): ?string
    {
        $file = $function->getFileName();
        $start = $function->getStartLine();
        $end = $function->getEndLine();

        if ($file === false || $start === false || $end === false || ! is_readable($file)) {
            return null;
        }

        $lines = file($file);

        return $lines === false ? null : trim(implode('', array_slice($lines, $start - 1, $end - $start + 1)));
    }
}
