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
 * The code of a route action and of the places that authorize it: the controller constructor
 * and the authorize() method of form requests the action receives.
 */
final class ActionSource
{
    /**
     * Calls that authorize a request, e.g. $this->authorize(), Gate::allows() or abort_unless().
     */
    private const AUTHORIZATION = '/(?:\bauthorize\w*\(|\bGate::|->(?:can|cannot|canAny|allows|denies|authorize)\(|\babort_(?:if|unless)\(|\babort\(\s*(?:403|404|Response::HTTP_(?:FORBIDDEN|NOT_FOUND))|AuthorizationException|AccessDeniedHttpException|Response::deny)/';

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
     * authorizeResource() in the constructor, or a "can:" middleware the controller adds itself
     * (the map already includes controller middleware, so only authorizeResource is left).
     */
    private function constructorAuthorizes(RouteInfo $route): bool
    {
        if ($route->controller === null) {
            return false;
        }

        try {
            $constructor = (new ReflectionClass($route->controller))->getConstructor();
        } catch (Throwable) {
            return false;
        }

        $code = $constructor === null ? null : $this->body($constructor);

        return $code !== null && str_contains($code, 'authorizeResource(');
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
