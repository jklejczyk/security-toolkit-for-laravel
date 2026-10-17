<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Map;

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use ReflectionClass;
use ReflectionFunction;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionParameter;
use Throwable;

/**
 * Routes, policies, guards and relations of the booted application, read on first use, so scans
 * that only check configuration never pay for the reflection.
 */
final class ApplicationMap
{
    /** @var ?list<RouteInfo> */
    private ?array $routes = null;

    /** @var array<class-string, list<BelongsToInfo>> */
    private array $belongsTo = [];

    /**
     * @return list<RouteInfo>
     */
    public function routes(): array
    {
        if ($this->routes !== null) {
            return $this->routes;
        }

        /** @var Router $router */
        $router = app('router');
        $routes = [];

        // The HTTP kernel registers middleware aliases and groups on the router when it is built,
        // which never happens in an Artisan command; without it "auth" would stay unresolved.
        try {
            app(HttpKernel::class);
        } catch (Throwable) {
            // Unresolved aliases are kept as written.
        }

        foreach ($router->getRoutes()->getRoutes() as $route) {
            $routes[] = $this->describe($route, $router);
        }

        return $this->routes = $routes;
    }

    /**
     * The policy class for the model, registered explicitly or found by convention.
     *
     * @param  class-string  $model
     * @return ?class-string
     */
    public function policyFor(string $model): ?string
    {
        try {
            $policy = Gate::getPolicyFor($model);
        } catch (Throwable) {
            return null;
        }

        return is_object($policy) ? $policy::class : null;
    }

    /**
     * Guard name => driver, e.g. ['web' => 'session', 'api' => 'sanctum'].
     *
     * @return array<string, string>
     */
    public function guards(): array
    {
        $guards = [];

        foreach ((array) config('auth.guards', []) as $name => $guard) {
            if (is_string($name) && is_array($guard) && is_string($guard['driver'] ?? null)) {
                $guards[$name] = $guard['driver'];
            }
        }

        return $guards;
    }

    /**
     * The belongsTo relations of a model: public methods without parameters that declare BelongsTo
     * as their return type or call $this->belongsTo(). A relation that fails to build is left out.
     *
     * @param  class-string<Model>  $model
     * @return list<BelongsToInfo>
     */
    public function belongsTo(string $model): array
    {
        if (isset($this->belongsTo[$model])) {
            return $this->belongsTo[$model];
        }

        $relations = [];

        try {
            $reflection = new ReflectionClass($model);
            $instance = $reflection->newInstanceWithoutConstructor();
        } catch (Throwable) {
            return $this->belongsTo[$model] = [];
        }

        foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->isStatic() || $method->getNumberOfRequiredParameters() > 0 || ! $this->declaresBelongsTo($method)) {
                continue;
            }

            try {
                $relation = $method->invoke($instance);
            } catch (Throwable) {
                continue;
            }

            if ($relation instanceof BelongsTo) {
                $relations[] = new BelongsToInfo($method->getName(), $relation->getRelated()::class, $relation->getForeignKeyName());
            }
        }

        return $this->belongsTo[$model] = $relations;
    }

    private function describe(Route $route, Router $router): RouteInfo
    {
        $controller = $this->controllerClass($route);
        $action = $controller === null ? null : $route->getActionMethod();

        // An invokable controller has no method in its action, only the class.
        if ($controller !== null && ($action === null || ltrim($action, '\\') === $controller)) {
            $action = '__invoke';
        }
        [$file, $line] = $this->actionLocation($route, $controller, $action);

        return new RouteInfo(
            array_values(array_diff($route->methods(), ['HEAD'])),
            $route->uri(),
            $route->getName(),
            $this->middleware($route, $router),
            $controller,
            $action,
            $file === null ? null : Location::inApplication($file, base_path())->file,
            $line,
            $this->models($route),
            $route->enforcesScopedBindings(),
            $route->preventsScopedBindings(),
            $file !== null && str_starts_with($file, rtrim(app_path(), '/').'/'),
        );
    }

    /**
     * @return ?class-string
     */
    private function controllerClass(Route $route): ?string
    {
        try {
            $class = $route->getControllerClass();
        } catch (Throwable) {
            return null;
        }

        if (! is_string($class)) {
            return null;
        }

        $class = ltrim($class, '\\');

        return class_exists($class) ? $class : null;
    }

    /**
     * @return list<string>
     */
    private function middleware(Route $route, Router $router): array
    {
        try {
            $middleware = $router->gatherRouteMiddleware($route);
        } catch (Throwable) {
            $middleware = $route->gatherMiddleware();
        }

        return array_values(array_filter($middleware, is_string(...)));
    }

    /**
     * @return array{?string, ?int}
     */
    private function actionLocation(Route $route, ?string $controller, ?string $action): array
    {
        try {
            if ($controller !== null && $action !== null) {
                $reflection = new ReflectionMethod($controller, $action);
            } elseif (($uses = $route->getAction('uses')) instanceof \Closure) {
                $reflection = new ReflectionFunction($uses);
            } else {
                return [null, null];
            }
        } catch (Throwable) {
            return [null, null];
        }

        $file = $reflection->getFileName();

        return [$file === false ? null : $file, $reflection->getStartLine() ?: null];
    }

    /**
     * @return list<RouteParameter>
     */
    private function models(Route $route): array
    {
        try {
            $signature = $route->signatureParameters(['subClass' => Model::class]);
        } catch (Throwable) {
            return [];
        }

        $byName = [];

        foreach ($signature as $parameter) {
            if (! $parameter instanceof ReflectionParameter) {
                continue;
            }

            $model = $this->modelClass($parameter);

            if ($model !== null) {
                $byName[$parameter->getName()] = $model;
            }
        }

        $models = [];

        foreach ($route->parameterNames() as $name) {
            if (is_string($name) && isset($byName[$name])) {
                $field = $route->bindingFieldFor($name);
                $models[] = new RouteParameter($name, $byName[$name], is_string($field) ? $field : null);
            }
        }

        return $models;
    }

    /**
     * @return ?class-string<Model>
     */
    private function modelClass(ReflectionParameter $parameter): ?string
    {
        $type = $parameter->getType();

        if (! $type instanceof ReflectionNamedType || $type->isBuiltin()) {
            return null;
        }

        $class = $type->getName();

        return class_exists($class) && is_subclass_of($class, Model::class) ? $class : null;
    }

    private function declaresBelongsTo(ReflectionMethod $method): bool
    {
        $type = $method->getReturnType();

        if ($type instanceof ReflectionNamedType && ! $type->isBuiltin() && is_a($type->getName(), BelongsTo::class, true)) {
            return true;
        }

        $file = $method->getFileName();
        $start = $method->getStartLine();
        $end = $method->getEndLine();

        if ($file === false || $start === false || $end === false || ! is_readable($file)) {
            return false;
        }

        $lines = file($file);

        return $lines !== false
            && str_contains(implode('', array_slice($lines, $start - 1, $end - $start + 1)), '$this->belongsTo(');
    }
}
