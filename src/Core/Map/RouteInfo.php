<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Map;

final readonly class RouteInfo
{
    private const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /**
     * @param  list<string>  $methods  HTTP methods without HEAD
     * @param  list<string>  $middleware  resolved middleware, classes with their parameters ("Class:param")
     * @param  ?class-string  $controller  null for a closure route
     * @param  ?string  $file  file of the action, relative to the application when inside it
     * @param  list<RouteParameter>  $models  model parameters in the order of the URI
     * @param  bool  $inApp  the action is defined in app/, not in a package
     */
    public function __construct(
        public array $methods,
        public string $uri,
        public ?string $name,
        public array $middleware,
        public ?string $controller,
        public ?string $action,
        public ?string $file,
        public ?int $line,
        public array $models,
        public bool $enforcesScopedBindings,
        public bool $preventsScopedBindings,
        public bool $inApp,
    ) {}

    public function isWrite(): bool
    {
        return array_intersect($this->methods, self::WRITE_METHODS) !== [];
    }

    /**
     * True when any middleware is one of the classes (or a subclass), whatever its parameters.
     *
     * @param  class-string  ...$classes
     */
    public function usesMiddleware(string ...$classes): bool
    {
        foreach ($this->middleware as $middleware) {
            $class = explode(':', $middleware, 2)[0];

            foreach ($classes as $expected) {
                if ($class === $expected || (class_exists($class) && is_subclass_of($class, $expected))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Parameters of every middleware of the class, e.g. ["update,post"] for "can:update,post".
     *
     * @param  class-string  $class
     * @return list<string>
     */
    public function middlewareParameters(string $class): array
    {
        $parameters = [];

        foreach ($this->middleware as $middleware) {
            [$name, $arguments] = array_pad(explode(':', $middleware, 2), 2, '');

            if ($name === $class) {
                $parameters[] = $arguments;
            }
        }

        return $parameters;
    }
}
