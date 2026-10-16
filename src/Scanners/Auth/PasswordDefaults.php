<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth;

use Closure;
use Illuminate\Validation\Rules\Password;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Throwable;

/**
 * The application's default password rule, set with Password::defaults().
 */
final class PasswordDefaults
{
    /**
     * Calls that apply the default rule. Password::defaults($callback) only defines it.
     */
    private const USAGE = '/Password::(?:defaults?|required|sometimes)\(\s*\)/';

    private ?ScanContext $evaluatedFor = null;

    /**
     * @var array{min: int, uncompromised: bool}|string the rules, or the reason they could not be read
     */
    private array|string $evaluation = '';

    public function __construct(
        private readonly AppSource $source = new AppSource,
    ) {}

    /**
     * Both password checks ask, but each scan searches app/ and runs the callback once.
     *
     * @return array{min: int, uncompromised: bool}
     *
     * @throws CheckSkipped
     */
    public function rules(ScanContext $context): array
    {
        if ($this->evaluatedFor !== $context) {
            $this->evaluatedFor = $context;

            try {
                $this->evaluation = $this->evaluate();
            } catch (CheckSkipped $skip) {
                $this->evaluation = $skip->getMessage();
            }
        }

        if (is_string($this->evaluation)) {
            throw CheckSkipped::because($this->evaluation);
        }

        return $this->evaluation;
    }

    /**
     * @return array{min: int, uncompromised: bool}
     *
     * @throws CheckSkipped
     */
    private function evaluate(): array
    {
        if (! $this->source->contains(self::USAGE)) {
            throw CheckSkipped::because('no password validation in app/ uses the default rule (Password::default(), Password::required() or Password::sometimes())');
        }

        try {
            $rule = Password::default();
        } catch (Throwable $exception) {
            throw CheckSkipped::because(sprintf('could not evaluate Password::defaults(): %s', $exception->getMessage()));
        }

        // The callback may return any validation rule, despite the declared return type.
        // @phpstan-ignore instanceof.alwaysTrue
        if (! $rule instanceof Password) {
            throw CheckSkipped::because(sprintf('the default password rule is not a Password rule (%s)', $rule::class));
        }

        $applied = $rule->appliedRules();

        return [
            'min' => is_int($applied['min'] ?? null) ? $applied['min'] : 8,
            'uncompromised' => ($applied['uncompromised'] ?? false) === true,
        ];
    }

    public function location(ScanContext $context): ?Location
    {
        $callback = Password::$defaultCallback;

        return $callback instanceof Closure ? Location::ofClosure($callback, $context->basePath) : null;
    }
}
