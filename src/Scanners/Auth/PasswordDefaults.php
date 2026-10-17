<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth;

use Closure;
use Illuminate\Validation\Rules\Password;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Support\AppSource;
use ReflectionFunction;
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

    /**
     * Password::defaults() with an argument registers the rule.
     */
    private const DEFINITION = '/Password::defaults\(\s*[^\s)]/';

    /**
     * Code that decides by environment; the faked production environment covers it only
     * inside a callback, not where the application boots.
     */
    private const ENVIRONMENT_DECISION = '/isProduction|isLocal|environment\s*\(|runningUnitTests|\benv\s*\(|app\.env|app\.debug/';

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
                $this->evaluation = $this->evaluate($context);
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
    private function evaluate(ScanContext $context): array
    {
        if (! $this->source->contains(self::USAGE)) {
            throw CheckSkipped::because('no password validation in app/ uses the default rule (Password::default(), Password::required() or Password::sometimes())');
        }

        if (! $context->isProduction()) {
            $this->ensureProductionRuleCanBeEvaluated();
        }

        try {
            $rule = $context->isProduction()
                ? Password::default()
                : $this->asInProduction(fn () => Password::default());
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

    /**
     * Outside production the callback runs with a faked production environment. That gives the
     * production rule only when one unconditional registration decides inside its callback;
     * anything decided while the application boots keeps its local value.
     *
     * @throws CheckSkipped
     */
    private function ensureProductionRuleCanBeEvaluated(): void
    {
        $callback = Password::$defaultCallback;
        $registrations = $this->source->matches(self::DEFINITION);

        if (count($registrations) > 1) {
            throw CheckSkipped::because('Password::defaults() is registered in more than one place; run the scan in production');
        }

        if ($registrations !== [] && ($callback === null || $this->isConditional($registrations[0]['code'], $registrations[0]['offset']))) {
            throw CheckSkipped::because('Password::defaults() is registered only in some environments; run the scan in production');
        }

        if ($callback === null) {
            return;
        }

        if (! is_callable($callback)) {
            $statement = $registrations === [] ? '' : $this->statementAt($registrations[0]['code'], $registrations[0]['offset']);

            if (preg_match(self::ENVIRONMENT_DECISION, $statement) === 1) {
                throw CheckSkipped::because('Password::defaults() picks its rule when the application boots; run the scan in production');
            }

            // A rule object chosen without an environment check is the same everywhere.
            return;
        }

        if (! $callback instanceof Closure || preg_match('/\benv\s*\(/', $this->sourceOf($callback)) === 1) {
            throw CheckSkipped::because('Password::defaults() reads env() directly or cannot be inspected, so its production rule cannot be evaluated here; run the scan in production');
        }

        if ((new ReflectionFunction($callback))->getClosureUsedVariables() !== []) {
            throw CheckSkipped::because('the Password::defaults() callback captures values computed when the application boots; run the scan in production');
        }
    }

    /**
     * Whether the statement at the offset runs only under a condition: an if/else around it,
     * a ternary or short-circuit in front of it, or a when() callback it sits in.
     */
    private function isConditional(string $code, int $offset): bool
    {
        $before = substr($code, 0, $offset);
        $start = self::statementStart($before);
        $prefix = self::withoutComments(substr($before, $start + 1));

        if (preg_match('/\?|&&|\|\||=>|\b(?:if|elseif|else|and|or)\b/i', $prefix) === 1) {
            return true;
        }

        if ($start < 0 || $before[$start] !== '{') {
            return false;
        }

        $head = substr($before, 0, $start);
        $header = self::withoutComments(substr($head, self::statementStart($head) + 1));

        return preg_match('/\b(?:if|elseif|else|switch|case|match|while|for|foreach|do|when|unless)\b/i', $header) === 1
            || preg_match(self::ENVIRONMENT_DECISION, $header) === 1;
    }

    /**
     * The registration statement, from the call to the next semicolon.
     */
    private function statementAt(string $code, int $offset): string
    {
        $end = strpos($code, ';', $offset);

        return substr($code, $offset, $end === false ? null : $end - $offset);
    }

    /**
     * Position of the character that ends the previous statement or opens the enclosing block, or -1.
     */
    private static function statementStart(string $code): int
    {
        $positions = array_filter([strrpos($code, ';'), strrpos($code, '{'), strrpos($code, '}')], is_int(...));

        return $positions === [] ? -1 : max($positions);
    }

    private static function withoutComments(string $code): string
    {
        return (string) preg_replace('~//[^\n]*|#(?!\[)[^\n]*|/\*.*?\*/~s', '', $code);
    }

    /**
     * @throws CheckSkipped
     */
    private function sourceOf(Closure $callback): string
    {
        $function = new ReflectionFunction($callback);
        $file = $function->getFileName();
        $start = $function->getStartLine();
        $end = $function->getEndLine();
        $lines = $file !== false && is_readable($file) ? file($file) : false;

        if ($lines === false || $start === false || $end === false) {
            throw CheckSkipped::because('could not read the source of the Password::defaults() callback; run the scan in production');
        }

        return implode('', array_slice($lines, $start - 1, $end - $start + 1));
    }

    /**
     * Runs the callback as the production environment would: isProduction(), environment(),
     * isLocal(), app.env and app.debug report production; everything is restored afterwards.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $evaluate
     * @return TResult
     */
    private function asInProduction(Closure $evaluate): mixed
    {
        $app = app();
        $environment = $app['env'];
        $config = ['app.env' => config('app.env'), 'app.debug' => config('app.debug')];

        $app['env'] = 'production';
        config(['app.env' => 'production', 'app.debug' => false]);

        try {
            return $evaluate();
        } finally {
            $app['env'] = $environment;
            config($config);
        }
    }

    public function location(ScanContext $context): ?Location
    {
        $callback = Password::$defaultCallback;

        return $callback instanceof Closure ? Location::ofClosure($callback, $context->basePath) : null;
    }
}
