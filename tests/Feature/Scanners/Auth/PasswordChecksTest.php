<?php

declare(strict_types=1);

use Illuminate\Contracts\Validation\Rule;
use Illuminate\Support\Facades\File;
use Illuminate\Validation\Rules\Password;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\PasswordNotCheckedForLeaksCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\PasswordTooShortCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\PasswordDefaults;

beforeEach(function () {
    $this->root = temporaryApp();
});

afterEach(function () {
    // The default rule is static state shared by every test.
    Password::$defaultCallback = null;
    File::deleteDirectory($this->root);
});

function usePasswordRule(string $root, string $code = "return ['password' => ['required', Password::default()]];"): void
{
    file_put_contents($root.'/app/PasswordValidationRules.php', "<?php\n\nuse Illuminate\\Validation\\Rules\\Password;\n\n".$code."\n");
}

/**
 * @return list<Finding>
 */
function passwordFindings(PasswordTooShortCheck|PasswordNotCheckedForLeaksCheck $check, string $root, bool $production = true): array
{
    $context = $production ? productionContext(basePath: $root) : localContext(basePath: $root);

    return iterator_to_array($check->run($context), false);
}

it('declares rule ids that run in every environment', function () {
    expect((new PasswordTooShortCheck)->id())->toBe('auth.password-too-short')
        ->and((new PasswordTooShortCheck)->onlyInProduction())->toBeFalse()
        ->and((new PasswordNotCheckedForLeaksCheck)->id())->toBe('auth.password-not-checked-for-leaks')
        ->and((new PasswordNotCheckedForLeaksCheck)->onlyInProduction())->toBeFalse();
});

it('reports a default rule shorter than 8 characters and points at its definition', function () {
    usePasswordRule($this->root);
    $line = __LINE__ + 1;
    Password::defaults(fn () => Password::min(6)->uncompromised());

    $findings = passwordFindings(new PasswordTooShortCheck, $this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([521])
        ->and($findings[0]->cvss)->toBeNull()
        ->and($findings[0]->description)->toContain('6 characters')
        ->and($findings[0]->location?->line)->toBe($line)
        ->and(passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root))->toBe([]);
});

it('reports a default rule that accepts leaked passwords', function () {
    usePasswordRule($this->root);
    Password::defaults(Password::min(12));

    $findings = passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([521])
        ->and($findings[0]->cvss)->toBeNull()
        ->and($findings[0]->location)->toBeNull()
        ->and(passwordFindings(new PasswordTooShortCheck, $this->root))->toBe([]);
});

// Without Password::defaults() Laravel uses Password::min(8); a callback returning null does the same.
it('evaluates the framework default when no rule is defined', function (?Closure $callback) {
    usePasswordRule($this->root);
    Password::$defaultCallback = $callback;

    expect(passwordFindings(new PasswordTooShortCheck, $this->root))->toBe([])
        ->and(passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root))->toHaveCount(1);
})->with([
    'no defaults' => [null],
    'callback returning null' => [fn () => null],
]);

it('accepts a strong default rule', function () {
    usePasswordRule($this->root);
    Password::defaults(fn () => Password::min(12)->uncompromised());

    expect(passwordFindings(new PasswordTooShortCheck, $this->root))->toBe([])
        ->and(passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root))->toBe([]);
});

it('recognizes every way of applying the default rule', function (string $call) {
    usePasswordRule($this->root, "return ['password' => [{$call}]];");
    Password::defaults(fn () => Password::min(6));

    expect(passwordFindings(new PasswordTooShortCheck, $this->root))->toHaveCount(1);
})->with(['Password::default()', 'Password::defaults()', 'Password::required()', 'Password::sometimes()', 'Rules\Password::default( )']);

it('skips both checks when no validation applies the default rule', function (string $code) {
    usePasswordRule($this->root, $code);
    Password::defaults(fn () => Password::min(6));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root))
        ->toThrow(CheckSkipped::class, 'no password validation')
        ->and(fn () => passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root))
        ->toThrow(CheckSkipped::class, 'no password validation');
})->with([
    'only the definition' => ['Password::defaults(fn () => Password::min(6));'],
    'an explicit rule' => ["return ['password' => [Password::min(6)]];"],
]);

it('skips when the application has no app directory', function () {
    File::deleteDirectory($this->root.'/app');

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root))->toThrow(CheckSkipped::class);
});

it('skips when the default rule cannot be evaluated', function () {
    usePasswordRule($this->root);
    Password::defaults(fn () => throw new RuntimeException('database is down'));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root))
        ->toThrow(CheckSkipped::class, 'database is down');
});

it('skips when the default rule is a custom rule', function () {
    usePasswordRule($this->root);
    Password::defaults(fn () => new class implements Rule
    {
        public function passes($attribute, $value): bool
        {
            return true;
        }

        public function message(): string
        {
            return '';
        }
    });

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root))
        ->toThrow(CheckSkipped::class, 'not a Password rule');
});

it('evaluates the default rule once per scan', function () {
    usePasswordRule($this->root);
    $calls = 0;
    Password::defaults(function () use (&$calls) {
        $calls++;

        return Password::min(6);
    });
    $defaults = new PasswordDefaults;
    $context = productionContext(basePath: $this->root);

    iterator_to_array((new PasswordTooShortCheck($defaults))->run($context), false);
    iterator_to_array((new PasswordNotCheckedForLeaksCheck($defaults))->run($context), false);
    expect($calls)->toBe(1);

    iterator_to_array((new PasswordTooShortCheck($defaults))->run(productionContext(basePath: $this->root)), false);
    expect($calls)->toBe(2);
});

it('remembers that the default rule could not be evaluated', function () {
    usePasswordRule($this->root);
    Password::defaults(fn () => throw new RuntimeException('database is down'));
    $defaults = new PasswordDefaults;
    $context = productionContext(basePath: $this->root);

    expect(fn () => (new PasswordTooShortCheck($defaults))->run($context))->toThrow(CheckSkipped::class, 'database is down')
        ->and(fn () => (new PasswordNotCheckedForLeaksCheck($defaults))->run($context))->toThrow(CheckSkipped::class, 'database is down');
});

it('evaluates the production branch of the default rule outside production', function () {
    usePasswordRule($this->root);
    Password::defaults(fn () => app()->isProduction() ? Password::min(6) : null);

    $findings = passwordFindings(new PasswordTooShortCheck, $this->root, production: false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->description)->toContain('6 characters');
});

it('evaluates the default rule as without debug mode outside production', function () {
    usePasswordRule($this->root);
    config(['app.debug' => true]);
    Password::defaults(fn () => config('app.debug') ? null : Password::min(6));

    expect(passwordFindings(new PasswordTooShortCheck, $this->root, production: false))->toHaveCount(1);
});

it('restores the environment after evaluating the default rule', function (Closure $callback) {
    usePasswordRule($this->root);
    config(['app.debug' => true]);
    $environment = app()->environment();
    $configured = config('app.env');
    Password::defaults($callback);

    try {
        passwordFindings(new PasswordTooShortCheck, $this->root, production: false);
    } catch (CheckSkipped) {
        // A failing callback is skipped; the environment must still be restored.
    }

    expect(app()->environment())->toBe($environment)
        ->and(config('app.env'))->toBe($configured)
        ->and(config('app.debug'))->toBeTrue();
})->with([
    'returning a rule' => [fn () => Password::min(6)],
    'throwing' => [fn () => throw new RuntimeException('database is down')],
]);

it('evaluates a rule object without a callback in every environment', function () {
    usePasswordRule($this->root);
    Password::defaults(Password::min(12));

    expect(passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root, production: false))->toHaveCount(1);
});

it('skips outside production when the default rule is registered only in some environments', function () {
    usePasswordRule($this->root, "if (app()->isProduction()) {\n    Password::defaults(fn () => Password::min(12)->uncompromised());\n}\n\nreturn ['password' => ['required', Password::default()]];");
    Password::$defaultCallback = null;

    expect(fn () => passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'registered only in some environments')
        // In production nothing was registered, so the framework default is the real rule.
        ->and(passwordFindings(new PasswordNotCheckedForLeaksCheck, $this->root))->toHaveCount(1);
});

it('skips outside production when the callback reads env() directly', function () {
    usePasswordRule($this->root);
    Password::defaults(fn () => env('SECURITY_TOOLKIT_STRONG_PASSWORDS') ? Password::min(12) : Password::min(6));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'reads env() directly')
        ->and(passwordFindings(new PasswordTooShortCheck, $this->root))->toHaveCount(1);
});

it('skips outside production when the default rule is not a closure', function () {
    usePasswordRule($this->root);
    Password::defaults(new class
    {
        public function __invoke(): Password
        {
            return Password::min(6);
        }
    });

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'cannot be inspected')
        ->and(passwordFindings(new PasswordTooShortCheck, $this->root))->toHaveCount(1);
});

it('skips outside production when the rule object is chosen when the application boots', function () {
    usePasswordRule($this->root, "Password::defaults(\$this->app->isProduction() ? Password::min(12)->uncompromised() : Password::min(6));\n\nreturn ['password' => ['required', Password::default()]];");
    Password::defaults(Password::min(6));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'when the application boots');
});

it('skips outside production when the callback captures values computed when the application boots', function () {
    usePasswordRule($this->root);
    $strict = false;
    Password::defaults(fn () => $strict ? Password::min(12) : Password::min(6));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'captures values');
});

it('skips outside production when the rule is registered in more than one place', function () {
    usePasswordRule($this->root, "if (\$this->app->isProduction()) {\n    Password::defaults(fn () => Password::min(12)->uncompromised());\n} else {\n    Password::defaults(fn () => Password::min(6));\n}\n\nreturn ['password' => ['required', Password::default()]];");
    Password::defaults(fn () => Password::min(6));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'more than one place');
});

it('skips outside production when the only registration is conditional', function (string $registration) {
    usePasswordRule($this->root, $registration."\n\nreturn ['password' => ['required', Password::default()]];");
    Password::defaults(fn () => Password::min(6));

    expect(fn () => passwordFindings(new PasswordTooShortCheck, $this->root, production: false))
        ->toThrow(CheckSkipped::class, 'only in some environments');
})->with([
    'if block' => ["if (\$this->app->isLocal()) {\n    Password::defaults(fn () => Password::min(6));\n}"],
    'if without braces' => ["if (\$this->app->isLocal())\n    Password::defaults(fn () => Password::min(6));"],
    'short-circuit' => ['$this->app->isLocal() && Password::defaults(fn () => Password::min(6));'],
]);

it('evaluates the starter kit registration outside production', function () {
    usePasswordRule($this->root, "DB::prohibitDestructiveCommands(app()->isProduction());\n\n// Strong passwords in production, or the framework default if it is local.\nPassword::defaults(fn (): ?Password => app()->isProduction() ? Password::min(6) : null);\n\nreturn ['password' => ['required', Password::default()]];");
    Password::defaults(fn (): ?Password => app()->isProduction() ? Password::min(6) : null);

    expect(passwordFindings(new PasswordTooShortCheck, $this->root, production: false))->toHaveCount(1);
});
