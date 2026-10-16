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
function passwordFindings(PasswordTooShortCheck|PasswordNotCheckedForLeaksCheck $check, string $root): array
{
    return iterator_to_array($check->run(productionContext(basePath: $root)), false);
}

it('declares production-only rule ids', function () {
    expect((new PasswordTooShortCheck)->id())->toBe('auth.password-too-short')
        ->and((new PasswordTooShortCheck)->onlyInProduction())->toBeTrue()
        ->and((new PasswordNotCheckedForLeaksCheck)->id())->toBe('auth.password-not-checked-for-leaks')
        ->and((new PasswordNotCheckedForLeaksCheck)->onlyInProduction())->toBeTrue();
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
