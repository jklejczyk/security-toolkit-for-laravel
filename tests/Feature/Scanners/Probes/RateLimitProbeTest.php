<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Lockout;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Scanners\Probes\CoverageCollector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Engine\ProbeEnvironment;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\RateLimitProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\TwoFactorUser;
use Laravel\Fortify\Features;
use Laravel\Fortify\FortifyServiceProvider;

final class ProbeRateLimitController
{
    public static int $sent = 0;

    public static int $attempts = 0;

    public function refuse(): JsonResponse
    {
        return $this->answer(422, 'These credentials do not match our records.');
    }

    public function count(): JsonResponse
    {
        app(RateLimiter::class)->hit('login', 60);

        return $this->answer(422, 'These credentials do not match our records.');
    }

    public function lockout(Request $request): JsonResponse
    {
        event(new Lockout($request));

        return $this->answer(422, 'These credentials do not match our records.');
    }

    public function limitAfterFiveAttempts(): JsonResponse
    {
        self::$attempts++;

        return self::$attempts > 5
            ? $this->answer(429, 'Too Many Attempts.')
            : $this->answer(422, 'These credentials do not match our records.');
    }

    public function broken(): never
    {
        throw new RuntimeException('the login of this application is broken');
    }

    public function reset(Request $request): JsonResponse
    {
        Password::broker()->sendResetLink(['email' => (string) $request->input('email')]);

        return $this->answer(200, 'sent');
    }

    private function answer(int $status, string $message): JsonResponse
    {
        self::$sent++;

        return response()->json(['message' => $message], $status);
    }
}

/**
 * @param  class-string<Model>  $userModel
 * @return array{0: ProbeContext, 1: CoverageCollector}
 */
function rateLimitProbeContext(?CoverageCollector $collector = null, string $userModel = User::class): array
{
    $map = new ApplicationMap;
    $ownership = new OwnershipResolver($map, [], $userModel);
    $config = ProbesConfig::fromConfig();
    $collector ??= new CoverageCollector;

    return [
        new ProbeContext(
            new HttpClient(app(Kernel::class)),
            $map,
            $collector,
            $config,
            localContext(),
            $ownership,
            new DataSelector($config, $ownership, $map),
            ProbeTargets::of(),
        ),
        $collector,
    ];
}

beforeEach(function () {
    (new ProbeEnvironment)->install();

    ProbeRateLimitController::$sent = 0;
    ProbeRateLimitController::$attempts = 0;

    Schema::create('users', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->string('two_factor_secret')->nullable();
        $table->text('two_factor_recovery_codes')->nullable();
        $table->timestamp('two_factor_confirmed_at')->nullable();
        $table->unsignedBigInteger('company_id')->nullable();
        $table->timestamps();
    });

    Schema::create('password_reset_tokens', function (Blueprint $table) {
        $table->string('email')->primary();
        $table->string('token');
        $table->timestamp('created_at')->nullable();
    });

    config([
        'app.key' => 'base64:'.base64_encode(random_bytes(32)),
        'security-toolkit.probes.data' => 'factories',
        'security-toolkit.probes.owners' => [],
        'security-toolkit.probes.candidates' => 5,
        'auth.passwords.users.throttle' => 0,
        'auth.providers.users.model' => User::class,
    ]);
});

it('confirms a login that the application never limits', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'refuse'])->name('login');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    expect($findings)->toHaveCount(1);

    $entry = $collector->entry('probes.rate-limit');

    expect($findings[0]->ruleId)->toBe('probes.missing-rate-limit')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([307])
        ->and($findings[0]->title)->toBe('POST /login is not limited by the application')
        ->and($findings[0]->reproduction?->steps[0]->received)->toBe('10 attempts answered 422 without a limit')
        ->and($entry->checked)->toBe(1)
        ->and($entry->confirmed)->toBe(1);
});

it('reports a login that counts its attempts against the rate limiter', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'count'])->name('login');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(1)
        ->and($entry->confirmed)->toBe(0)
        ->and($entry->notConfirmed[0]->reason)->toBe('the application counted the attempts against a rate limiter');
});

it('reports nothing when the application raises a lockout itself', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'lockout'])->name('login');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(1)
        ->and($entry->confirmed)->toBe(0)
        ->and($entry->notConfirmed[0]->reason)->toBe('the application counted the attempts against a rate limiter');
});

it('reports nothing when the application answers 429 on the sixth attempt', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'limitAfterFiveAttempts'])->name('login');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(1)
        ->and($entry->notConfirmed[0]->reason)->toBe('answered 429 on attempt 6')
        ->and(ProbeRateLimitController::$sent)->toBe(6);
});

it('leaves a route behind the throttle middleware alone', function () {
    Route::middleware(['web', 'throttle:5,1'])->post('login', [ProbeRateLimitController::class, 'refuse'])->name('login');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(0)
        ->and($entry->skipped)->toHaveCount(1)
        ->and($entry->skipped[0]->reason)->toBe('limited by middleware')
        ->and(ProbeRateLimitController::$sent)->toBe(0);
});

it('skips a login the probe cannot send to, the URL carries a parameter', function () {
    Route::middleware('web')->post('login/{redirect}', [ProbeRateLimitController::class, 'refuse'])->name('login.store');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(0)
        ->and($entry->skipped[0]->reason)->toBe('needs a record for every URL parameter');
});

it('skips a password reset the password broker throttles', function () {
    config(['auth.passwords.users.throttle' => 60]);
    Route::middleware('web')->post('forgot-password', [ProbeRateLimitController::class, 'reset'])->name('password.email');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(0)
        ->and($entry->skipped)->toHaveCount(2)
        ->and($entry->skipped[1]->reason)->toBe('limited by password broker throttle');
});

it('confirms a password reset the password broker does not throttle', function () {
    Route::middleware('web')->post('forgot-password', [ProbeRateLimitController::class, 'reset'])->name('password.email');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('probes.missing-rate-limit')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($findings[0]->title)->toBe('POST /forgot-password is not limited by the application')
        ->and($collector->entry('probes.rate-limit')->confirmed)->toBe(1);
});

it('skips a route that fails with an application error', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'broken'])->name('login');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->checked)->toBe(0)
        ->and($entry->skipped)->toHaveCount(1)
        ->and($entry->skipped[0]->reason)->toBe('login failed with an application error (HTTP 500)');
});

it('skips the challenge when the login route is not recognized', function () {
    Route::middleware('web')->post('two-factor-challenge', [ProbeRateLimitController::class, 'refuse'])
        ->name('two-factor.login.store');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toBeEmpty()
        ->and($entry->skipped)->toHaveCount(2)
        ->and($entry->skipped[0]->reason)->toBe('login route not recognized')
        ->and($entry->skipped[1]->reason)->toBe('2FA challenge not recognized');
});

it('confirms the two factor challenge of Fortify and leaves its counted login alone', function () {
    config([
        'auth.providers.users.model' => TwoFactorUser::class,
        'fortify.features' => [Features::twoFactorAuthentication()],
        'fortify.views' => false,
    ]);
    app()->register(FortifyServiceProvider::class);

    [$context, $collector] = rateLimitProbeContext(userModel: TwoFactorUser::class);

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->title)->toBe('POST /two-factor-challenge is not limited by the application')
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($entry->checked)->toBe(2)
        ->and($entry->confirmed)->toBe(1)
        ->and($entry->notConfirmed[0]->reason)->toBe('the application counted the attempts against a rate limiter');
});

it('recognizes a login route the configuration points at', function () {
    config(['security-toolkit.probes.rate_limit.routes' => ['credentials']]);
    Route::middleware('web')->post('credentials', [ProbeRateLimitController::class, 'refuse'])->name('auth.attempt');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->title)->toBe('POST /credentials is not limited by the application')
        ->and($collector->entry('probes.rate-limit')->confirmed)->toBe(1);
});

it('skips a challenge the application does not offer', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'refuse'])->name('login');
    Route::middleware('web')->post('two-factor-challenge', [ProbeRateLimitController::class, 'refuse'])
        ->name('two-factor.login.store');

    [$context, $collector] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    $entry = $collector->entry('probes.rate-limit');

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->title)->toBe('POST /login is not limited by the application')
        ->and($entry->skipped)->toHaveCount(1)
        ->and($entry->skipped[0]->reason)->toBe('2FA challenge not recognized')
        ->and($entry->skipped[0]->hint)->toBe('enable the two factor authentication feature of Fortify');
});

it('excludes its targets from the CSRF check and puts the exclusions back', function () {
    Route::middleware('web')->post('login', [ProbeRateLimitController::class, 'refuse'])->name('login');

    // The check is off while PHPUnit runs, so the environment says otherwise for this test.
    app()->instance('env', 'local');

    $client = new HttpClient(app(Kernel::class));

    expect($client->request('POST', '/login', ['email' => 'a@example.com', 'password' => 'x'])->status)->toBe(419);

    [$context] = rateLimitProbeContext();

    $findings = iterator_to_array((new RateLimitProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and((new PreventRequestForgery(app(), app(Encrypter::class)))->getExcludedPaths())->toBe([])
        ->and($client->request('POST', '/login', ['email' => 'a@example.com', 'password' => 'x'])->status)->toBe(419);
});
