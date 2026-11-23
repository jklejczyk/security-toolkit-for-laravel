<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\VerifiedWithoutMustVerifyEmailCheck;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Models\UnverifiedUser;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Models\VerifiedUser;

beforeEach(function () {
    config(['auth.providers.users.model' => UnverifiedUser::class]);
});

/**
 * @return list<Finding>
 */
function verifiedFindings(): array
{
    return iterator_to_array((new VerifiedWithoutMustVerifyEmailCheck)->run(localContext()), false);
}

function publicRegistration(string $uri = 'register', ?string $name = 'register.store'): void
{
    $route = Route::middleware(['web', 'guest'])->post($uri, fn () => 'registered');

    if ($name !== null) {
        $route->name($name);
    }
}

it('runs in every environment', function () {
    expect((new VerifiedWithoutMustVerifyEmailCheck)->onlyInProduction())->toBeFalse()
        ->and((new VerifiedWithoutMustVerifyEmailCheck)->id())->toBe('auth.verified-without-must-verify-email');
});

it('reports verified routes that let every user through while anyone can register', function () {
    publicRegistration();
    Route::middleware(['web', 'auth', 'verified'])->get('dashboard', fn () => 'dashboard');
    Route::middleware(['web', 'auth', 'verified'])->get('invoices', fn () => 'invoices');

    $findings = verifiedFindings();

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->confidence)->toBe(Confidence::Certain)
        ->and($findings[0]->cwe)->toBe([304])
        ->and($findings[0]->title)->toBe('The verified middleware does not check anything')
        ->and($findings[0]->description)->toContain(UnverifiedUser::class, '2 routes', 'GET /dashboard', 'POST /register')
        ->and($findings[0]->location?->file)->toEndWith('UnverifiedUser.php');
});

it('recognises registration by the route name or the URI', function (string $uri, ?string $name) {
    publicRegistration($uri, $name);
    Route::middleware(['web', 'auth', 'verified'])->get('dashboard', fn () => 'dashboard');

    expect(verifiedFindings())->toHaveCount(1);
})->with([
    'the URI' => ['register', null],
    'the name "register"' => ['sign-up', 'register'],
    'the name "register.store"' => ['konto/nowe', 'register.store'],
]);

it('does not report a user model that requires verification', function () {
    config(['auth.providers.users.model' => VerifiedUser::class]);
    publicRegistration();
    Route::middleware(['web', 'auth', 'verified'])->get('dashboard', fn () => 'dashboard');

    expect(verifiedFindings())->toBe([]);
});

it('does not report without verified routes', function () {
    publicRegistration();
    Route::middleware(['web', 'auth'])->get('dashboard', fn () => 'dashboard');

    expect(verifiedFindings())->toBe([]);
});

it('does not report when accounts are not open to everyone', function () {
    // Only a logged-in admin creates accounts, so every address was given by someone trusted.
    Route::middleware(['web', 'auth'])->post('register', fn () => 'registered')->name('register.store');
    Route::middleware(['web', 'auth', 'verified'])->get('dashboard', fn () => 'dashboard');

    expect(verifiedFindings())->toBe([]);
});

it('skips when the user model cannot be resolved', function () {
    config(['auth.providers.users.model' => 'App\Models\Missing']);
    publicRegistration();
    Route::middleware(['web', 'auth', 'verified'])->get('dashboard', fn () => 'dashboard');

    verifiedFindings();
})->throws(CheckSkipped::class, 'auth.providers.users.model');
