<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Response;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Scanners\Probes\CoverageCollector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\CsrfProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Invoice;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\InvoiceRequest;

final class ProbeCsrfController
{
    public function destroy(Invoice $invoice): Response
    {
        $invoice->delete();

        return response()->noContent();
    }

    public function update(Invoice $invoice): Response
    {
        return response()->noContent();
    }

    public function rewrite(Invoice $invoice, InvoiceRequest $request): Response
    {
        $invoice->update(['number' => $request->validated()['number']]);

        return response()->noContent();
    }
}

/**
 * Sets the URIs excluded from CSRF the way validateCsrfTokens(except:) does.
 *
 * @param  list<string>  $uris
 */
function csrfProbeExclude(array $uris): void
{
    foreach (['Illuminate\Foundation\Http\Middleware\PreventRequestForgery', 'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken'] as $class) {
        if (class_exists($class) && property_exists($class, 'neverVerify')) {
            (new ReflectionClass($class))->setStaticPropertyValue('neverVerify', $uris);

            return;
        }
    }
}

function csrfProbeContext(?CoverageCollector $collector = null): array
{
    $map = new ApplicationMap;
    $ownership = new OwnershipResolver($map, [], User::class);
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
    Schema::create('companies', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->unsignedBigInteger('parent_id')->nullable();
        $table->timestamps();
    });

    Schema::create('users', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->unsignedBigInteger('company_id')->nullable();
        $table->timestamps();
    });

    Schema::create('invoices', function (Blueprint $table) {
        $table->id();
        $table->string('number');
        $table->unsignedBigInteger('company_id')->nullable();
        $table->unsignedBigInteger('user_id')->nullable();
        $table->timestamps();
    });

    config([
        'security-toolkit.probes.data' => 'factories',
        'security-toolkit.probes.owners' => [],
        'security-toolkit.probes.candidates' => 5,
        'session.same_site' => 'none',
        'app.key' => 'base64:'.base64_encode(random_bytes(32)),
    ]);
});

afterEach(function () {
    csrfProbeExclude([]);
});

it('confirms a write on an excluded route when SameSite is none', function () {
    csrfProbeExclude(['api/invoices/*']);
    Route::middleware(['web', 'auth', SubstituteBindings::class])
        ->delete('api/invoices/{invoice}', [ProbeCsrfController::class, 'destroy']);

    [$context, $collector] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('routes.csrf-excluded')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($findings[0]->cwe)->toBe([352])
        ->and($collector->entry('probes.csrf')->confirmed)->toBe(1);
});

it('confirms a write on a session route without the CSRF middleware', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->delete('api/invoices/{invoice}', [ProbeCsrfController::class, 'destroy']);

    [$context, $collector] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('probes.csrf-unprotected')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('checks the write but reports nothing when SameSite is lax', function () {
    config(['session.same_site' => 'lax']);
    csrfProbeExclude(['api/invoices/*']);
    Route::middleware(['web', 'auth', SubstituteBindings::class])
        ->delete('api/invoices/{invoice}', [ProbeCsrfController::class, 'destroy']);

    [$context, $collector] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toBeEmpty()
        ->and($collector->entry('probes.csrf')->checked)->toBe(1)
        ->and($collector->entry('probes.csrf')->confirmed)->toBe(0);
});

it('confirms a write on an excluded route without a token', function () {
    csrfProbeExclude(['api/invoices/*']);
    Route::middleware(['web', 'auth', SubstituteBindings::class])
        ->put('api/invoices/{invoice}', [ProbeCsrfController::class, 'rewrite']);

    [$context, $collector] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('routes.csrf-excluded')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($collector->entry('probes.csrf')->confirmed)->toBe(1);
});

it('skips a route that needs a request body', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/invoices/{invoice}', [ProbeCsrfController::class, 'update']);

    [$context, $collector] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toBeEmpty()
        ->and($collector->entry('probes.csrf')->skipped)->toHaveCount(1);
});

it('ignores a route behind the CSRF check without an exclusion', function () {
    csrfProbeExclude(['webhooks/*']);
    Route::middleware(['web', 'auth', SubstituteBindings::class])
        ->delete('api/invoices/{invoice}', [ProbeCsrfController::class, 'destroy']);

    [$context] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toBeEmpty();
});

it('ignores an API route without a session guard', function () {
    Route::middleware([SubstituteBindings::class])
        ->delete('api/invoices/{invoice}', [ProbeCsrfController::class, 'destroy']);

    [$context] = csrfProbeContext();

    $findings = iterator_to_array((new CsrfProbe)->run($context));

    expect($findings)->toBeEmpty();
});
