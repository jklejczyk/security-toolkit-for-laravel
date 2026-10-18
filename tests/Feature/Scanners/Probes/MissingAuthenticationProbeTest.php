<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Response;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteParameter;
use Jklejczyk\SecurityToolkit\Scanners\Probes\CoverageCollector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\MissingAuthenticationProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTarget;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Invoice;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;

final class ProbeInvoiceController
{
    public function destroy(Invoice $invoice): Response
    {
        $invoice->delete();

        return response()->noContent();
    }

    public function guard(Invoice $invoice): Response
    {
        return response()->noContent(403);
    }
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
    ]);
});

/**
 * @param  list<string>  $methods
 */
function probeContext(array $methods, ?CoverageCollector $collector = null): array
{
    $map = new ApplicationMap;
    $ownership = new OwnershipResolver($map, [], User::class);
    $config = ProbesConfig::fromConfig();

    $route = new RouteInfo(
        methods: $methods,
        uri: 'api/invoices/{invoice}',
        name: 'invoices.destroy',
        middleware: [],
        controller: ProbeInvoiceController::class,
        action: 'destroy',
        file: 'app/Http/Controllers/ProbeInvoiceController.php',
        line: 1,
        models: [new RouteParameter('invoice', Invoice::class)],
        enforcesScopedBindings: false,
        preventsScopedBindings: false,
        inApp: true,
    );

    $suspicion = new Finding(
        'routes.missing-authentication',
        Severity::High,
        'title',
        'description',
        'remediation',
        confidence: Confidence::Suspected,
    );

    $targets = ProbeTargets::of(new ProbeTarget($route, $suspicion));

    return [
        new ProbeContext(
            new HttpClient(app(Kernel::class)),
            $map,
            $collector ?? new CoverageCollector,
            $config,
            localContext(),
            $ownership,
            new DataSelector($config, $ownership, $map),
            $targets,
        ),
        $collector,
    ];
}

it('confirms a delete that a guest really performed', function () {
    Route::delete('/api/invoices/{invoice}', [ProbeInvoiceController::class, 'destroy'])->middleware(SubstituteBindings::class);

    [$context] = probeContext(['DELETE']);

    $findings = iterator_to_array((new MissingAuthenticationProbe)->run($context));

    expect($findings)->toHaveCount(1);

    $finding = $findings[0];

    expect($finding->ruleId)->toBe('routes.missing-authentication')
        ->and($finding->confidence)->toBe(Confidence::Confirmed)
        ->and($finding->reproduction?->probe)->toBe('probes.missing-authentication');
});

it('does not confirm when the action refuses the guest', function () {
    Route::delete('/api/invoices/{invoice}', [ProbeInvoiceController::class, 'guard'])->middleware(SubstituteBindings::class);

    $collector = new CoverageCollector;
    [$context] = probeContext(['DELETE'], $collector);

    $findings = iterator_to_array((new MissingAuthenticationProbe)->run($context));

    expect($findings)->toBeEmpty();

    $entry = $collector->entry('probes.missing-authentication');

    expect($entry->checked)->toBe(1)
        ->and($entry->confirmed)->toBe(0);
});

it('skips a route that needs a request body', function () {
    Route::put('/api/invoices/{invoice}', [ProbeInvoiceController::class, 'destroy'])->middleware(SubstituteBindings::class);

    $collector = new CoverageCollector;
    [$context] = probeContext(['PUT'], $collector);

    $findings = iterator_to_array((new MissingAuthenticationProbe)->run($context));

    expect($findings)->toBeEmpty();

    $entry = $collector->entry('probes.missing-authentication');

    expect($entry->checked)->toBe(0)
        ->and($entry->skipped)->toHaveCount(1)
        ->and($entry->skipped[0]->reason)->toContain('request body');
});
