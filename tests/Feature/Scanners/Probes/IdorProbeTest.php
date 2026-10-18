<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Gate;
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
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\IdorProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTarget;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Client;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Invoice;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\InvoicePolicy;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Receipt;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\ReceiptPolicy;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\InvoiceRequest;

final class ProbeIdorController
{
    public function show(Invoice $invoice): JsonResponse
    {
        return response()->json($invoice);
    }

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

final class ProbeNestedReceiptController
{
    public function show(Client $client, Receipt $receipt): JsonResponse
    {
        return response()->json($receipt);
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

    Schema::create('clients', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->unsignedBigInteger('company_id')->nullable();
        $table->timestamps();
    });

    Schema::create('receipts', function (Blueprint $table) {
        $table->id();
        $table->string('reference');
        $table->unsignedBigInteger('client_id')->nullable();
        $table->timestamps();
    });

    config([
        'security-toolkit.probes.data' => 'factories',
        'security-toolkit.probes.owners' => [],
        'security-toolkit.probes.candidates' => 5,
    ]);

    Gate::policy(Invoice::class, InvoicePolicy::class);
    Gate::policy(Receipt::class, ReceiptPolicy::class);
});

function idorContext(?ProbeTarget $target = null, ?CoverageCollector $collector = null): array
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
            $target === null ? ProbeTargets::of() : ProbeTargets::of($target),
        ),
        $collector,
    ];
}

function idorTarget(string $rule, array $methods, string $uri): ProbeTarget
{
    $route = new RouteInfo(
        methods: $methods,
        uri: $uri,
        name: null,
        middleware: [],
        controller: ProbeIdorController::class,
        action: 'show',
        file: 'app/Http/Controllers/ProbeIdorController.php',
        line: 1,
        models: [new RouteParameter('invoice', Invoice::class)],
        enforcesScopedBindings: false,
        preventsScopedBindings: false,
        inApp: true,
    );

    return new ProbeTarget($route, new Finding(
        $rule,
        Severity::Medium,
        'title',
        'description',
        'remediation',
        confidence: Confidence::Suspected,
    ));
}

it('confirms a read of another owner\'s record', function () {
    Route::middleware(['auth', SubstituteBindings::class])->get('api/invoices/{invoice}', [ProbeIdorController::class, 'show']);

    [$context] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('probes.idor')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('keeps the rule of the suspicion the probe confirmed', function () {
    Route::middleware(['auth', SubstituteBindings::class])->get('api/invoices/{invoice}', [ProbeIdorController::class, 'show']);

    [$context] = idorContext(idorTarget('routes.missing-authorization', ['GET'], 'api/invoices/{invoice}'));

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('routes.missing-authorization')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('confirms a write of another owner\'s record', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/invoices/{invoice}', [ProbeIdorController::class, 'rewrite']);

    [$context, $collector] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($collector->entry('probes.idor')->confirmed)->toBe(1);
});

it('confirms a delete of another owner\'s record', function () {
    Route::middleware(['auth', SubstituteBindings::class])->delete('api/invoices/{invoice}', [ProbeIdorController::class, 'destroy']);

    [$context] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('skips a route without a policy', function () {
    Gate::policy(Invoice::class, null);
    Route::middleware(['auth', SubstituteBindings::class])->get('api/invoices/{invoice}', [ProbeIdorController::class, 'show']);

    [$context, $collector] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toBeEmpty()
        ->and($collector->entry('probes.idor')->skipped)->toHaveCount(1);
});

it('skips a route that needs a request body', function () {
    Route::middleware(['auth', SubstituteBindings::class])->put('api/invoices/{invoice}', [ProbeIdorController::class, 'update']);

    [$context, $collector] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toBeEmpty()
        ->and($collector->entry('probes.idor')->skipped)->toHaveCount(1);
});

it('ignores a route without authentication', function () {
    Route::middleware([SubstituteBindings::class])->get('api/invoices/{invoice}', [ProbeIdorController::class, 'show']);

    [$context] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toBeEmpty();
});

it('confirms a nested read when the child is bound without a scope', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->get('api/clients/{client}/receipts/{receipt}', [ProbeNestedReceiptController::class, 'show']);

    [$context] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('probes.idor')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
});

it('does not confirm a nested read when bindings are scoped', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->get('api/clients/{client}/receipts/{receipt}', [ProbeNestedReceiptController::class, 'show'])
        ->scopeBindings();

    [$context, $collector] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toBeEmpty()
        ->and($collector->entry('probes.idor')->checked)->toBe(1)
        ->and($collector->entry('probes.idor')->confirmed)->toBe(0);
});
