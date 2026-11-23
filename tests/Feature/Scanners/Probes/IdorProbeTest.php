<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
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
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Company;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Invoice;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\InvoicePolicy;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Receipt;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\ReceiptPolicy;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Statement;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\StatementPolicy;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\InvoiceRequest;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\TokenWall;

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

    public function rewriteChecked(Invoice $invoice, Request $request): Response
    {
        Validator::make($request->all(), ['number' => ['required', 'string']])->validate();
        $invoice->update(['number' => $request->input('number')]);

        return response()->noContent();
    }

    public function ignore(Invoice $invoice, InvoiceRequest $request): Response
    {
        return response()->noContent();
    }

    public function rewrite(Invoice $invoice, InvoiceRequest $request): Response
    {
        $invoice->update(['number' => $request->validated()['number']]);

        return response()->noContent();
    }
}

final class ProbeNestedStatementController
{
    public function show(Client $client, Statement $statement): JsonResponse
    {
        return response()->json($statement);
    }

    public function deep(Company $company, Client $client, Statement $statement): JsonResponse
    {
        return response()->json($statement);
    }

    public function orphan(Client $client, Invoice $invoice): JsonResponse
    {
        return response()->json($invoice);
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

    Schema::create('statements', function (Blueprint $table) {
        $table->id();
        $table->string('reference');
        $table->unsignedBigInteger('company_id')->nullable();
        $table->unsignedBigInteger('client_id')->nullable();
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
    Gate::policy(Statement::class, StatementPolicy::class);
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

it('confirms a write whose body it learned from the validation errors, and says so', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/invoices/{invoice}', [ProbeIdorController::class, 'rewriteChecked']);

    [$context] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($findings[0]->description)->toContain("request body inferred from the application's validation errors");
});

it('does not mention inferred bodies when the rules were read', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/invoices/{invoice}', [ProbeIdorController::class, 'rewrite']);

    [$context] = idorContext();

    expect(iterator_to_array((new IdorProbe)->run($context))[0]->description)->not->toContain('inferred');
});

it('does not confirm a write that left the other owner\'s record as it was', function () {
    // The factory leaves user_id unset; the database row has it as null, which must not count as a change.
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/invoices/{invoice}', [ProbeIdorController::class, 'ignore']);

    [$context, $collector] = idorContext();

    expect(iterator_to_array((new IdorProbe)->run($context)))->toBe([])
        ->and($collector->entry('probes.idor')->checked)->toBe(1);
});

it('confirms a delete of another owner\'s record', function () {
    Route::middleware(['auth', SubstituteBindings::class])->delete('api/invoices/{invoice}', [ProbeIdorController::class, 'destroy']);

    [$context] = idorContext();

    $findings = iterator_to_array((new IdorProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
});

describe('behind the CSRF check', function () {
    beforeEach(function () {
        // Testbench runs as "testing", where Laravel skips the CSRF check; the polygon apps do not.
        $this->environment = app()->environment();
        app()->detectEnvironment(fn () => 'local');
        // The web group encrypts cookies, which needs an application key.
        config(['app.key' => 'base64:'.base64_encode(str_repeat('k', 32))]);
    });

    afterEach(function () {
        app()->detectEnvironment(fn () => $this->environment);
    });

    it('confirms writes of another owner\'s record on web routes, as user A has a token of their own', function (string $method, string $action) {
        Route::middleware(['web', 'auth'])->{$method}('invoices/{invoice}', [ProbeIdorController::class, $action]);

        [$context] = idorContext();

        $findings = iterator_to_array((new IdorProbe)->run($context));

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
    })->with([['delete', 'destroy'], ['put', 'rewrite']]);

    it('skips a write that a CSRF check it cannot pass turns away, instead of counting it as checked', function () {
        Route::middleware(['auth', SubstituteBindings::class, TokenWall::class])->delete('api/invoices/{invoice}', [ProbeIdorController::class, 'destroy']);

        [$context, $collector] = idorContext();

        expect(iterator_to_array((new IdorProbe)->run($context)))->toBe([])
            ->and($collector->entry('probes.idor')->checked)->toBe(0)
            ->and($collector->entry('probes.idor')->skipped[0]->reason)->toBe('blocked by the CSRF check');
    });
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

describe('nested routes whose parent is not on the owner path', function () {
    it('confirms a read of another owner\'s child under a parent of A', function () {
        Route::middleware(['auth', SubstituteBindings::class])
            ->get('api/clients/{client}/statements/{statement}', [ProbeNestedStatementController::class, 'show']);

        [$context] = idorContext();

        $findings = iterator_to_array((new IdorProbe)->run($context));

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->confidence)->toBe(Confidence::Confirmed);
    });

    it('does not confirm when the bindings are scoped', function () {
        Route::middleware(['auth', SubstituteBindings::class])->scopeBindings()
            ->get('api/clients/{client}/statements/{statement}', [ProbeNestedStatementController::class, 'show']);

        [$context, $collector] = idorContext();

        expect(iterator_to_array((new IdorProbe)->run($context)))->toBe([])
            ->and($collector->entry('probes.idor')->notConfirmed[0]->reason ?? null)->toBe('answered 404 for the other owner');
    });

    it('skips a child that does not belong to the parent model', function () {
        Route::middleware(['auth', SubstituteBindings::class])
            ->get('api/clients/{client}/invoices/{invoice}', [ProbeNestedStatementController::class, 'orphan']);

        [$context, $collector] = idorContext();

        expect(iterator_to_array((new IdorProbe)->run($context)))->toBe([])
            ->and($collector->entry('probes.idor')->skipped[0]->reason)->toBe('cannot find how Invoice belongs to Client');
    });

    it('skips in the existing mode when A has no child under its parent', function () {
        config(['security-toolkit.probes.data' => 'existing']);
        Route::middleware(['auth', SubstituteBindings::class])
            ->get('api/clients/{client}/statements/{statement}', [ProbeNestedStatementController::class, 'show']);

        $companyA = Company::query()->create(['name' => 'A']);
        $companyB = Company::query()->create(['name' => 'B']);
        User::query()->create(['name' => 'A', 'email' => 'a@example.com', 'password' => 'x', 'company_id' => $companyA->getKey()]);
        User::query()->create(['name' => 'B', 'email' => 'b@example.com', 'password' => 'x', 'company_id' => $companyB->getKey()]);
        Client::query()->create(['name' => 'Client of A', 'company_id' => $companyA->getKey()]);
        $clientB = Client::query()->create(['name' => 'Client of B', 'company_id' => $companyB->getKey()]);
        Statement::query()->create(['reference' => 'ST-A', 'company_id' => $companyA->getKey()]);
        Statement::query()->create(['reference' => 'ST-B', 'company_id' => $companyB->getKey(), 'client_id' => $clientB->getKey()]);

        [$context, $collector] = idorContext();

        expect(iterator_to_array((new IdorProbe)->run($context)))->toBe([])
            ->and($collector->entry('probes.idor')->skipped[0]->reason)->toBe('no Statement of A under its Client');
    });

    it('skips more than one parent outside the owner path', function () {
        Route::middleware(['auth', SubstituteBindings::class])
            ->get('api/companies/{company}/clients/{client}/statements/{statement}', [ProbeNestedStatementController::class, 'deep']);

        [$context, $collector] = idorContext();

        iterator_to_array((new IdorProbe)->run($context));

        expect(collect($collector->entry('probes.idor')->skipped)->pluck('reason')->all())
            ->toContain('nested routes with more than one parent outside the owner path are not supported');
    });
});
