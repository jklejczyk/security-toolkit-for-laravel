<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelection;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\Owner;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Company;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Draft;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Invoice;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;

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
});

/**
 * @param  array<string, string>  $owners
 */
function selector(string $mode, array $owners = []): DataSelector
{
    config([
        'security-toolkit.probes.data' => $mode,
        'security-toolkit.probes.owners' => $owners,
        'security-toolkit.probes.candidates' => 5,
    ]);

    return new DataSelector(
        ProbesConfig::fromConfig(),
        new OwnershipResolver(new ApplicationMap, $owners, User::class),
    );
}

function ownerOf(string $model): Owner
{
    $owner = (new OwnershipResolver(new ApplicationMap, [], User::class))->for($model)->owner;

    expect($owner)->not->toBeNull();

    return $owner;
}

function select(string $mode, string $model): DataSelection
{
    return selector($mode)->for($model, ownerOf($model));
}

it('builds two owners and their records from factories', function () {
    $selection = select('factories', Invoice::class);

    expect($selection->isFound())->toBeTrue();

    $data = $selection->data;

    expect($data?->mode)->toBe('factories')
        ->and($data?->a->ownerId())->not->toBe($data?->b->ownerId())
        ->and($data?->a->id())->not->toBe($data?->b->id())
        ->and($data?->recordA?->getAttribute('company_id'))->toBe($data?->a->ownerId())
        ->and($data?->recordB?->getAttribute('company_id'))->toBe($data?->b->ownerId());
});

it('reads two owners that already have records', function () {
    $companyA = Company::query()->create(['name' => 'A']);
    $companyB = Company::query()->create(['name' => 'B']);

    $userA = User::query()->create(['name' => 'A', 'email' => 'a@example.com', 'password' => 'x', 'company_id' => $companyA->getKey()]);
    $userB = User::query()->create(['name' => 'B', 'email' => 'b@example.com', 'password' => 'x', 'company_id' => $companyB->getKey()]);

    $invoiceA = Invoice::query()->create(['number' => 'INV-A', 'company_id' => $companyA->getKey(), 'user_id' => $userA->getKey()]);
    $invoiceB = Invoice::query()->create(['number' => 'INV-B', 'company_id' => $companyB->getKey(), 'user_id' => $userB->getKey()]);

    $selection = select('existing', Invoice::class);

    expect($selection->isFound())->toBeTrue();

    $data = $selection->data;

    expect($data?->mode)->toBe('existing')
        ->and($data?->recordA?->getKey())->toBe($invoiceA->getKey())
        ->and($data?->recordB?->getKey())->toBe($invoiceB->getKey())
        ->and($data?->a->id())->toBe($userA->getKey())
        ->and($data?->b->id())->toBe($userB->getKey());
});

it('skips existing when fewer than two owners have records', function () {
    $company = Company::query()->create(['name' => 'A']);
    $user = User::query()->create(['name' => 'A', 'email' => 'a@example.com', 'password' => 'x', 'company_id' => $company->getKey()]);
    Invoice::query()->create(['number' => 'INV-A', 'company_id' => $company->getKey(), 'user_id' => $user->getKey()]);

    $selection = select('existing', Invoice::class);

    expect($selection->isFound())->toBeFalse()
        ->and($selection->reason)->toContain('fewer than two owners');
});

it('prefers factories in automatic mode', function () {
    $selection = select('auto', Invoice::class);

    expect($selection->isFound())->toBeTrue()
        ->and($selection->data?->mode)->toBe('factories');
});

it('skips factories when the model has none', function () {
    $selection = select('factories', Draft::class);

    expect($selection->isFound())->toBeFalse()
        ->and($selection->reason)->toContain('no factory');
});
