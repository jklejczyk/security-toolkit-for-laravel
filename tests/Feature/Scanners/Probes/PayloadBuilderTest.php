<?php

declare(strict_types=1);

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Schema;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteParameter;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\Actor;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\PayloadBuilder;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\PayloadResult;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Profile;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\ProfileRequest;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\RulesRequest;

final class PayloadProfileController
{
    public function plain(Profile $profile): Response
    {
        return response()->noContent();
    }

    public function withRules(Profile $profile, RulesRequest $request): Response
    {
        return response()->noContent();
    }

    public function update(Profile $profile, ProfileRequest $request): Response
    {
        return response()->noContent();
    }
}

beforeEach(function () {
    Schema::create('users', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->timestamps();
    });

    Schema::create('profiles', function (Blueprint $table) {
        $table->id();
        $table->string('bio');
        $table->boolean('is_admin')->default(false);
        $table->string('role')->nullable();
        $table->unsignedBigInteger('user_id')->nullable();
        $table->timestamps();
    });

    config([
        'security-toolkit.probes.data' => 'factories',
        'security-toolkit.probes.owners' => [],
        'security-toolkit.probes.candidates' => 5,
    ]);
});

it('builds a body that satisfies the rules', function () {
    $map = new ApplicationMap;
    $ownership = new OwnershipResolver($map, [], User::class);
    $config = ProbesConfig::fromConfig();

    $user = User::factory()->create();
    $actor = new Actor('A', $user);
    $owner = $ownership->for(Profile::class)->owner;

    expect($owner)->not->toBeNull();

    $route = new RouteInfo(
        methods: ['PUT'],
        uri: 'api/profiles/{profile}',
        name: null,
        middleware: [],
        controller: PayloadProfileController::class,
        action: 'update',
        file: 'app/Http/Controllers/PayloadProfileController.php',
        line: 1,
        models: [new RouteParameter('profile', Profile::class)],
        enforcesScopedBindings: false,
        preventsScopedBindings: false,
        inApp: true,
    );

    $builder = new PayloadBuilder(app(Container::class), $map, $ownership, $config);
    $result = $builder->build($route, $owner, $actor, Profile::class);

    expect($result->isBuilt())->toBeTrue()
        ->and($result->body)->toHaveKey('bio');
});

it('returns a reason when the action has no FormRequest', function () {
    $map = new ApplicationMap;
    $ownership = new OwnershipResolver($map, [], User::class);
    $config = ProbesConfig::fromConfig();

    $user = User::factory()->create();
    $actor = new Actor('A', $user);
    $owner = $ownership->for(Profile::class)->owner;

    expect($owner)->not->toBeNull();

    $route = new RouteInfo(
        methods: ['PUT'],
        uri: 'api/profiles/{profile}',
        name: null,
        middleware: [],
        controller: PayloadProfileController::class,
        action: 'missing',
        file: 'app/Http/Controllers/PayloadProfileController.php',
        line: 1,
        models: [new RouteParameter('profile', Profile::class)],
        enforcesScopedBindings: false,
        preventsScopedBindings: false,
        inApp: true,
    );

    $builder = new PayloadBuilder(app(Container::class), $map, $ownership, $config);
    $result = $builder->build($route, $owner, $actor, Profile::class);

    expect($result->isBuilt())->toBeFalse()
        ->and($result->reason)->toContain('FormRequest');
});

/**
 * Builds the body for an action of PayloadProfileController on PUT api/profiles/{profile}.
 */
function buildPayload(string $action, ...$extra): PayloadResult
{
    $map = new ApplicationMap;
    $ownership = new OwnershipResolver($map, [], User::class);
    $owner = $ownership->for(Profile::class)->owner;

    expect($owner)->not->toBeNull();

    $route = new RouteInfo(
        methods: ['PUT'],
        uri: 'api/profiles/{profile}',
        name: null,
        middleware: [],
        controller: PayloadProfileController::class,
        action: $action,
        file: 'app/Http/Controllers/PayloadProfileController.php',
        line: 1,
        models: [new RouteParameter('profile', Profile::class)],
        enforcesScopedBindings: false,
        preventsScopedBindings: false,
        inApp: true,
    );

    return (new PayloadBuilder(app(Container::class), $map, $ownership, ProbesConfig::fromConfig()))
        ->build($route, $owner, new Actor('A', User::factory()->create()), Profile::class, ...$extra);
}

it('picks a value of the rule type, not of a modifier', function (mixed $rules, mixed $expected) {
    RulesRequest::$rules = ['field' => $rules];

    $result = buildPayload('withRules');

    expect($result->reason)->toBeNull()
        ->and($result->body)->toBe(['field' => $expected]);
})->with([
    'required integer' => [['required', 'integer'], 1],
    'sometimes date' => [['sometimes', 'date'], '2026-01-01'],
    'nullable email as a string' => ['nullable|email', 'probe@example.test'],
    'required string as a string' => ['required|string', 'probe'],
]);

describe('probes.payloads.fields', function () {
    beforeEach(function () {
        RulesRequest::$rules = ['field' => ['required', 'string']];
    });

    it('overrides a value from the rules with the value configured for the model', function () {
        config(['security-toolkit.probes.payloads.fields' => [Profile::class => ['field' => 'configured']]]);

        expect(buildPayload('withRules')->body)->toBe(['field' => 'configured']);
    });

    it('prefers the route over the model', function () {
        config(['security-toolkit.probes.payloads.fields' => [
            Profile::class => ['field' => 'model'],
            'PUT /api/profiles/{profile}' => ['field' => 'route'],
        ]]);

        expect(buildPayload('withRules')->body)->toBe(['field' => 'route']);
    });

    it('builds the body from the configuration alone when the action has no rules', function () {
        config(['security-toolkit.probes.payloads.fields' => [Profile::class => ['bio' => 'configured']]]);

        $result = buildPayload('plain');

        expect($result->body)->toBe(['bio' => 'configured'])
            ->and($result->source)->toBe('config');
    });

    it('leaves out ignored fields', function () {
        config([
            'security-toolkit.probes.payloads.fields' => [Profile::class => ['field' => 'configured', 'secret' => 'x']],
            'security-toolkit.probes.payloads.ignore' => ['secret'],
        ]);

        expect(buildPayload('withRules')->body)->toBe(['field' => 'configured']);
    });
});
