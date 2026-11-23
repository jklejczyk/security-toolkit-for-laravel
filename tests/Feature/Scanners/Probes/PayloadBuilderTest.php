<?php

declare(strict_types=1);

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Validator;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\Map\RouteInfo;
use Jklejczyk\SecurityToolkit\Core\Map\RouteParameter;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\Actor;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\PayloadBuilder;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\PayloadResult;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\ValidationRequest;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Profile;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\ProfileRequest;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\RulesRequest;

final class PayloadProfileController
{
    /** @var list<string> paths of the requests the runtime step sent */
    public static array $seen = [];

    public function needsNumber(Request $request, Profile $profile): Response
    {
        self::$seen[] = $request->path();
        Validator::make($request->all(), ['number' => ['required', 'integer']])->validate();

        return response()->noContent();
    }

    public function neverValid(Request $request, Profile $profile): Response
    {
        self::$seen[] = $request->path();
        Validator::make($request->all(), ['number' => ['required', 'in:never']])->validate();

        return response()->noContent();
    }

    public function acceptsAnything(Request $request, Profile $profile): Response
    {
        self::$seen[] = $request->path();

        return response()->noContent();
    }

    public function bareRefusal(Request $request, Profile $profile): JsonResponse
    {
        self::$seen[] = $request->path();

        return response()->json(['message' => 'Nope.'], 422);
    }

    public function impossibleInline(Request $request, Profile $profile): Response
    {
        self::$seen[] = $request->path();
        $request->validate(['number' => ['required', 'in:']]);

        return response()->noContent();
    }

    public function inline(Request $request, Profile $profile): Response
    {
        $profile->update($request->validate(['bio' => ['required', 'string'], 'role' => 'nullable|string|max:20']));

        return response()->noContent();
    }

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

it('reads the rules from a validate call in the action', function () {
    $result = buildPayload('inline');

    expect($result->body)->toBe(['bio' => 'probe', 'role' => 'probe'])
        ->and($result->source)->toBe('inline');
});

describe('validation errors at runtime', function () {
    beforeEach(function () {
        PayloadProfileController::$seen = [];
    });

    function validationRequest(string $action): ValidationRequest
    {
        Route::put('api/profiles/{profile}', [PayloadProfileController::class, $action]);

        return new ValidationRequest(new HttpClient(app(Kernel::class)), 'PUT', '/api/profiles/7', User::factory()->create());
    }

    it('learns the fields the action asks for', function () {
        $result = buildPayload('needsNumber', validationRequest('needsNumber'));

        expect($result->reason)->toBeNull()
            ->and($result->body)->toBe(['number' => 1])
            ->and($result->source)->toBe('runtime');
    });

    it('names the fields it could not fill after three rounds', function () {
        $result = buildPayload('neverValid', validationRequest('neverValid'));

        expect($result->isBuilt())->toBeFalse()
            ->and($result->reason)->toBe('cannot build a request body from the validation errors: number')
            ->and(PayloadProfileController::$seen)->toHaveCount(4);
    });

    it('gives up when the action accepts a request without fields', function () {
        $result = buildPayload('acceptsAnything', validationRequest('acceptsAnything'));

        expect($result->reason)->toBe('the action accepts a request without fields; cannot tell which fields it writes');
    });

    it('gives up on a 422 without validation errors', function () {
        $result = buildPayload('bareRefusal', validationRequest('bareRefusal'));

        expect($result->reason)->toBe('the action answered 422 without validation errors to read')
            ->and(PayloadProfileController::$seen)->toHaveCount(1);
    });

    it('falls back to the runtime step when the rules in the action cannot be met', function () {
        buildPayload('impossibleInline', validationRequest('impossibleInline'));

        expect(PayloadProfileController::$seen)->not->toBeEmpty();
    });

    it('sends every request to the record it was given', function () {
        buildPayload('neverValid', validationRequest('neverValid'));

        expect(array_unique(PayloadProfileController::$seen))->toBe(['api/profiles/7']);
    });

    it('sends nothing without a validation request', function () {
        Route::put('api/profiles/{profile}', [PayloadProfileController::class, 'needsNumber']);

        expect(buildPayload('needsNumber')->isBuilt())->toBeFalse()
            ->and(PayloadProfileController::$seen)->toBe([]);
    });
});
