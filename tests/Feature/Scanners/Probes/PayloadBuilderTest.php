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
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Profile;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\ProfileRequest;

final class PayloadProfileController
{
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
