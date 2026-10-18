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
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\CoverageCollector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Data\DataSelector;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbeContext;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Probes\MassAssignmentProbe;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Jklejczyk\SecurityToolkit\Scanners\Probes\StaticModels;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Targets\ProbeTargets;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Profile;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes\ProfileRequest;

final class ProbeProfileController
{
    public function update(Profile $profile, ProfileRequest $request): Response
    {
        $profile->update($request->all());

        return response()->noContent();
    }

    public function guarded(Profile $profile, ProfileRequest $request): Response
    {
        $profile->update($request->validated());

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

function massAssignmentContext(?CoverageCollector $collector = null): array
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

it('confirms a privileged column that the request can set', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/profiles/{profile}', [ProbeProfileController::class, 'update']);

    [$context, $collector] = massAssignmentContext();

    $findings = iterator_to_array((new MassAssignmentProbe)->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('probes.mass-assignment')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($findings[0]->cwe)->toBe([915])
        ->and($collector->entry('probes.mass-assignment')->confirmed)->toBe(1);
});

it('does not confirm when the action validates the request', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/profiles/{profile}', [ProbeProfileController::class, 'guarded']);

    [$context, $collector] = massAssignmentContext();

    $findings = iterator_to_array((new MassAssignmentProbe)->run($context));

    expect($findings)->toBeEmpty()
        ->and($collector->entry('probes.mass-assignment')->confirmed)->toBe(0);
});

it('confirms the static models.guarded-empty finding for the model', function () {
    Route::middleware(['auth', SubstituteBindings::class])
        ->put('api/profiles/{profile}', [ProbeProfileController::class, 'update']);

    $static = new class extends StaticModels
    {
        public function guardedEmpty(ScanContext $context, string $model): ?Finding
        {
            return $model === Profile::class
                ? new Finding('models.guarded-empty', Severity::Medium, 'T', 'D', 'R', location: new Location('app/Models/Profile.php', 1), cwe: [915])
                : null;
        }
    };

    [$context] = massAssignmentContext();

    $findings = iterator_to_array((new MassAssignmentProbe($static))->run($context));

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->ruleId)->toBe('models.guarded-empty')
        ->and($findings[0]->confidence)->toBe(Confidence::Confirmed)
        ->and($findings[0]->location->file)->toBe('app/Models/Profile.php');
});
