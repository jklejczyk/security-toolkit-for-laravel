<?php

declare(strict_types=1);

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\File;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\SanctumTokensNeverExpireCheck;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Models\UserWithApiTokens;

beforeEach(function () {
    $this->root = temporaryApp();
    config(['sanctum.expiration' => null, 'auth.providers.users.model' => UserWithApiTokens::class]);
});

afterEach(function () {
    File::deleteDirectory($this->root);
});

/**
 * @param  list<string>  $packages
 * @return list<Finding>
 */
function sanctumFindings(string $root, array $packages = ['laravel/sanctum'], bool $production = true): array
{
    $context = $production ? productionContext($packages, $root) : localContext($packages, $root);

    return iterator_to_array((new SanctumTokensNeverExpireCheck)->run($context), false);
}

it('runs in every environment', function () {
    expect((new SanctumTokensNeverExpireCheck)->onlyInProduction())->toBeFalse()
        ->and((new SanctumTokensNeverExpireCheck)->id())->toBe('auth.sanctum-tokens-never-expire');
});

function issueTokens(string $root, string $call = "\$user->createToken('api')"): void
{
    file_put_contents($root.'/app/TokenController.php', "<?php\n\n\$token = {$call};\n");
}

it('reports API tokens that never expire', function () {
    issueTokens($this->root);
    mkdir($this->root.'/config');
    file_put_contents($this->root.'/config/sanctum.php', '<?php return [];');

    $findings = sanctumFindings($this->root);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([613])
        ->and($findings[0]->cvss)->toBeNull()
        ->and($findings[0]->location?->file)->toBe('config/sanctum.php');
});

it('asks to publish the Sanctum config when the app does not have it', function () {
    issueTokens($this->root);

    $findings = sanctumFindings($this->root);

    expect($findings[0]->location)->toBeNull()
        ->and($findings[0]->remediation)->toContain('vendor:publish --tag=sanctum-config');
});

it('accepts tokens with an expiration', function () {
    config(['sanctum.expiration' => 60 * 24]);

    expect(sanctumFindings($this->root))->toBe([]);
});

it('does nothing without Sanctum', function () {
    expect(sanctumFindings($this->root, []))->toBe([]);
});

it('skips when the user model does not issue API tokens', function () {
    config(['auth.providers.users.model' => User::class]);

    expect(fn () => sanctumFindings($this->root))->toThrow(CheckSkipped::class, 'does not issue API tokens');
});

it('skips when the user model cannot be resolved', function () {
    config(['auth.providers.users.model' => 'App\Models\Missing']);

    expect(fn () => sanctumFindings($this->root))->toThrow(CheckSkipped::class, 'could not be resolved');
});

// Jetstream adds HasApiTokens by default, and SPA-only apps never create tokens.
it('skips when no code creates API tokens', function () {
    expect(fn () => sanctumFindings($this->root))->toThrow(CheckSkipped::class, 'no code in app/ creates API tokens');
});

it('reports tokens issued through Jetstream API features', function () {
    config(['jetstream.features' => ['api', 'account-deletion']]);

    expect(sanctumFindings($this->root))->toHaveCount(1);
});

it('skips when tokens may get their own expiry date', function (string $call) {
    issueTokens($this->root, $call);

    expect(fn () => sanctumFindings($this->root))->toThrow(CheckSkipped::class, 'own expiry date');
})->with([
    "\$user->createToken('api', ['*'], now()->addWeek())",
    "\$user->createToken(\n    'api',\n    expiresAt: now()->addDay(),\n)",
]);

it('still reports tokens created without an expiry date', function (string $call) {
    issueTokens($this->root, $call);

    expect(sanctumFindings($this->root))->toHaveCount(1);
})->with([
    'abilities' => ["\$user->createToken('api', ['read'])"],
    'several abilities' => ["\$user->createToken('api', ['read', 'write'])"],
    'trailing comma' => ["\$user->createToken(\n    'api',\n    ['read'],\n)"],
    'call inside an array' => ["['token' => \$user->createToken('x')->plainTextToken, 'user' => \$user]"],
    'comma in a string' => ["\$user->createToken('api, cli', ['read'])"],
]);

it('reports tokens that never expire outside production too', function () {
    issueTokens($this->root);
    mkdir($this->root.'/config');
    file_put_contents($this->root.'/config/sanctum.php', "<?php\n\nreturn [\n    'expiration' => null,\n];\n");

    expect(sanctumFindings($this->root, production: false))->toHaveCount(1);
});

it('skips outside production when the expiration comes from env()', function () {
    issueTokens($this->root);
    mkdir($this->root.'/config');
    file_put_contents($this->root.'/config/sanctum.php', "<?php\n\nreturn [\n    'expiration' => env('SANCTUM_EXPIRATION'),\n];\n");

    expect(fn () => sanctumFindings($this->root, production: false))
        ->toThrow(CheckSkipped::class, 'sanctum.expiration comes from env()')
        ->and(sanctumFindings($this->root))->toHaveCount(1);
});
