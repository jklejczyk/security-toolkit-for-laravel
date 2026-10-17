<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Models\Checks;

use Illuminate\Database\Eloquent\Model;
use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Support\AppSource;

final class UnguardedCheck implements Check
{
    private const UNGUARD_CALL = '/\b(?:Model|Eloquent)::unguard\(\s*\)/';

    public function __construct(
        private readonly AppSource $source = new AppSource,
    ) {}

    public function id(): string
    {
        return 'models.unguarded';
    }

    public function onlyInProduction(): bool
    {
        return false;
    }

    public function run(ScanContext $context): iterable
    {
        // The flag after boot, not the syntax: Model::unguarded(fn) and unguard() in seeders leave it off.
        if (! Model::isUnguarded()) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Medium,
                'Mass assignment protection is disabled for every model',
                'Model::unguard() runs while the application boots, so $fillable and $guarded are ignored on every model. Any code that passes request input to create(), fill() or update() lets the user set any column, such as is_admin, role or user_id. If the call depends on the environment, run the scan with --env=production to see the production result.',
                'Remove the global Model::unguard() call and list the assignable attributes in $fillable on each model. Use Model::unguarded(fn () => $this->call(UserSeeder::class)) for the code that really needs it, such as seeders.',
                [
                    'https://laravel.com/docs/eloquent#mass-assignment',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
                ],
                $this->location($context),
                cwe: [915],
            ),
        ];
    }

    private function location(ScanContext $context): ?Location
    {
        $match = $this->source->matches(self::UNGUARD_CALL)[0] ?? null;

        if ($match === null) {
            return null;
        }

        return Location::inApplication($match['file'], $context->basePath, substr_count(substr($match['code'], 0, $match['offset']), "\n") + 1);
    }
}
