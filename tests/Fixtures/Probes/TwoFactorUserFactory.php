<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<TwoFactorUser>
 */
final class TwoFactorUserFactory extends Factory
{
    protected $model = TwoFactorUser::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'password' => 'secret',
        ];
    }
}
