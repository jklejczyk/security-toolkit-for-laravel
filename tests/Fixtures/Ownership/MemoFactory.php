<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Memo>
 */
final class MemoFactory extends Factory
{
    protected $model = Memo::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'body' => fake()->unique()->numerify('MEMO-#####'),
        ];
    }
}
