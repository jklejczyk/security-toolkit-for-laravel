<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership;

use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<InvoiceItem>
 */
final class InvoiceItemFactory extends Factory
{
    protected $model = InvoiceItem::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'description' => fake()->sentence(),
        ];
    }
}
