<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes;

use Illuminate\Foundation\Http\FormRequest;

/**
 * A form request whose rules a test sets, so one fixture covers every rule shape.
 */
final class RulesRequest extends FormRequest
{
    /** @var array<string, mixed> */
    public static array $rules = [];

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return self::$rules;
    }

    public function authorize(): bool
    {
        return true;
    }
}
