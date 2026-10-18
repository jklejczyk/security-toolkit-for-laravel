<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Validates only the bio, so a probe injecting is_admin or a tenant column exercises mass assignment.
 */
final class ProfileRequest extends FormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'bio' => ['required', 'string'],
        ];
    }

    public function authorize(): bool
    {
        return true;
    }
}
