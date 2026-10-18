<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Validates the invoice number, so the IDOR probe can build a write body for it.
 */
final class InvoiceRequest extends FormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'number' => ['required', 'string'],
        ];
    }

    public function authorize(): bool
    {
        return true;
    }
}
