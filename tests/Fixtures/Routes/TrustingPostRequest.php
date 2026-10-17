<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Routes;

use Illuminate\Foundation\Http\FormRequest;

final class TrustingPostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }
}
