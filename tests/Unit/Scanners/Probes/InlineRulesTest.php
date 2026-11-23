<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Scanners\Probes\Payload\InlineRules;

it('reads the rules of the validate call forms', function (string $code) {
    expect(InlineRules::from($code))->toBe([
        'number' => ['required', 'string'],
        'due_date' => ['sometimes', 'date'],
    ]);
})->with([
    'request validate' => ['public function update(Request $request, Invoice $invoice) { $invoice->update($request->validate([\'number\' => \'required|string\', \'due_date\' => [\'sometimes\', \'date\']])); }'],
    'request helper' => ['{ request()->validate(["number" => "required|string", "due_date" => ["sometimes", "date"]]); }'],
    'controller validate' => ['{ $this->validate($request, [\'number\' => \'required|string\', \'due_date\' => [\'sometimes\', \'date\']]); }'],
    'validate with a bag' => ['{ $request->validateWithBag(\'update\', [\'number\' => \'required|string\', \'due_date\' => [\'sometimes\', \'date\']]); }'],
]);

it('reads an array over several lines with comments and a trailing comma', function () {
    $code = <<<'PHP'
        {
            $data = $request->validate([
                // the visible number
                'number' => ['required', 'string', 'max:20'], /* kept short */
                'notes' => 'nullable|string',
            ]);
        }
        PHP;

    expect(InlineRules::from($code))->toBe([
        'number' => ['required', 'string', 'max:20'],
        'notes' => ['nullable', 'string'],
    ]);
});

it('gives up on rules that are not plain strings', function (string $rules) {
    expect(InlineRules::from('{ $request->validate(['.$rules.']); }'))->toBeNull();
})->with([
    'a rule object' => ["'status' => ['required', Rule::in(['a', 'b'])]"],
    'a variable' => ["'status' => \$rules"],
    'a constant' => ["'status' => self::RULES"],
    'a concatenation' => ["'status' => 'max:'.\$max"],
    'an interpolated string' => ["'status' => \"max:{\$max}\""],
    'a computed key' => ["\$field => 'required'"],
]);

it('returns null without a validate call', function () {
    expect(InlineRules::from('{ $invoice->update($request->all()); }'))->toBeNull();
});

it('takes the first validate call', function () {
    $code = "{ \$request->validate(['a' => 'required']); \$request->validate(['b' => 'required']); }";

    expect(InlineRules::from($code))->toBe(['a' => ['required']]);
});

it('returns null for code that ends inside the array', function () {
    expect(InlineRules::from("{ \$request->validate(['a' => "))->toBeNull()
        ->and(InlineRules::from("{ \$request->validate(['a' => ['required', "))->toBeNull();
});
