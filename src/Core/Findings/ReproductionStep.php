<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

/**
 * One request of a reproduction: who sent it, to what, and what came back. Holds model names, IDs
 * and field names only, never column values.
 */
final readonly class ReproductionStep
{
    /**
     * @param  string  $actor  the name of an actor of the reproduction, e.g. "A" or "guest"
     * @param  string  $request  method and URI, e.g. "DELETE /api/invoices/41"
     * @param  ?string  $resource  the targeted record, e.g. "App\Models\Invoice#41 (owner B)"
     * @param  list<string>  $fields  names of the fields sent
     */
    public function __construct(
        public string $actor,
        public string $request,
        public ?string $resource,
        public array $fields,
        public string $expected,
        public string $received,
    ) {}
}
