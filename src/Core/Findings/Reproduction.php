<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

/**
 * How a probe reproduced a finding, so a person (or a generated test) can repeat it.
 */
final readonly class Reproduction
{
    /**
     * @param  string  $data  where the records came from: "existing" or "factories"
     * @param  list<array{name: string, model: ?string, id: int|string|null, owner: ?string}>  $actors
     * @param  list<ReproductionStep>  $steps
     */
    public function __construct(
        public string $probe,
        public string $data,
        public array $actors,
        public array $steps,
    ) {}
}
