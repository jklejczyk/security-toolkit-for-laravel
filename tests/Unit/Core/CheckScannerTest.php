<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckScanner;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;

function finding(string $ruleId): Finding
{
    return new Finding($ruleId, Severity::High, 'Title', 'Description', 'Remediation');
}

/**
 * @param  iterable<Finding>|Closure(): iterable<Finding>  $result
 */
function check(string $id, bool $onlyInProduction, iterable|Closure $result = []): Check
{
    return new class($id, $onlyInProduction, $result) implements Check
    {
        public function __construct(
            private string $id,
            private bool $onlyInProduction,
            private mixed $result,
        ) {}

        public function id(): string
        {
            return $this->id;
        }

        public function onlyInProduction(): bool
        {
            return $this->onlyInProduction;
        }

        public function run(ScanContext $context): iterable
        {
            return $this->result instanceof Closure ? ($this->result)() : $this->result;
        }
    };
}

/**
 * @param  list<Check>  $checks
 */
function scannerWith(array $checks): CheckScanner
{
    return new class($checks) extends CheckScanner
    {
        /**
         * @param  list<Check>  $checks
         */
        public function __construct(private array $checks) {}

        public function id(): string
        {
            return 'test';
        }

        protected function checks(): array
        {
            return $this->checks;
        }
    };
}

it('collects findings from every check', function () {
    $result = scannerWith([
        check('test.a', false, [finding('test.a')]),
        check('test.b', false, [finding('test.b'), finding('test.b')]),
    ])->scan(localContext());

    expect($result->findings)->toHaveCount(3)
        ->and($result->skipped)->toBe([]);
});

it('skips production-only checks outside production without running them', function () {
    $result = scannerWith([
        check('test.prod', true, fn () => throw new RuntimeException('must not run')),
    ])->scan(localContext());

    expect($result->findings)->toBe([])
        ->and($result->skipped)->toHaveCount(1)
        ->and($result->skipped[0]->checkId)->toBe('test.prod')
        ->and($result->skipped[0]->reason)->toBe('only relevant in production (current environment: local)');
});

it('runs production-only checks in production', function () {
    $result = scannerWith([check('test.prod', true, [finding('test.prod')])])->scan(productionContext());

    expect($result->findings)->toHaveCount(1)
        ->and($result->skipped)->toBe([]);
});

it('records a skip when a check cannot be evaluated', function () {
    $result = scannerWith([
        check('test.unknown', false, fn () => throw CheckSkipped::because('gate threw an exception')),
    ])->scan(localContext());

    expect($result->skipped)->toHaveCount(1)
        ->and($result->skipped[0]->reason)->toBe('gate threw an exception');
});

it('keeps findings yielded before a check skips itself', function () {
    $generator = function () {
        yield finding('test.partial');
        throw CheckSkipped::because('second part could not be evaluated');
    };

    $result = scannerWith([check('test.partial', false, $generator)])->scan(localContext());

    expect($result->findings)->toHaveCount(1)
        ->and($result->skipped)->toHaveCount(1);
});

it('lets other exceptions bubble up', function () {
    scannerWith([
        check('test.broken', false, fn () => throw new RuntimeException('boom')),
    ])->scan(localContext());
})->throws(RuntimeException::class, 'boom');

it('is always available', function () {
    expect(scannerWith([])->availability()->available)->toBeTrue();
});
