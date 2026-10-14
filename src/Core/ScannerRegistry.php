<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use Illuminate\Contracts\Container\Container;
use Jklejczyk\SecurityToolkit\Core\Contracts\Scanner;
use LogicException;

final class ScannerRegistry
{
    /**
     * @var list<class-string<Scanner>>
     */
    private array $scanners = [];

    public function __construct(
        private readonly Container $container,
    ) {}

    /**
     * @param  class-string<Scanner>  $scanner
     */
    public function register(string $scanner): void
    {
        if (! in_array($scanner, $this->scanners, true)) {
            $this->scanners[] = $scanner;
        }
    }

    /**
     * @return list<Scanner>
     */
    public function all(): array
    {
        $scanners = [];

        foreach ($this->scanners as $scanner) {
            $instance = $this->container->make($scanner);

            if (! $instance instanceof Scanner) {
                throw new LogicException(sprintf('%s must implement %s.', $scanner, Scanner::class));
            }

            $scanners[] = $instance;
        }

        return $scanners;
    }

    /**
     * @param  list<string>  $ids
     * @return list<Scanner>
     *
     * @throws UnknownScanner
     */
    public function only(array $ids): array
    {
        $scanners = $this->all();
        $known = array_map(fn (Scanner $scanner): string => $scanner->id(), $scanners);
        $unknown = array_values(array_diff($ids, $known));

        if ($unknown !== []) {
            throw UnknownScanner::ids($unknown);
        }

        return array_values(array_filter(
            $scanners,
            fn (Scanner $scanner): bool => in_array($scanner->id(), $ids, true),
        ));
    }
}
