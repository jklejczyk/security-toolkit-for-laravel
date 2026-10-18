<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

use InvalidArgumentException;

/**
 * The validated `security-toolkit.probes` configuration. Values are read once and used by both the
 * scan process (blocks) and the probe process (data, owners, payloads).
 */
final readonly class ProbesConfig
{
    public const DATA_MODES = ['auto', 'existing', 'factories'];

    /**
     * @param  array<string, string>  $owners
     * @param  list<string>  $rateLimitRoutes
     * @param  array<array-key, mixed>  $payloads
     */
    private function __construct(
        public ?string $connection,
        public string $data,
        public bool $migrate,
        public bool $allowAppDatabase,
        public int $timeout,
        public array $owners,
        public int $candidates,
        public int $rateLimitAttempts,
        public array $rateLimitRoutes,
        public array $payloads,
        public int $massAssignmentFields,
    ) {}

    /**
     * @throws InvalidArgumentException when probes.data is not one of the known modes
     */
    public static function fromConfig(): self
    {
        $probes = self::array(config('security-toolkit.probes'));

        $data = self::string($probes['data'] ?? 'auto', 'auto');

        if (! in_array($data, self::DATA_MODES, true)) {
            throw new InvalidArgumentException(sprintf(
                'probes.data must be one of %s, "%s" given.',
                implode(', ', self::DATA_MODES),
                $data,
            ));
        }

        $rateLimit = self::array($probes['rate_limit'] ?? []);
        $massAssignment = self::array($probes['mass_assignment'] ?? []);

        return new self(
            self::nullableString($probes['connection'] ?? null),
            $data,
            self::bool($probes['migrate'] ?? false),
            self::bool($probes['allow_app_database'] ?? false),
            max(1, self::int($probes['timeout'] ?? 300, 300)),
            self::stringMap($probes['owners'] ?? []),
            max(1, self::int($probes['candidates'] ?? 5, 5)),
            max(1, self::int($rateLimit['attempts'] ?? 10, 10)),
            self::stringList($rateLimit['routes'] ?? []),
            self::array($probes['payloads'] ?? []),
            max(1, self::int($massAssignment['fields'] ?? 5, 5)),
        );
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function array(mixed $value): array
    {
        return is_array($value) ? $value : [];
    }

    private static function nullableString(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? $value : null;
    }

    private static function string(mixed $value, string $default): string
    {
        return is_string($value) ? $value : $default;
    }

    private static function bool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        if (is_string($value)) {
            return filter_var($value, FILTER_VALIDATE_BOOL);
        }

        return false;
    }

    private static function int(mixed $value, int $default): int
    {
        if (is_int($value)) {
            return $value;
        }

        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * @return array<string, string>
     */
    private static function stringMap(mixed $value): array
    {
        $map = [];

        foreach (self::array($value) as $key => $item) {
            if (is_string($key) && is_string($item)) {
                $map[$key] = $item;
            }
        }

        return $map;
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        return array_values(array_filter(self::array($value), is_string(...)));
    }
}
