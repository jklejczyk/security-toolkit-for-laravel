<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol;

use InvalidArgumentException;
use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Reproduction;
use Jklejczyk\SecurityToolkit\Core\Findings\ReproductionStep;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;

/**
 * Turns findings into plain arrays for the child process JSON protocol and back. Only names, ids
 * and field names travel; column values never do.
 */
final class FindingCodec
{
    /**
     * @return array<array-key, mixed>
     */
    public static function encode(Finding $finding): array
    {
        return [
            'rule' => $finding->ruleId,
            'severity' => $finding->severity->value,
            'title' => $finding->title,
            'description' => $finding->description,
            'remediation' => $finding->remediation,
            'references' => $finding->references,
            'cwe' => $finding->cwe,
            'cve' => $finding->cve,
            'confidence' => $finding->confidence->value,
            'location' => $finding->location === null ? null : [
                'file' => $finding->location->file,
                'line' => $finding->location->line,
            ],
            'reproduction' => $finding->reproduction === null ? null : [
                'probe' => $finding->reproduction->probe,
                'data' => $finding->reproduction->data,
                'actors' => $finding->reproduction->actors,
                'steps' => array_map(fn (ReproductionStep $step): array => [
                    'actor' => $step->actor,
                    'request' => $step->request,
                    'resource' => $step->resource,
                    'fields' => $step->fields,
                    'expected' => $step->expected,
                    'received' => $step->received,
                ], $finding->reproduction->steps),
            ],
        ];
    }

    public static function decode(mixed $data): Finding
    {
        $data = self::map($data, 'finding');

        $reproduction = self::nullableMap($data['reproduction'] ?? null);

        return new Finding(
            self::string($data, 'rule'),
            self::severity($data['severity'] ?? null),
            self::string($data, 'title'),
            self::string($data, 'description'),
            self::string($data, 'remediation'),
            self::stringList($data['references'] ?? []),
            self::location($data['location'] ?? null),
            self::intList($data['cwe'] ?? []),
            null,
            self::stringList($data['cve'] ?? []),
            self::confidence($data['confidence'] ?? null),
            $reproduction === null ? null : self::reproduction($reproduction),
        );
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    private static function reproduction(array $data): Reproduction
    {
        $actors = [];

        foreach (self::list($data['actors'] ?? []) as $actor) {
            $actor = self::map($actor, 'actor');
            $actors[] = [
                'name' => self::string($actor, 'name'),
                'model' => self::nullableString($actor['model'] ?? null),
                'id' => self::id($actor['id'] ?? null),
                'owner' => self::nullableString($actor['owner'] ?? null),
            ];
        }

        $steps = [];

        foreach (self::list($data['steps'] ?? []) as $step) {
            $step = self::map($step, 'step');
            $steps[] = new ReproductionStep(
                self::string($step, 'actor'),
                self::string($step, 'request'),
                self::nullableString($step['resource'] ?? null),
                self::stringList($step['fields'] ?? []),
                self::string($step, 'expected'),
                self::string($step, 'received'),
            );
        }

        return new Reproduction(
            self::string($data, 'probe'),
            self::string($data, 'data'),
            $actors,
            $steps,
        );
    }

    private static function location(mixed $data): ?Location
    {
        $location = self::nullableMap($data);

        if ($location === null) {
            return null;
        }

        $line = $location['line'] ?? null;

        return new Location(self::string($location, 'file'), is_int($line) ? $line : null);
    }

    private static function severity(mixed $value): Severity
    {
        return is_string($value) ? (Severity::tryFrom($value) ?? Severity::Unknown) : Severity::Unknown;
    }

    private static function confidence(mixed $value): Confidence
    {
        return is_string($value) ? (Confidence::tryFrom($value) ?? Confidence::Certain) : Confidence::Certain;
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function map(mixed $data, string $what): array
    {
        if (! is_array($data)) {
            throw new InvalidArgumentException(sprintf('Expected the %s to be an object.', $what));
        }

        return $data;
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private static function nullableMap(mixed $data): ?array
    {
        return is_array($data) ? $data : null;
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value)) {
            throw new InvalidArgumentException(sprintf('Expected "%s" to be a string.', $key));
        }

        return $value;
    }

    private static function nullableString(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }

    private static function id(mixed $value): int|string|null
    {
        return is_int($value) || is_string($value) ? $value : null;
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        return array_values(array_filter(self::list($value), is_string(...)));
    }

    /**
     * @return list<int>
     */
    private static function intList(mixed $value): array
    {
        return array_values(array_filter(self::list($value), is_int(...)));
    }

    /**
     * @return list<mixed>
     */
    private static function list(mixed $value): array
    {
        return is_array($value) ? array_values($value) : [];
    }
}
