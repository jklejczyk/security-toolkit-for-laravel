<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Protocol;

use InvalidArgumentException;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageEntry;
use Jklejczyk\SecurityToolkit\Core\Coverage\CoverageTarget;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Notice;

/**
 * The JSON the probe process prints for the parent scan: confirmed findings, coverage and notices.
 */
final readonly class ProbeReport
{
    /**
     * @param  list<Finding>  $findings
     * @param  list<CoverageEntry>  $coverage
     * @param  list<Notice>  $notices
     */
    public function __construct(
        public array $findings = [],
        public array $coverage = [],
        public array $notices = [],
    ) {}

    public function toJson(): string
    {
        $data = [
            'findings' => array_map(FindingCodec::encode(...), $this->findings),
            'coverage' => array_map($this->encodeCoverage(...), $this->coverage),
            'notices' => array_map(fn (Notice $notice): array => [
                'scanner' => $notice->scannerId,
                'message' => $notice->message,
            ], $this->notices),
        ];

        return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);

        if (! is_array($data)) {
            throw new InvalidArgumentException('The probe process did not print a JSON object.');
        }

        return self::fromArray($data);
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $findings = [];

        foreach (self::list($data['findings'] ?? []) as $finding) {
            $findings[] = FindingCodec::decode($finding);
        }

        $coverage = [];

        foreach (self::list($data['coverage'] ?? []) as $entry) {
            $coverage[] = self::decodeCoverage(self::map($entry));
        }

        $notices = [];

        foreach (self::list($data['notices'] ?? []) as $notice) {
            $notice = self::map($notice);
            $notices[] = new Notice(
                self::string($notice, 'scanner'),
                self::string($notice, 'message'),
            );
        }

        return new self($findings, $coverage, $notices);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function encodeCoverage(CoverageEntry $entry): array
    {
        return [
            'probe' => $entry->probe,
            'checked' => $entry->checked,
            'confirmed' => $entry->confirmed,
            'not_confirmed' => array_map($this->encodeTarget(...), $entry->notConfirmed),
            'skipped' => array_map($this->encodeTarget(...), $entry->skipped),
        ];
    }

    /**
     * @return array{target: string, reason: string, hint: ?string}
     */
    private function encodeTarget(CoverageTarget $target): array
    {
        return ['target' => $target->target, 'reason' => $target->reason, 'hint' => $target->hint];
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    private static function decodeCoverage(array $data): CoverageEntry
    {
        return new CoverageEntry(
            self::string($data, 'probe'),
            self::int($data['checked'] ?? 0),
            self::int($data['confirmed'] ?? 0),
            array_map(self::decodeTarget(...), self::list($data['not_confirmed'] ?? [])),
            array_map(self::decodeTarget(...), self::list($data['skipped'] ?? [])),
        );
    }

    private static function decodeTarget(mixed $data): CoverageTarget
    {
        $data = self::map($data);
        $hint = $data['hint'] ?? null;

        return new CoverageTarget(
            self::string($data, 'target'),
            self::string($data, 'reason'),
            is_string($hint) ? $hint : null,
        );
    }

    /**
     * @return array<array-key, mixed>
     */
    private static function map(mixed $data): array
    {
        if (! is_array($data)) {
            throw new InvalidArgumentException('Expected an object in the probe report.');
        }

        return $data;
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value)) {
            throw new InvalidArgumentException(sprintf('Expected "%s" in the probe report to be a string.', $key));
        }

        return $value;
    }

    private static function int(mixed $value): int
    {
        return is_int($value) ? $value : 0;
    }

    /**
     * @return list<mixed>
     */
    private static function list(mixed $value): array
    {
        return is_array($value) ? array_values($value) : [];
    }
}
