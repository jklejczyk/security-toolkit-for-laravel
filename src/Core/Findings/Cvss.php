<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

use InvalidArgumentException;

/**
 * A CVSS 3.1 base vector and the base score it yields.
 *
 * @see https://www.first.org/cvss/v3.1/specification-document
 */
final readonly class Cvss
{
    public const VERSION = '3.1';

    private const PREFIX = 'CVSS:'.self::VERSION.'/';

    /**
     * Base metrics in specification order, with the weight of each value.
     * Privileges Required has other weights when the scope changes, see baseScore().
     */
    private const METRICS = [
        'AV' => ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2],
        'AC' => ['L' => 0.77, 'H' => 0.44],
        'PR' => ['N' => 0.85, 'L' => 0.62, 'H' => 0.27],
        'UI' => ['N' => 0.85, 'R' => 0.62],
        'S' => ['U' => 0.0, 'C' => 0.0],
        'C' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
        'I' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
        'A' => ['H' => 0.56, 'L' => 0.22, 'N' => 0.0],
    ];

    private function __construct(
        public string $vector,
        public float $score,
    ) {}

    /**
     * @throws InvalidArgumentException when the vector is not a scorable CVSS 3.1 base vector
     */
    public static function fromVector(string $vector): self
    {
        if (! str_starts_with($vector, self::PREFIX)) {
            throw new InvalidArgumentException(sprintf('Unsupported CVSS vector "%s": only CVSS:3.1 base vectors are supported.', $vector));
        }

        $parts = explode('/', substr($vector, strlen(self::PREFIX)));

        if (count($parts) !== count(self::METRICS)) {
            throw new InvalidArgumentException(sprintf('CVSS vector "%s" must contain exactly the base metrics AV, AC, PR, UI, S, C, I and A, in this order.', $vector));
        }

        $values = [];

        foreach (array_keys(self::METRICS) as $position => $metric) {
            [$name, $value] = array_pad(explode(':', $parts[$position], 2), 2, '');

            if ($name !== $metric) {
                throw new InvalidArgumentException(sprintf('CVSS vector "%s": expected %s at position %d, found "%s".', $vector, $metric, $position + 1, $name));
            }

            if (! array_key_exists($value, self::METRICS[$metric])) {
                throw new InvalidArgumentException(sprintf('CVSS vector "%s": invalid value "%s" for %s.', $vector, $value, $metric));
            }

            $values[$metric] = $value;
        }

        $score = self::baseScore($values);

        if ($score === 0.0) {
            throw new InvalidArgumentException(sprintf('CVSS vector "%s" has no impact, so it does not describe a finding.', $vector));
        }

        return new self($vector, $score);
    }

    public function severity(): Severity
    {
        return match (true) {
            $this->score >= 9.0 => Severity::Critical,
            $this->score >= 7.0 => Severity::High,
            $this->score >= 4.0 => Severity::Medium,
            default => Severity::Low,
        };
    }

    /**
     * The vector without the version prefix, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".
     */
    public function metrics(): string
    {
        return substr($this->vector, strlen(self::PREFIX));
    }

    /**
     * Base score formulas from section 7.1 of the specification.
     *
     * @param  array<string, string>  $values
     */
    private static function baseScore(array $values): float
    {
        $weight = fn (string $metric): float => self::METRICS[$metric][$values[$metric]];
        $scopeChanged = $values['S'] === 'C';

        $iss = 1 - (1 - $weight('C')) * (1 - $weight('I')) * (1 - $weight('A'));
        $impact = $scopeChanged
            ? 7.52 * ($iss - 0.029) - 3.25 * (($iss - 0.02) ** 15)
            : 6.42 * $iss;

        if ($impact <= 0) {
            return 0.0;
        }

        $privileges = match (true) {
            $scopeChanged && $values['PR'] === 'L' => 0.68,
            $scopeChanged && $values['PR'] === 'H' => 0.5,
            default => $weight('PR'),
        };

        $exploitability = 8.22 * $weight('AV') * $weight('AC') * $privileges * $weight('UI');

        return self::roundUp(min(($scopeChanged ? 1.08 : 1.0) * ($impact + $exploitability), 10.0));
    }

    /**
     * Roundup from appendix A: the smallest number with one decimal place that is at least the input,
     * computed on integers so that e.g. 4.0000000001 caused by floating point does not become 4.1.
     */
    private static function roundUp(float $value): float
    {
        $integer = (int) round($value * 100000);

        if ($integer % 10000 === 0) {
            return $integer / 100000;
        }

        return (floor($integer / 10000) + 1) / 10;
    }
}
