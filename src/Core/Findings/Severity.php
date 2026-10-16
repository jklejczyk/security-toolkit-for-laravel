<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    /**
     * The source did not rate the issue, e.g. an advisory published without a severity.
     */
    case Unknown = 'unknown';

    /**
     * Sort order; an unrated finding sorts after every rated one.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Critical => 4,
            self::High => 3,
            self::Medium => 2,
            self::Low => 1,
            self::Info => 0,
            self::Unknown => -1,
        };
    }

    /**
     * An unrated finding could be critical, so it meets every threshold.
     */
    public function isAtLeast(self $other): bool
    {
        return $this === self::Unknown || $this->rank() >= $other->rank();
    }

    /**
     * Severities usable as a threshold (--fail-on, --min-severity).
     *
     * @return list<self>
     */
    public static function thresholds(): array
    {
        return [self::Critical, self::High, self::Medium, self::Low, self::Info];
    }
}
