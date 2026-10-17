<?php

declare(strict_types=1);

namespace Opcodes\LogViewer\Facades;

/**
 * Stand-in for the opcodesio/log-viewer facade, which is not a dev dependency.
 */
final class LogViewer
{
    public static bool $hasAuthCallback = false;

    public static function hasAuthCallback(): bool
    {
        return self::$hasAuthCallback;
    }
}
