<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Checks;

use RuntimeException;

final class CheckSkipped extends RuntimeException
{
    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
