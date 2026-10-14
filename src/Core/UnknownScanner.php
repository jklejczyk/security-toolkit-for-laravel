<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core;

use InvalidArgumentException;

final class UnknownScanner extends InvalidArgumentException
{
    /**
     * @param  list<string>  $ids
     */
    public static function ids(array $ids): self
    {
        return new self('Unknown scanner(s): '.implode(', ', $ids));
    }
}
