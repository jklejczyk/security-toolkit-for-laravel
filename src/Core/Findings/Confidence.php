<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Core\Findings;

/**
 * How sure the toolkit is that the finding is real.
 */
enum Confidence: string
{
    /**
     * The state was read directly, e.g. a config value or a flag after boot.
     */
    case Certain = 'certain';

    /**
     * Inferred from code; a safeguard the analysis cannot see may exist elsewhere.
     */
    case Suspected = 'suspected';

    /**
     * A probe reproduced the attack against the running application.
     */
    case Confirmed = 'confirmed';
}
