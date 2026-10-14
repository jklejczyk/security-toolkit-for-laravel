<?php

declare(strict_types=1);

arch('php preset')->preset()->php();

arch('security preset')->preset()->security();

arch('all source files use strict types')
    ->expect('Jklejczyk\SecurityToolkit')
    ->toUseStrictTypes();

arch('core does not depend on modules, console or reporting')
    ->expect('Jklejczyk\SecurityToolkit\Core')
    ->not->toUse([
        'Jklejczyk\SecurityToolkit\Scanners',
        'Jklejczyk\SecurityToolkit\Console',
        'Jklejczyk\SecurityToolkit\Reporting',
    ]);

arch('scanners do not depend on console or reporting')
    ->expect('Jklejczyk\SecurityToolkit\Scanners')
    ->not->toUse([
        'Jklejczyk\SecurityToolkit\Console',
        'Jklejczyk\SecurityToolkit\Reporting',
    ]);
