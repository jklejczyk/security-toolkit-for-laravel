<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Tests\Fixtures\Probes;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * A token check the probes do not know, e.g. a package middleware: it always answers 419.
 */
final class TokenWall
{
    public function handle(Request $request, Closure $next): Response
    {
        return new Response('', 419);
    }
}
