<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Payload;

use Illuminate\Contracts\Auth\Authenticatable;
use Jklejczyk\SecurityToolkit\Scanners\Probes\HttpClient;

/**
 * Where the payload builder may ask the application which fields it validates: a request to a record
 * of actor A, never to the record under attack.
 */
final readonly class ValidationRequest
{
    public function __construct(
        public HttpClient $client,
        public string $method,
        public string $uri,
        public Authenticatable $actor,
    ) {}
}
