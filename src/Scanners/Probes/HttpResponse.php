<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes;

/**
 * The status, body and cookies of one probe request. Deliberately not a TestResponse, which needs
 * PHPUnit. The cookies come back so a probe that has to carry a session from one request to the
 * next — a 2FA challenge — can send them the way a browser would.
 */
final readonly class HttpResponse
{
    /**
     * @param  array<string, string>  $cookies
     */
    public function __construct(
        public int $status,
        public string $body,
        public array $cookies = [],
    ) {}

    public function isSuccessful(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    public function isRedirect(): bool
    {
        return $this->status >= 300 && $this->status < 400;
    }

    /**
     * A definitive refusal: the probe must not treat it as a confirmation.
     */
    public function isDenied(): bool
    {
        return in_array($this->status, [401, 403, 404, 419, 422], true);
    }
}
