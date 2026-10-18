<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Engine;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * The container's RateLimiter during a probe run, reporting every time the application counts an
 * attempt against a limit. Reading a limit counts too: the application deciding "are you throttled?"
 * is what the probe looks for, not only answering 429. Registering a limiter (for, limiter) does not
 * count, because applications do that while booting, before any probe sends a request.
 */
final class RecordingRateLimiter extends RateLimiter
{
    public function __construct(
        Cache $cache,
        private readonly RateLimiterRecorder $recorder,
    ) {
        parent::__construct($cache);
    }

    public function attempt($key, $maxAttempts, Closure $callback, $decaySeconds = 60)
    {
        $this->recorder->touch();

        return parent::attempt($key, $maxAttempts, $callback, $decaySeconds);
    }

    public function tooManyAttempts($key, $maxAttempts)
    {
        $this->recorder->touch();

        return parent::tooManyAttempts($key, $maxAttempts);
    }

    public function hit($key, $decaySeconds = 60)
    {
        $this->recorder->touch();

        return parent::hit($key, $decaySeconds);
    }

    public function increment($key, $decaySeconds = 60, $amount = 1)
    {
        $this->recorder->touch();

        return parent::increment($key, $decaySeconds, $amount);
    }

    public function decrement($key, $decaySeconds = 60, $amount = 1)
    {
        $this->recorder->touch();

        return parent::decrement($key, $decaySeconds, $amount);
    }

    public function attempts($key)
    {
        $this->recorder->touch();

        return parent::attempts($key);
    }

    public function resetAttempts($key)
    {
        $this->recorder->touch();

        return parent::resetAttempts($key);
    }

    public function remaining($key, $maxAttempts)
    {
        $this->recorder->touch();

        return parent::remaining($key, $maxAttempts);
    }

    public function retriesLeft($key, $maxAttempts)
    {
        $this->recorder->touch();

        return parent::retriesLeft($key, $maxAttempts);
    }

    public function clear($key)
    {
        $this->recorder->touch();

        parent::clear($key);
    }

    public function availableIn($key)
    {
        $this->recorder->touch();

        return parent::availableIn($key);
    }
}
