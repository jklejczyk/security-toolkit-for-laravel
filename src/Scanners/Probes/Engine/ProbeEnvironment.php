<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Engine;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Throwable;

/**
 * Neutralizes the side effects a probe could have outside the database: mail, notifications,
 * broadcasts, queued jobs, stray HTTP calls, disk writes and the cache store, which the probes
 * turn to array so nothing is written to the application's own cache — no rate limit, no cached
 * view, nothing left behind. Events are left alone, because they drive the application logic the
 * probes exercise — except the ones it watches: every RateLimiter call and every Lockout is
 * recorded, so the rate limit probe can see a limit that never answers 429.
 */
final class ProbeEnvironment
{
    public function install(): void
    {
        Mail::fake();
        Notification::fake();
        Queue::fake();
        Http::preventStrayRequests();
        config(['cache.default' => 'array']);

        foreach ($this->disks() as $disk) {
            try {
                Storage::fake($disk);
            } catch (Throwable) {
                // A disk without a usable fake is left as it is; the probes only need writes to stay local.
            }
        }

        $this->watchRateLimiter();
    }

    /**
     * Replaces the container's RateLimiter with one that reports to a recorder, and listens for the
     * Lockout event. Only this process, only while probes run.
     */
    private function watchRateLimiter(): void
    {
        if (app()->bound(RateLimiterRecorder::class)) {
            return;
        }

        $recorder = new RateLimiterRecorder;
        $recorder->reset();

        app()->instance(RateLimiterRecorder::class, $recorder);

        Event::listen(Lockout::class, static function () use ($recorder): void {
            $recorder->touch();
        });

        app()->instance(RateLimiter::class, new RecordingRateLimiter(Cache::store(), $recorder));
    }

    /**
     * @return list<string>
     */
    private function disks(): array
    {
        $configured = config('filesystems.disks');

        if (! is_array($configured)) {
            return [];
        }

        return array_values(array_filter(array_keys($configured), is_string(...)));
    }
}
