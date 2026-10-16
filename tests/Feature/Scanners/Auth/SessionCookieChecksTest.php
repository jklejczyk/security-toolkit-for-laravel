<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\SessionCookieInsecureCheck;
use Jklejczyk\SecurityToolkit\Scanners\Auth\Checks\SessionCookieScriptAccessibleCheck;

it('declares production-only rule ids', function () {
    expect((new SessionCookieInsecureCheck)->id())->toBe('auth.session-cookie-insecure')
        ->and((new SessionCookieInsecureCheck)->onlyInProduction())->toBeTrue()
        ->and((new SessionCookieScriptAccessibleCheck)->id())->toBe('auth.session-cookie-script-accessible')
        ->and((new SessionCookieScriptAccessibleCheck)->onlyInProduction())->toBeTrue();
});

// Laravel's default is env('SESSION_SECURE_COOKIE'), i.e. null.
it('reports a session cookie without the Secure flag', function (mixed $value) {
    config(['session.secure' => $value]);

    $findings = iterator_to_array((new SessionCookieInsecureCheck)->run(productionContext()), false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([614])
        ->and($findings[0]->cvss?->vector)->toBe('CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N')
        ->and($findings[0]->location?->file)->toBe('config/session.php');
})->with([null, false, '', '0']);

it('accepts a session cookie with the Secure flag', function (mixed $value) {
    config(['session.secure' => $value]);

    expect(iterator_to_array((new SessionCookieInsecureCheck)->run(productionContext()), false))->toBe([]);
})->with([true, '1']);

it('reports a session cookie readable by JavaScript', function (mixed $value) {
    config(['session.http_only' => $value]);

    $findings = iterator_to_array((new SessionCookieScriptAccessibleCheck)->run(productionContext()), false);

    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->cwe)->toBe([1004])
        ->and($findings[0]->cvss)->toBeNull()
        ->and($findings[0]->location?->file)->toBe('config/session.php');
})->with([false, '0', '']);

// Laravel falls back to HttpOnly when the option is missing.
it('accepts an HttpOnly session cookie', function (mixed $value) {
    config(['session.http_only' => $value]);

    expect(iterator_to_array((new SessionCookieScriptAccessibleCheck)->run(productionContext()), false))->toBe([]);
})->with([true, null, '1']);
