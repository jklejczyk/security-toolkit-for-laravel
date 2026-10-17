<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Confidence;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;

it('has no classification by default', function () {
    $finding = new Finding('a.rule', Severity::Low, 'T', 'D', 'R');

    expect($finding->cwe)->toBe([])
        ->and($finding->cvss)->toBeNull()
        ->and($finding->cve)->toBe([]);
});

it('keeps its classification', function () {
    $cvss = Cvss::fromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');

    $finding = new Finding('a.rule', Severity::High, 'T', 'D', 'R', cwe: [209], cvss: $cvss, cve: ['CVE-2021-3129']);

    expect($finding->cwe)->toBe([209])
        ->and($finding->cvss)->toBe($cvss)
        ->and($finding->cve)->toBe(['CVE-2021-3129']);
});

it('rejects a severity that disagrees with the CVSS score', function () {
    $cvss = Cvss::fromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');

    expect(fn () => new Finding('config.debug-enabled', Severity::Critical, 'T', 'D', 'R', cvss: $cvss))
        ->toThrow(InvalidArgumentException::class, 'Finding config.debug-enabled is rated critical, but its CVSS score 7.5 means high.');
});

it('rejects a CWE that is not a positive number', function (int $cwe) {
    expect(fn () => new Finding('a.rule', Severity::Low, 'T', 'D', 'R', cwe: [$cwe]))
        ->toThrow(InvalidArgumentException::class, 'invalid CWE');
})->with([0, -79]);

it('rejects a malformed CVE ID', function (string $cve) {
    expect(fn () => new Finding('a.rule', Severity::Low, 'T', 'D', 'R', cve: [$cve]))
        ->toThrow(InvalidArgumentException::class, 'invalid CVE ID');
})->with(['GHSA-3cw5-7cxw-v5qg', 'CVE-2023-123', 'cve-2023-24813', 'CVE-2023-24813 ', "CVE-2023-24813\n"]);

it('is certain unless stated otherwise', function () {
    expect((new Finding('a.rule', Severity::Low, 'T', 'D', 'R'))->confidence)->toBe(Confidence::Certain)
        ->and((new Finding('a.rule', Severity::Low, 'T', 'D', 'R', confidence: Confidence::Suspected))->confidence)->toBe(Confidence::Suspected);
});
