<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Dependencies\AuditFindings;

function auditReport(): string
{
    return <<<'JSON'
    {
        "advisories": {
            "dompdf/dompdf": [
                {
                    "advisoryId": "PKSA-1",
                    "packageName": "dompdf/dompdf",
                    "affectedVersions": "<2.0.3",
                    "title": "Remote code execution via SVG images",
                    "cve": "CVE-2023-24813",
                    "link": "https://github.com/advisories/GHSA-3cw5-7cxw-v5qg",
                    "reportedAt": "2023-02-07T00:00:00+00:00",
                    "sources": [],
                    "severity": "critical"
                },
                {
                    "advisoryId": "PKSA-2",
                    "packageName": "dompdf/dompdf",
                    "affectedVersions": "<1.2.1",
                    "title": "Arbitrary file read",
                    "cve": null,
                    "link": "https://example.com/advisory",
                    "reportedAt": "2022-05-01T00:00:00+00:00",
                    "sources": [],
                    "severity": null
                }
            ]
        },
        "abandoned": {
            "fzaninotto/faker": "fakerphp/faker",
            "acme/legacy": null
        }
    }
    JSON;
}

/**
 * @return array<string, Finding>
 */
function findingsByTitle(string $json): array
{
    $findings = (new AuditFindings)->fromOutput($json);

    return array_combine(array_map(fn (Finding $finding) => $finding->title, $findings), $findings);
}

it('maps a rated advisory', function () {
    $finding = findingsByTitle(auditReport())['dompdf/dompdf: Remote code execution via SVG images'];

    expect($finding->ruleId)->toBe('dependencies.vulnerable-package')
        ->and($finding->severity)->toBe(Severity::Critical)
        ->and($finding->description)->toContain('<2.0.3')->not->toContain('Identifier')
        ->and($finding->cve)->toBe(['CVE-2023-24813'])
        ->and($finding->cwe)->toBe([1395])
        ->and($finding->cvss)->toBeNull()
        ->and($finding->remediation)->toContain('composer update dompdf/dompdf', 'composer why dompdf/dompdf')
        ->and($finding->references)->toBe([
            'https://github.com/advisories/GHSA-3cw5-7cxw-v5qg',
            'https://www.cve.org/CVERecord?id=CVE-2023-24813',
        ])
        ->and($finding->location?->file)->toBe('composer.lock');
});

it('marks an advisory without a severity as unknown', function () {
    $finding = findingsByTitle(auditReport())['dompdf/dompdf: Arbitrary file read'];

    expect($finding->severity)->toBe(Severity::Unknown)
        ->and($finding->description)->toContain('did not publish a severity')
        ->and($finding->references)->toBe(['https://example.com/advisory'])
        ->and($finding->cve)->toBe([])
        ->and($finding->cwe)->toBe([1395]);
});

it('reports abandoned packages as informational', function () {
    $findings = findingsByTitle(auditReport());

    expect($findings['fzaninotto/faker is abandoned']->ruleId)->toBe('dependencies.abandoned-package')
        ->and($findings['fzaninotto/faker is abandoned']->severity)->toBe(Severity::Info)
        ->and($findings['fzaninotto/faker is abandoned']->cwe)->toBe([1104])
        ->and($findings['fzaninotto/faker is abandoned']->remediation)->toContain('fakerphp/faker')
        ->and($findings['acme/legacy is abandoned']->remediation)->toContain('maintained alternative');
});

it('maps every severity spelling Composer may print', function (string $value, Severity $expected) {
    $json = json_encode(['advisories' => ['a/b' => [['title' => 'T', 'severity' => $value]]], 'abandoned' => []], JSON_THROW_ON_ERROR);

    expect((new AuditFindings)->fromOutput($json)[0]->severity)->toBe($expected);
})->with([
    ['critical', Severity::Critical],
    ['HIGH', Severity::High],
    ['medium', Severity::Medium],
    ['moderate', Severity::Medium],
    ['low', Severity::Low],
    ['none', Severity::Unknown],
]);

it('accepts advisories listed as a JSON object', function () {
    $json = '{"advisories": {"a/b": {"3": {"title": "T", "severity": "high"}}}, "abandoned": {}}';

    expect((new AuditFindings)->fromOutput($json))->toHaveCount(1);
});

it('returns nothing for a clean report', function () {
    expect((new AuditFindings)->fromOutput('{"advisories": [], "abandoned": []}'))->toBe([]);
});

it('fails when Composer did not print a report', function (string $output) {
    expect(fn () => (new AuditFindings)->fromOutput($output, 'The "https://packagist.org/api/security-advisories/" file could not be downloaded'))
        ->toThrow(RuntimeException::class, 'could not be downloaded');
})->with(['', 'not json', '{"abandoned": []}']);

// Composer before 2.7 does not report abandoned packages.
it('accepts a report without abandoned packages', function () {
    expect((new AuditFindings)->fromOutput('{"advisories": {"a/b": [{"title": "T", "severity": "low"}]}}'))->toHaveCount(1);
});

// An older Composer on a newer PHP may print deprecations to stdout before the report.
it('reads the report after PHP notices', function () {
    $output = "PHP Deprecated:  Implicitly nullable parameter in phar:///usr/bin/composer/src/Foo.php on line 3\n".auditReport();

    expect((new AuditFindings)->fromOutput($output))->toHaveCount(4);
});

it('drops stray spaces and a repeated package name from advisory titles', function (string $title, string $expected) {
    $json = json_encode(['advisories' => ['dompdf/dompdf' => [['title' => $title, 'severity' => 'low']]]], JSON_THROW_ON_ERROR);

    expect((new AuditFindings)->fromOutput($json)[0]->title)->toBe($expected);
})->with([
    ['Dompdf: Chroot Validation Bypass ', 'dompdf/dompdf: Chroot Validation Bypass'],
    ['dompdf/dompdf: Remote file inclusion', 'dompdf/dompdf: Remote file inclusion'],
    ['Dompdf vulnerable to URI validation failure', 'dompdf/dompdf: Dompdf vulnerable to URI validation failure'],
]);

it('keeps an identifier that is not a CVE ID in the description', function () {
    $json = json_encode(['advisories' => ['a/b' => [[
        'title' => 'T',
        'severity' => 'high',
        'cve' => 'GHSA-3cw5-7cxw-v5qg',
    ]]], 'abandoned' => []], JSON_THROW_ON_ERROR);

    $finding = (new AuditFindings)->fromOutput($json)[0];

    expect($finding->cve)->toBe([])
        ->and($finding->description)->toContain('Identifier: GHSA-3cw5-7cxw-v5qg.')
        ->and($finding->references)->toBe([]);
});
