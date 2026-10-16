<?php

declare(strict_types=1);

/**
 * Every built-in check must name the kind of weakness it reports.
 * The DVLA scan confirms the same at runtime; this catches a new check that forgets it.
 */
it('classifies every built-in check with a CWE', function (string $file) {
    expect((string) file_get_contents($file))->toContain('cwe: [');
})->with(function (): array {
    $files = glob(dirname(__DIR__, 2).'/src/Scanners/*/Checks/*.php') ?: [];

    return array_combine(array_map('basename', $files), array_map(fn (string $file): array => [$file], $files));
});
