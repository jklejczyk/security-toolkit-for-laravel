<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Auth;

use Closure;
use FilesystemIterator;
use Jklejczyk\SecurityToolkit\Core\Checks\CheckSkipped;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use UnexpectedValueException;

/**
 * Plain-text search of the application code: evidence that a feature is used, not proof of how.
 * Code that cannot be read or searched makes the answer a guess, so it skips the check.
 */
final class AppSource
{
    /**
     * @throws CheckSkipped
     */
    public function contains(string $pattern): bool
    {
        return $this->any(function (string $code, string $file) use ($pattern): bool {
            $result = preg_match($pattern, $code);

            if ($result === false) {
                throw CheckSkipped::because(sprintf('could not search %s: %s', $file, preg_last_error_msg()));
            }

            return $result === 1;
        });
    }

    /**
     * Every match of the pattern, with the code of its file and its byte offset in it.
     *
     * @return list<array{file: string, code: string, offset: int}>
     *
     * @throws CheckSkipped
     */
    public function matches(string $pattern): array
    {
        $found = [];

        $this->any(function (string $code, string $file) use ($pattern, &$found): bool {
            if (preg_match_all($pattern, $code, $matches, PREG_OFFSET_CAPTURE) === false) {
                throw CheckSkipped::because(sprintf('could not search %s: %s', $file, preg_last_error_msg()));
            }

            foreach ($matches[0] as [, $offset]) {
                $found[] = ['file' => $file, 'code' => $code, 'offset' => $offset];
            }

            return false;
        });

        return $found;
    }

    /**
     * @param  Closure(string, string): bool  $matches  receives the code and the file path relative to the application
     *
     * @throws CheckSkipped
     */
    public function any(Closure $matches): bool
    {
        $directory = app_path();

        if (! is_dir($directory)) {
            return false;
        }

        try {
            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS));

            foreach ($files as $file) {
                if (! $file instanceof SplFileInfo || ! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                $path = Location::inApplication($file->getPathname(), base_path())->file;
                $code = $file->isReadable() ? file_get_contents($file->getPathname()) : false;

                if ($code === false) {
                    throw CheckSkipped::because(sprintf('could not read %s', $path));
                }

                if ($matches($code, $path)) {
                    return true;
                }
            }
        } catch (UnexpectedValueException $exception) {
            throw CheckSkipped::because(sprintf('could not read the application code: %s', $exception->getMessage()));
        }

        return false;
    }
}
