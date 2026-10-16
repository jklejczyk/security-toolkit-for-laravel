<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Files;

/**
 * What the web server exposes: the public directory and the links that point out of it.
 */
final class WebRoot
{
    /**
     * Links from filesystems.links and symlinks found directly in the public directory.
     * A link present in both is listed once, as configured.
     *
     * @return list<PublicLink>
     */
    public function links(): array
    {
        $links = [];

        $configured = config('filesystems.links', []);

        foreach (is_array($configured) ? $configured : [] as $link => $target) {
            if (is_string($link) && is_string($target)) {
                $path = self::normalizeLink($link);
                $links[$path] = new PublicLink($path, self::normalize($target), true);
            }
        }

        foreach ($this->symlinksInPublicDirectory() as $path => $target) {
            $links[$path] ??= new PublicLink($path, $target, false);
        }

        return array_values($links);
    }

    /**
     * Disks with the local driver, keyed by name; "public" means the author meant the disk to be
     * public ('visibility' => 'public' or a 'url'), not that the web server serves it.
     *
     * @return array<string, array{root: string, public: bool}>
     */
    public function localDisks(): array
    {
        $disks = config('filesystems.disks', []);
        $local = [];

        foreach (is_array($disks) ? $disks : [] as $name => $disk) {
            if (! is_string($name) || ! is_array($disk) || ($disk['driver'] ?? null) !== 'local' || ! is_string($disk['root'] ?? null)) {
                continue;
            }

            $local[$name] = [
                'root' => self::normalize($disk['root']),
                'public' => ($disk['visibility'] ?? null) === 'public' || is_string($disk['url'] ?? null),
            ];
        }

        return $local;
    }

    /**
     * Whether files in the directory can be downloaded over HTTP.
     */
    public function serves(string $directory): bool
    {
        $directory = self::normalize($directory);

        if (self::contains(self::normalize(public_path()), $directory)) {
            return true;
        }

        foreach ($this->links() as $link) {
            if (self::contains($link->target, $directory)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The real path of an existing directory, otherwise the path as configured.
     */
    public static function normalize(string $path): string
    {
        $real = realpath($path);

        return $real !== false ? $real : rtrim($path, '/');
    }

    /**
     * Whether the path is the directory itself or lies inside it.
     */
    public static function contains(string $directory, string $path): bool
    {
        return $path === $directory || str_starts_with($path, rtrim($directory, '/').'/');
    }

    /**
     * Resolving the link itself would return its target, so only its parent is resolved.
     */
    private static function normalizeLink(string $path): string
    {
        return self::normalize(dirname($path)).'/'.basename($path);
    }

    /**
     * @return array<string, string> link path => resolved target
     */
    private function symlinksInPublicDirectory(): array
    {
        $public = self::normalize(public_path());
        // An unreadable directory only hides links made by hand; configured ones are still checked.
        $entries = is_dir($public) && is_readable($public) ? scandir($public) : false;
        $links = [];

        foreach ($entries === false ? [] : $entries as $entry) {
            $path = $public.'/'.$entry;

            if ($entry === '.' || $entry === '..' || ! is_link($path)) {
                continue;
            }

            // A dangling link exposes nothing.
            $target = realpath($path);

            if ($target !== false) {
                $links[$path] = $target;
            }
        }

        return $links;
    }
}
