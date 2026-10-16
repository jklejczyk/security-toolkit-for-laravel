<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Files\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Files\PublicLink;
use Jklejczyk\SecurityToolkit\Scanners\Files\WebRoot;

final class PrivateStorageLinkedCheck implements Check
{
    public function __construct(
        private readonly WebRoot $webRoot = new WebRoot,
    ) {}

    /**
     * Logs sit at a well-known path (storage/logs/laravel.log), so reading them takes no guessing.
     */
    private const LOGS_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';

    /**
     * Private files, session files (random IDs) and cache files (hashes) have to be found by name before they can be downloaded.
     */
    private const PRIVATE_FILES_VECTOR = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N';

    public function id(): string
    {
        return 'files.private-storage-linked';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        $storage = WebRoot::normalize(storage_path());
        $logs = WebRoot::normalize(storage_path('logs'));
        $internals = [WebRoot::normalize(storage_path('logs')), WebRoot::normalize(storage_path('framework'))];
        $privateDisks = $this->privateDisks();

        foreach ($this->webRoot->links() as $link) {
            $exposedDisks = array_keys(array_filter(
                $privateDisks,
                fn (string $root): bool => WebRoot::contains($link->target, $root),
            ));
            $exposesStorage = WebRoot::contains($link->target, $storage);
            // A link to the whole directory, a parent of it or a part of it exposes logs or sessions.
            $exposesInternals = array_filter(
                $internals,
                fn (string $internal): bool => WebRoot::contains($link->target, $internal) || WebRoot::contains($internal, $link->target),
            ) !== [];
            $exposesLogs = WebRoot::contains($link->target, $logs) || WebRoot::contains($logs, $link->target);

            if ($exposedDisks !== [] || $exposesStorage || $exposesInternals) {
                yield $this->finding($link, $exposedDisks, $exposesStorage, $exposesInternals, $exposesLogs, $context);
            }
        }
    }

    /**
     * Roots of the disks meant to be private, keyed by disk name. A disk inside a public disk
     * (e.g. storage/app/public/avatars without its own visibility) is public by design.
     *
     * @return array<string, string>
     */
    private function privateDisks(): array
    {
        $disks = $this->webRoot->localDisks();
        $publicRoots = array_column(array_filter($disks, fn (array $disk): bool => $disk['public']), 'root');
        $private = [];

        foreach ($disks as $name => $disk) {
            $insidePublicDisk = array_filter($publicRoots, fn (string $root): bool => WebRoot::contains($root, $disk['root'])) !== [];

            if (! $disk['public'] && ! $insidePublicDisk) {
                $private[$name] = $disk['root'];
            }
        }

        return $private;
    }

    /**
     * @param  list<string>  $exposedDisks
     */
    private function finding(PublicLink $link, array $exposedDisks, bool $exposesStorage, bool $exposesInternals, bool $exposesLogs, ScanContext $context): Finding
    {

        $linkPath = Location::inApplication($link->path, $context->basePath)->file;
        $target = Location::inApplication($link->target, $context->basePath)->file;

        $exposed = [];

        if ($exposedDisks !== []) {
            $exposed[] = 'the private '.implode(', ', array_map(fn (string $disk): string => '"'.$disk.'"', $exposedDisks)).' disk';
        }

        if ($exposesStorage) {
            $exposed[] = 'the whole storage directory, including logs, file sessions and cache';
        } elseif ($exposesInternals) {
            $exposed[] = 'application logs or framework files such as file sessions and cache';
        }

        $cvss = Cvss::fromVector($exposesLogs ? self::LOGS_VECTOR : self::PRIVATE_FILES_VECTOR);

        return new Finding(
            $this->id(),
            $cvss->severity(),
            sprintf('Private storage is reachable over HTTP through %s', $linkPath),
            sprintf(
                'The link %s points to %s, which contains %s. Anyone who knows or guesses a file path can download it without logging in.%s',
                $linkPath,
                $target,
                implode(' and ', $exposed),
                $exposesInternals ? ' Logs and session files reveal personal data, tokens and session IDs that let an attacker log in as other users.' : '',
            ),
            'Link only the public disk directory (storage/app/public by default): fix filesystems.links, delete the link and run php artisan storage:link again. Serve private files through a controller that checks authorization, or with temporary signed URLs.',
            [
                'https://laravel.com/docs/filesystem#the-public-disk',
                'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
            ],
            $link->fromConfig ? new Location('config/filesystems.php') : Location::inApplication($link->path, $context->basePath),
            cwe: [552],
            cvss: $cvss,
        );
    }
}
