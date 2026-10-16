<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Files\Checks;

use Jklejczyk\SecurityToolkit\Core\Checks\Check;
use Jklejczyk\SecurityToolkit\Core\Findings\Cvss;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Location;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Core\ScanContext;
use Jklejczyk\SecurityToolkit\Scanners\Files\WebRoot;

final class DefaultDiskPublicCheck implements Check
{
    public function __construct(
        private readonly WebRoot $webRoot = new WebRoot,
    ) {}

    public function id(): string
    {
        return 'files.default-disk-public';
    }

    public function onlyInProduction(): bool
    {
        return true;
    }

    public function run(ScanContext $context): iterable
    {
        $default = config('filesystems.default');
        $disks = $this->webRoot->localDisks();

        if (! is_string($default) || ! isset($disks[$default]) || ! $this->webRoot->serves($disks[$default]['root'])) {
            return [];
        }

        return [
            new Finding(
                $this->id(),
                Severity::Low,
                sprintf('The default filesystem disk "%s" is publicly accessible', $default),
                sprintf('Files stored without naming a disk, for example with $request->file(\'document\')->store(\'documents\') or Storage::put(), land on the default disk. The "%s" disk is served by the web server, so anyone who knows or guesses such a file\'s path can download it, including uploads that were meant to stay private.', $default),
                'Set FILESYSTEM_DISK=local (the private disk) and name the public disk explicitly where a file must be public, for example ->store(\'avatars\', \'public\').',
                ['https://laravel.com/docs/filesystem#the-public-disk'],
                new Location('config/filesystems.php'),
                cwe: [552],
                cvss: Cvss::fromVector('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'),
            ),
        ];
    }
}
