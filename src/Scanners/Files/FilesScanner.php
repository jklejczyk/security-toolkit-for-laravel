<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Files;

use Jklejczyk\SecurityToolkit\Core\Checks\CheckScanner;
use Jklejczyk\SecurityToolkit\Scanners\Files\Checks\DefaultDiskPublicCheck;
use Jklejczyk\SecurityToolkit\Scanners\Files\Checks\PrivateStorageLinkedCheck;

final class FilesScanner extends CheckScanner
{
    public function id(): string
    {
        return 'files';
    }

    protected function checks(): array
    {
        $webRoot = new WebRoot;

        return [
            new PrivateStorageLinkedCheck($webRoot),
            new DefaultDiskPublicCheck($webRoot),
        ];
    }
}
