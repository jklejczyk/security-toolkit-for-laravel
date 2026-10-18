<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership;

/**
 * Whether the owner of a resource is the signed-in user or the group (team, company, tenant) the
 * user belongs to.
 */
enum OwnerKind: string
{
    case User = 'user';
    case Group = 'group';
}
