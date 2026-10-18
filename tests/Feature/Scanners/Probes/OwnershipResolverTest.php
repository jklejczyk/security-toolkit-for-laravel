<?php

declare(strict_types=1);

use Jklejczyk\SecurityToolkit\Core\Map\ApplicationMap;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnerKind;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Ownership\OwnershipResolver;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Author;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Map\Post;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Attachment;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Company;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Invoice;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\InvoiceItem;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Note;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Profile;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\Shared;
use Jklejczyk\SecurityToolkit\Tests\Fixtures\Ownership\User;

/**
 * @param  array<string, string>  $configured
 */
function resolver(array $configured = [], string $userModel = User::class): OwnershipResolver
{
    return new OwnershipResolver(new ApplicationMap, $configured, $userModel);
}

it('makes the user the owner of themselves', function () {
    $resolution = resolver()->for(User::class);

    expect($resolution->owner?->kind)->toBe(OwnerKind::User)
        ->and($resolution->owner?->relations)->toBe([]);
});

it('prefers the group both the model and the user belong to', function () {
    $resolution = resolver()->for(Invoice::class);

    expect($resolution->owner?->kind)->toBe(OwnerKind::Group)
        ->and($resolution->owner?->model)->toBe(Company::class)
        ->and($resolution->owner?->relations)->toBe(['company'])
        ->and($resolution->owner?->foreignKeys)->toBe(['company_id']);
});

it('reaches a group through one parent', function () {
    $resolution = resolver()->for(InvoiceItem::class);

    expect($resolution->owner?->kind)->toBe(OwnerKind::Group)
        ->and($resolution->owner?->relations)->toBe(['invoice', 'company'])
        ->and($resolution->owner?->foreignKeys)->toBe(['invoice_id', 'company_id']);
});

it('falls back to a direct relation to the user', function () {
    $resolution = resolver()->for(Profile::class);

    expect($resolution->owner?->kind)->toBe(OwnerKind::User)
        ->and($resolution->owner?->relations)->toBe(['user'])
        ->and($resolution->owner?->foreignKeys)->toBe(['user_id']);
});

it('picks the named user relation among several', function () {
    $resolution = resolver(userModel: Author::class)->for(Post::class);

    expect($resolution->owner?->kind)->toBe(OwnerKind::User)
        ->and($resolution->owner?->relations)->toBe(['author'])
        ->and($resolution->owner?->foreignKeys)->toBe(['author_id']);
});

it('skips a model with no relation to the user', function () {
    $resolution = resolver()->for(Note::class);

    expect($resolution->isFound())->toBeFalse()
        ->and($resolution->reason)->toContain('no owner')
        ->and($resolution->hint)->toBe('set probes.owners');
});

it('skips a chain longer than two relations', function () {
    expect(resolver()->for(Attachment::class)->isFound())->toBeFalse();
});

it('skips when several user relations are equally likely', function () {
    $resolution = resolver()->for(Shared::class);

    expect($resolution->isFound())->toBeFalse()
        ->and($resolution->reason)->toContain('several relations')
        ->and($resolution->hint)->toBe('set probes.owners');
});

it('uses a configured relation path before anything else', function () {
    $resolution = resolver([Attachment::class => 'item.invoice.company'])->for(Attachment::class);

    expect($resolution->owner?->kind)->toBe(OwnerKind::Group)
        ->and($resolution->owner?->relations)->toBe(['item', 'invoice', 'company']);
});

it('skips a configured path that does not exist', function () {
    $resolution = resolver([Invoice::class => 'customer'])->for(Invoice::class);

    expect($resolution->isFound())->toBeFalse()
        ->and($resolution->reason)->toContain('"customer"')
        ->and($resolution->hint)->toBe('fix probes.owners');
});
