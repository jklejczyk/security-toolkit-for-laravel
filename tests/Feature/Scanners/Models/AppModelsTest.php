<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Jklejczyk\SecurityToolkit\Scanners\Models\AppModels;

beforeEach(function () {
    $this->root = temporaryApp();
    $this->namespace = 'App\\AppModelsTest'.bin2hex(random_bytes(4));
    $this->loaded = [];

    // Loads classes of the temporary app on demand, like Composer does, and records every class it loads.
    $this->autoloader = function (string $class): void {
        if (! str_starts_with($class, $this->namespace.'\\')) {
            return;
        }

        $file = $this->root.'/app/'.str_replace('\\', '/', substr($class, strlen($this->namespace) + 1)).'.php';

        if (is_file($file)) {
            $this->loaded[] = $class;
            require $file;
        }
    };
    spl_autoload_register($this->autoloader);
});

afterEach(function () {
    spl_autoload_unregister($this->autoloader);
    File::deleteDirectory($this->root);
});

/**
 * Writes a class to app/<path>.php in the test namespace, without loading it.
 */
function appClass(string $root, string $namespace, string $path, string $declaration, string $uses = ''): string
{
    $directory = dirname($root.'/app/'.$path);
    $relativeNamespace = str_replace('/', '\\', dirname($path));
    $fullNamespace = $relativeNamespace === '.' ? $namespace : $namespace.'\\'.$relativeNamespace;

    @mkdir($directory, 0777, true);
    file_put_contents($root.'/app/'.$path.'.php', "<?php\n\nnamespace {$fullNamespace};\n\n{$uses}\n\n{$declaration}\n");

    return $fullNamespace.'\\'.basename($path);
}

it('does not load classes whose source shows they are not models', function () {
    $base = appClass($this->root, $this->namespace, 'Services/Validator', 'abstract class Validator {}');
    $child = appClass($this->root, $this->namespace, 'Forms/OfferValidator', 'class OfferValidator extends \\'.$this->namespace.'\\Services\\Validator {}');
    $plain = appClass($this->root, $this->namespace, 'Support/Helper', 'final class Helper {}');

    expect((new AppModels)->all())->toBe([])
        ->and($this->loaded)->not->toContain($base, $child, $plain);
});

it('does not let a broken class that is not a model stop the scan', function () {
    // Loading this child is a fatal error (incompatible signature), which no try/catch can stop.
    appClass($this->root, $this->namespace, 'Services/Validator', 'abstract class Validator { abstract public function check(): static; }');
    appClass($this->root, $this->namespace, 'Forms/OfferValidator', 'class OfferValidator extends Validator { public function check(): array { return []; } }', 'use '.$this->namespace.'\\Services\\Validator;');
    $model = appClass($this->root, $this->namespace, 'Models/Post', 'class Post extends Model {}', 'use Illuminate\\Database\\Eloquent\\Model;');

    expect(array_column((new AppModels)->all(), 'class'))->toBe([$model]);
});

it('finds models extending the framework model directly, through an alias or through app base models', function () {
    $direct = appClass($this->root, $this->namespace, 'Models/Post', 'class Post extends Model {}', 'use Illuminate\\Database\\Eloquent\\Model;');
    $aliased = appClass($this->root, $this->namespace, 'Models/User', 'class User extends Authenticatable {}', 'use Illuminate\\Foundation\\Auth\\User as Authenticatable;');
    $qualified = appClass($this->root, $this->namespace, 'Models/Tag', 'final class Tag extends \\Illuminate\\Database\\Eloquent\\Model {}');
    appClass($this->root, $this->namespace, 'Models/BaseModel', 'abstract class BaseModel extends Model {}', 'use Illuminate\\Database\\Eloquent\\Model;');
    $inherited = appClass($this->root, $this->namespace, 'Models/Invoice', 'class Invoice extends BaseModel {}');

    $classes = array_column((new AppModels)->all(), 'class');
    sort($classes);
    $expected = [$direct, $aliased, $qualified, $inherited];
    sort($expected);

    expect($classes)->toBe($expected);
});

it('leaves out pivots and abstract models', function () {
    appClass($this->root, $this->namespace, 'Models/PostTag', 'class PostTag extends Pivot {}', 'use Illuminate\\Database\\Eloquent\\Relations\\Pivot;');
    appClass($this->root, $this->namespace, 'Models/BaseModel', 'abstract class BaseModel extends \\Illuminate\\Database\\Eloquent\\Model {}');

    expect((new AppModels)->all())->toBe([]);
});
