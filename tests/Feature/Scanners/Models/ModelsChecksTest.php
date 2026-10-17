<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\File;
use Jklejczyk\SecurityToolkit\Core\Findings\Finding;
use Jklejczyk\SecurityToolkit\Core\Findings\Severity;
use Jklejczyk\SecurityToolkit\Scanners\Models\Checks\GuardedEmptyCheck;
use Jklejczyk\SecurityToolkit\Scanners\Models\Checks\UnguardedCheck;

beforeEach(function () {
    $this->root = temporaryApp();
});

afterEach(function () {
    Model::reguard();
    File::deleteDirectory($this->root);
});

/**
 * Writes a class to app/Models and loads it; the namespace is unique, so every test can reuse class names.
 */
function appModel(string $root, string $class, string $body, string $extends = '\Illuminate\Database\Eloquent\Model', string $modifiers = ''): string
{
    static $counter = 0;
    $namespace = 'App\Models\Test'.(++$counter);

    @mkdir($root.'/app/Models', 0777, true);
    $file = $root.'/app/Models/'.$class.$counter.'.php';
    file_put_contents($file, "<?php\n\nnamespace {$namespace};\n\n{$modifiers}class {$class} extends {$extends}\n{\n    {$body}\n}\n");
    require $file;

    return $namespace.'\\'.$class;
}

function appController(string $root, string $code): void
{
    @mkdir($root.'/app/Http/Controllers', 0777, true);
    file_put_contents($root.'/app/Http/Controllers/PostController.php', "<?php\n\n{$code}\n");
}

/**
 * @return list<Finding>
 */
function modelFindings(object $check): array
{
    return iterator_to_array($check->run(localContext(basePath: test()->root)), false);
}

describe('models.unguarded', function () {
    it('runs in every environment', function () {
        expect((new UnguardedCheck)->onlyInProduction())->toBeFalse()
            ->and((new UnguardedCheck)->id())->toBe('models.unguarded');
    });

    it('reports models unguarded while the application boots, pointing at the call', function () {
        file_put_contents($this->root.'/app/AppServiceProvider.php', "<?php\n\nclass AppServiceProvider\n{\n    public function boot()\n    {\n        Model::unguard();\n    }\n}\n");
        Model::unguard();

        $findings = modelFindings(new UnguardedCheck);

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->severity)->toBe(Severity::Medium)
            ->and($findings[0]->cwe)->toBe([915])
            ->and($findings[0]->cvss)->toBeNull()
            ->and($findings[0]->location?->file)->toBe('app/AppServiceProvider.php')
            ->and($findings[0]->location?->line)->toBe(7);
    });

    it('reports without a location when the call is outside app/', function () {
        Model::unguard();

        expect(modelFindings(new UnguardedCheck)[0]->location)->toBeNull();
    });

    it('does not report guarded models, even with scoped or seeder calls in the code', function () {
        file_put_contents($this->root.'/app/Importer.php', '<?php Model::unguarded(fn () => null); Model::unguard(); Model::reguard();');

        expect(modelFindings(new UnguardedCheck))->toBe([]);
    });
});

describe('models.guarded-empty', function () {
    it('runs in every environment', function () {
        expect((new GuardedEmptyCheck)->onlyInProduction())->toBeFalse()
            ->and((new GuardedEmptyCheck)->id())->toBe('models.guarded-empty');
    });

    it('reports a model with an empty $guarded when the whole request is mass assigned', function (string $call) {
        $class = appModel($this->root, 'Post', 'protected $guarded = [];');
        appModel($this->root, 'Comment', "protected \$fillable = ['body'];");
        appController($this->root, "\n\$post = {$call};");

        $findings = modelFindings(new GuardedEmptyCheck);

        expect($findings)->toHaveCount(1)
            ->and($findings[0]->title)->toBe('Post accepts mass assignment of every attribute')
            ->and($findings[0]->description)->toContain($class, 'app/Http/Controllers/PostController.php:4')
            ->and($findings[0]->location?->file)->toStartWith('app/Models/Post')
            ->and($findings[0]->severity)->toBe(Severity::Medium)
            ->and($findings[0]->cwe)->toBe([915]);
    })->with([
        'Post::create($request->all())',
        '$post->fill(request()->all())',
        '$post->update($request->input())',
        'Post::updateOrCreate(Request::all())',
        'Post::firstOrCreate( $request->all() )',
    ]);

    it('does not report without evidence of the whole request being assigned', function (string $call) {
        appModel($this->root, 'Post', 'protected $guarded = [];');
        appController($this->root, "\$post = {$call};");

        expect(modelFindings(new GuardedEmptyCheck))->toBe([]);
    })->with([
        'Post::create($request->validated())',
        'Post::create($request->only(["title"]))',
        'Post::create(["title" => $request->input("title")])',
        '$request->all()',
    ]);

    it('does not report models with fillable or guarded attributes', function () {
        appModel($this->root, 'Post', "protected \$fillable = ['title'];");
        appModel($this->root, 'Tag', "protected \$guarded = ['id'];");
        appModel($this->root, 'Category', '');
        appController($this->root, 'Post::create($request->all());');

        expect(modelFindings(new GuardedEmptyCheck))->toBe([]);
    });

    it('ignores abstract models, pivots and classes that are not models', function () {
        appModel($this->root, 'BaseModel', 'protected $guarded = [];', modifiers: 'abstract ');
        appModel($this->root, 'PostTag', '', '\Illuminate\Database\Eloquent\Relations\Pivot');
        appModel($this->root, 'Dto', 'protected $guarded = [];', '\ArrayObject');
        appController($this->root, 'Post::create($request->all());');

        expect(modelFindings(new GuardedEmptyCheck))->toBe([]);
    });

    it('reads the guarded attributes without calling the constructor', function () {
        appModel($this->root, 'Post', 'protected $guarded = []; public function __construct(string $required) { throw new RuntimeException("constructed"); }');
        appController($this->root, 'Post::create($request->all());');

        expect(modelFindings(new GuardedEmptyCheck))->toHaveCount(1);
    });

    it('leaves the finding to models.unguarded when every model is unguarded', function () {
        appModel($this->root, 'Post', 'protected $guarded = [];');
        appController($this->root, 'Post::create($request->all());');
        Model::unguard();

        expect(modelFindings(new GuardedEmptyCheck))->toBe([]);
    });
});

it('reports a model marked with the #[Unguarded] attribute', function () {
    $class = appModel($this->root, 'Post', '', modifiers: "#[\\Illuminate\\Database\\Eloquent\\Attributes\\Unguarded]\n");
    appController($this->root, 'Post::create($request->all());');

    expect(modelFindings(new GuardedEmptyCheck))->toHaveCount(1);
})->skip(! class_exists('Illuminate\Database\Eloquent\Attributes\Unguarded'), 'model attributes need Laravel 13');
