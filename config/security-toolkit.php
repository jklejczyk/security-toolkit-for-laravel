<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Probes (DAST)
    |--------------------------------------------------------------------------
    |
    | Probes write to the database and send real requests to the application, so
    | they never run on their own: without a configured connection the probes
    | module is unavailable. Point the connection at a test database. The
    | application database is used only when allow_app_database is set, and even
    | then the production environment is refused.
    |
    */

    'probes' => [
        // Name of a connection in config/database.php. null = probes are off.
        'connection' => env('SECURITY_TOOLKIT_PROBES_CONNECTION'),

        // Where probes take their data: 'existing' (records already in the test
        // database), 'factories' (created through the application factories) or
        // 'auto' (factories, and existing records when there are none).
        'data' => env('SECURITY_TOOLKIT_PROBES_DATA', 'auto'),

        // Run migrations before probing. Only for an empty database; on a database
        // with a schema and data leave this off.
        'migrate' => (bool) env('SECURITY_TOOLKIT_PROBES_MIGRATE', false),

        // Let probes work against the application database, e.g. a local copy of a
        // customer database.
        'allow_app_database' => (bool) env('SECURITY_TOOLKIT_PROBES_ALLOW_APP_DATABASE', false),

        // Whole probe process time limit, in seconds.
        'timeout' => (int) env('SECURITY_TOOLKIT_PROBES_TIMEOUT', 300),

        // Owner of a model as a belongsTo path, e.g. App\Models\Payment::class => 'invoice.company'.
        'owners' => [],

        // How many records of the other owner to try in the 'existing' data mode.
        'candidates' => 5,

        'rate_limit' => [
            // Failed attempts before a missing limit is reported.
            'attempts' => 10,

            // Extra route names to test for a missing rate limit.
            'routes' => [],
        ],

        'payloads' => [
            // model or 'METHOD /uri' => [field => value], highest precedence when
            // building a request body.
            'fields' => [],

            // Fields left out when building a body (unpredictable rules, integrations).
            'ignore' => [],

            // Extra field names the mass assignment probe tries.
            'attack_fields' => [],
        ],

        'mass_assignment' => [
            // How many attack fields to try per target.
            'fields' => 5,
        ],
    ],

];
