<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Console;

use Illuminate\Console\Command;
use Jklejczyk\SecurityToolkit\Scanners\Probes\Engine\ProbeEngine;
use Jklejczyk\SecurityToolkit\Scanners\Probes\ProbesConfig;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

/**
 * The hidden child-process command. It boots the application with the probe environment already in
 * place, runs the probes and prints their report as JSON on the last line of stdout.
 */
final class ProbeCommand extends Command
{
    protected $signature = 'security:probe
        {--internal : Print the probe report as JSON for the parent scan process}
        {--deadline=270 : Seconds the probe process may spend before it stops probing}';

    protected $description = 'Run the DAST probes in an isolated process (internal)';

    public function __construct()
    {
        parent::__construct();

        $this->setHidden(true);
    }

    public function handle(ProbeEngine $engine): int
    {
        if ($this->option('internal') !== true) {
            $this->output->getErrorStyle()->error('This command is internal. Run "php artisan security:scan" instead.');

            return self::INVALID;
        }

        $deadline = $this->option('deadline');

        try {
            $report = $engine->run(ProbesConfig::fromConfig(), is_numeric($deadline) ? (int) $deadline : 270);
        } catch (Throwable $exception) {
            $this->output->getErrorStyle()->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->output->writeln($report->toJson(), OutputInterface::OUTPUT_RAW);

        return self::SUCCESS;
    }
}
