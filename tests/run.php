<?php

declare(strict_types=1);

use Bastet\Core\RuleRegistry;
use Bastet\Core\Scanner;
use Bastet\Core\Severity;

require dirname(__DIR__) . '/vendor/autoload.php';

$fixturesDir = __DIR__ . '/fixtures';
$specFiles = glob($fixturesDir . '/*/expect.json');

if ($specFiles === false || $specFiles === []) {
    fwrite(STDERR, "No Bastet fixtures found.\n");
    exit(1);
}

$failures = [];
$executed = 0;

foreach ($specFiles as $specFile) {
    $executed++;
    $fixtureDir = dirname($specFile);
    $phpFile = $fixtureDir . '/input.php';

    if (! is_file($phpFile)) {
        $failures[] = basename($fixtureDir) . ': missing input.php';
        continue;
    }

    $specJson = file_get_contents($specFile);
    if ($specJson === false) {
        $failures[] = basename($fixtureDir) . ': could not read expect.json';
        continue;
    }

    $spec = json_decode($specJson, true);
    if (! is_array($spec)) {
        $failures[] = basename($fixtureDir) . ': invalid expect.json';
        continue;
    }

    $scanner = new Scanner(Severity::Info);
    foreach (RuleRegistry::all() as $rule) {
        $scanner->addRule($rule);
    }

    $findings = $scanner->scan($phpFile);
    $errors = [];

    if (isset($spec['expected_count']) && count($findings) !== (int) $spec['expected_count']) {
        $errors[] = sprintf('expected_count=%d actual=%d', (int) $spec['expected_count'], count($findings));
    }

    foreach (($spec['expected_rule_ids'] ?? []) as $ruleId) {
        $matched = array_filter($findings, static fn ($finding): bool => $finding->ruleId === $ruleId);
        if ($matched === []) {
            $errors[] = sprintf('missing expected rule %s', $ruleId);
        }
    }

    foreach (($spec['absent_rule_ids'] ?? []) as $ruleId) {
        $matched = array_filter($findings, static fn ($finding): bool => $finding->ruleId === $ruleId);
        if ($matched !== []) {
            $errors[] = sprintf('unexpected rule %s', $ruleId);
        }
    }

    foreach (($spec['expected_sources'] ?? []) as $sourceLabel) {
        $matched = array_filter(
            $findings,
            static fn ($finding): bool => ($finding->details['source'] ?? null) === $sourceLabel,
        );
        if ($matched === []) {
            $errors[] = sprintf('missing source %s', $sourceLabel);
        }
    }

    if ($errors !== []) {
        $failures[] = basename($fixtureDir) . ': ' . implode('; ', $errors);
    }
}

if ($failures !== []) {
    fwrite(STDERR, "Bastet fixture tests failed:\n");
    foreach ($failures as $failure) {
        fwrite(STDERR, "  - {$failure}\n");
    }
    exit(1);
}

fwrite(STDOUT, sprintf("Bastet fixture tests passed (%d fixtures).\n", $executed));
