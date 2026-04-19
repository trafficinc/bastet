<?php

declare(strict_types=1);

namespace Bastet\Core;

use Bastet\Rules\SqlInjectionRule;
use Bastet\Rules\XssOutputRule;
use Bastet\Rules\CommandInjectionRule;
use Bastet\Rules\FileInclusionRule;
use Bastet\Rules\UnsafeUploadRule;
use Bastet\Rules\WeakHashingRule;
use Bastet\Rules\MissingCsrfRule;
use Bastet\Rules\HardcodedSecretsRule;
use Bastet\Rules\DangerousFunctionsRule;
use Bastet\Rules\InsecureCookieSessionRule;
use Bastet\Rules\AccessControlSmellsRule;
use Bastet\Rules\InsecureConfigRule;

/**
 * Central registry of all built-in rules.
 * Add new rules here to have them participate in every scan.
 */
final class RuleRegistry
{
    /** @return Rule[] */
    public static function all(): array
    {
        return [
            new SqlInjectionRule(),
            new XssOutputRule(),
            new CommandInjectionRule(),
            new FileInclusionRule(),
            new UnsafeUploadRule(),
            new WeakHashingRule(),
            new MissingCsrfRule(),
            new HardcodedSecretsRule(),
            new DangerousFunctionsRule(),
            new InsecureCookieSessionRule(),
            new AccessControlSmellsRule(),
            new InsecureConfigRule(),
        ];
    }
}
