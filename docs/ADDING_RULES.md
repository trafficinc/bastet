# Adding Rules

This package is designed to be extended in three places:

- rules in `src/Rules/`
- reporters in `src/Reporting/`
- CLI behavior in `src/Cli/Application.php`

## Add a Rule

1. Create a new class in `src/Rules/`.
2. Extend `Bastet\Core\Rule`.
3. Implement:
   - `id()`
   - `name()`
   - `analyse(string $filePath, string $source, array $lines): array`
4. Register the rule in `src/Core/RuleRegistry.php`.

Minimal example:

```php
<?php

declare(strict_types=1);

namespace Bastet\Rules;

use Bastet\Core\Finding;
use Bastet\Core\Rule;
use Bastet\Core\Severity;

final class MyRule extends Rule
{
    public function id(): string
    {
        return 'SEC013';
    }

    public function name(): string
    {
        return 'My Rule';
    }

    public function analyse(string $filePath, string $source, array $lines): array
    {
        return $this->matchLines($lines, '/danger_pattern/', function (int $lineNo, string $lineText) use ($filePath): Finding {
            return $this->finding(
                severity: Severity::High,
                title: 'Dangerous pattern found',
                file: $filePath,
                line: $lineNo,
                snippet: $lineText,
                explanation: 'Why this matters.',
                remediation: 'How to fix it.',
                confidence: 0.8,
            );
        });
    }
}
```

## Rule Guidelines

- Keep each rule focused on one class of problem.
- Prefer medium-confidence findings over noisy regexes that trigger everywhere.
- Use `matchLines()` for line-local patterns.
- Use `matchSource()` when the pattern spans lines or depends on offsets.
- Default to `php` extensions unless the rule is intentionally broader.
- Give each rule a stable ID like `SEC013`.

## Add a Reporter

1. Create a class in `src/Reporting/`.
2. Implement `Bastet\Reporting\ReporterInterface`.
3. Wire it into the reporter `match` in `src/Cli/Application.php`.

## Add a CLI Option

1. Update `getopt(...)` in `src/Cli/Application.php`.
2. Normalize and validate the option.
3. Thread it into scanner or reporter behavior.
4. Update `README.md`.

## Local Testing

From a consuming app such as `your_app/`:

```bash
php vendor/bin/bastet --list-rules
php vendor/bin/bastet app
```

Because the app uses a Composer path repository for `../bastet`, local package changes are reflected immediately.
