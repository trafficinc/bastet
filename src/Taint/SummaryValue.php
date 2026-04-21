<?php

declare(strict_types=1);

namespace Bastet\Taint;

final readonly class SummaryValue
{
    /**
     * @param list<int> $argIndexes
     * @param list<SecurityContext> $sanitizedFor
     */
    public function __construct(
        public array $argIndexes = [],
        public array $sanitizedFor = [],
        public bool $taintedWithoutArgs = false,
        public ?string $sourceLabel = null,
    ) {}

    public static function clean(): self
    {
        return new self();
    }

    public function merge(self $other): self
    {
        return new self(
            argIndexes: array_values(array_unique(array_merge($this->argIndexes, $other->argIndexes))),
            sanitizedFor: array_values(array_unique(array_merge($this->sanitizedFor, $other->sanitizedFor))),
            taintedWithoutArgs: $this->taintedWithoutArgs || $other->taintedWithoutArgs,
            sourceLabel: $this->sourceLabel ?? $other->sourceLabel,
        );
    }

    public function withSanitization(array $contexts): self
    {
        return new self(
            argIndexes: $this->argIndexes,
            sanitizedFor: array_values(array_unique($contexts)),
            taintedWithoutArgs: $this->taintedWithoutArgs,
            sourceLabel: $this->sourceLabel,
        );
    }

    public function withoutSanitization(): self
    {
        return new self(
            argIndexes: $this->argIndexes,
            sanitizedFor: [],
            taintedWithoutArgs: $this->taintedWithoutArgs,
            sourceLabel: $this->sourceLabel,
        );
    }

    public function dependsOnInput(): bool
    {
        return $this->argIndexes !== [] || $this->taintedWithoutArgs;
    }
}
