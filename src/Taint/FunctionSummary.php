<?php

declare(strict_types=1);

namespace Bastet\Taint;

final readonly class FunctionSummary
{
    /**
     * @param list<int> $taintOutFromArgs
     * @param list<SecurityContext> $sanitizes
     */
    public function __construct(
        public array $taintOutFromArgs = [],
        public array $sanitizes = [],
        public bool $taintedWithoutArgs = false,
        public ?string $sourceLabel = null,
    ) {}

    public function equals(self $other): bool
    {
        return $this->taintOutFromArgs === $other->taintOutFromArgs
            && $this->sanitizes === $other->sanitizes
            && $this->taintedWithoutArgs === $other->taintedWithoutArgs
            && $this->sourceLabel === $other->sourceLabel;
    }
}
