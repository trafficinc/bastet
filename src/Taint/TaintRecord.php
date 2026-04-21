<?php

declare(strict_types=1);

namespace Bastet\Taint;

final readonly class TaintRecord
{
    /**
     * @param list<SecurityContext> $sanitizedFor
     */
    public function __construct(
        public TaintState $state,
        public ?string $predecessor = null,
        public ?string $sourceLabel = null,
        public array $sanitizedFor = [],
    ) {}

    public function isSafeFor(SecurityContext $context): bool
    {
        if ($this->state === TaintState::Clean) {
            return true;
        }

        if ($this->state === TaintState::Sanitized) {
            return in_array($context, $this->sanitizedFor, true);
        }

        return false;
    }
}
