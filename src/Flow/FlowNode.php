<?php

declare(strict_types=1);

namespace Bastet\Flow;

final readonly class FlowNode
{
    /**
     * @param list<string> $inputs
     * @param array<string, mixed> $attributes
     */
    public function __construct(
        public string $id,
        public string $kind,
        public string $label,
        public string $file,
        public int $line,
        public array $inputs = [],
        public array $attributes = [],
    ) {}
}
