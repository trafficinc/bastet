<?php

declare(strict_types=1);

namespace Bastet\Flow;

final readonly class FlowEdge
{
    public function __construct(
        public string $from,
        public string $to,
        public string $type,
    ) {}
}
