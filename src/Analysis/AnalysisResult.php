<?php

declare(strict_types=1);

namespace Bastet\Analysis;

use Bastet\Flow\FlowGraph;
use Bastet\SecurityAst\Program;
use Bastet\Taint\TaintAnalysisResult;

final readonly class AnalysisResult
{
    public function __construct(
        public Program $program,
        public FlowGraph $graph,
        public TaintAnalysisResult $taint,
    ) {}
}
