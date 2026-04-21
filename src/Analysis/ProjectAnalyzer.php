<?php

declare(strict_types=1);

namespace Bastet\Analysis;

use Bastet\Flow\FlowGraphBuilder;
use Bastet\Parsing\PhpFileParser;
use Bastet\SecurityAst\AstNormalizer;
use Bastet\Taint\FunctionRegistry;
use Bastet\Taint\TaintAnalyzer;

final class ProjectAnalyzer
{
    public function __construct(
        private readonly PhpFileParser $parser = new PhpFileParser(),
        private readonly AstNormalizer $normalizer = new AstNormalizer(),
        private readonly FunctionRegistry $registry = new FunctionRegistry(),
    ) {}

    public function isAvailable(): bool
    {
        return $this->parser->canParse();
    }

    public function analyzeFile(string $filePath, string $source): ?AnalysisResult
    {
        $parsed = $this->parser->parseFile($filePath, $source);

        if ($parsed === null) {
            return null;
        }

        $program = $this->normalizer->normalize($parsed);
        $graph = (new FlowGraphBuilder($this->registry))->build($program);
        $taint = (new TaintAnalyzer($this->registry))->analyze($graph);

        return new AnalysisResult($program, $graph, $taint);
    }
}
