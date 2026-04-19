<?php

declare(strict_types=1);

namespace Bastet\Core;

enum Severity: string
{
    case Critical = 'critical';
    case High     = 'high';
    case Medium   = 'medium';
    case Low      = 'low';
    case Info     = 'info';

    public function weight(): int
    {
        return match($this) {
            self::Critical => 5,
            self::High     => 4,
            self::Medium   => 3,
            self::Low      => 2,
            self::Info     => 1,
        };
    }

    public function color(): string
    {
        return match($this) {
            self::Critical => "\033[1;31m",  // bold red
            self::High     => "\033[0;31m",  // red
            self::Medium   => "\033[0;33m",  // yellow
            self::Low      => "\033[0;36m",  // cyan
            self::Info     => "\033[0;37m",  // light gray
        };
    }

    public static function fromString(string $value): self
    {
        return match(strtolower($value)) {
            'critical' => self::Critical,
            'high'     => self::High,
            'medium'   => self::Medium,
            'low'      => self::Low,
            'info'     => self::Info,
            default    => throw new \ValueError("Unknown severity: {$value}"),
        };
    }
}
