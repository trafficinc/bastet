<?php

declare(strict_types=1);

namespace Bastet\Taint;

enum TaintState: int
{
    case Clean = 0;
    case Sanitized = 1;
    case Tainted = 2;

    public static function merge(self ...$states): self
    {
        $result = self::Clean;

        foreach ($states as $state) {
            if ($state->value > $result->value) {
                $result = $state;
            }
        }

        return $result;
    }
}
