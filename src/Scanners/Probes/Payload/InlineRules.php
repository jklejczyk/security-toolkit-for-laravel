<?php

declare(strict_types=1);

namespace Jklejczyk\SecurityToolkit\Scanners\Probes\Payload;

/**
 * Validation rules written in the action itself: the array passed to $request->validate(),
 * request()->validate(), $this->validate($request, ...) or $request->validateWithBag('bag', ...).
 * Read with the PHP tokenizer and accepted only when every key and rule is a plain string literal;
 * a rule object, a variable or a constant makes the whole array unreadable, because rules taken in
 * part would build a body the action rejects for a reason the probe cannot name.
 */
final class InlineRules
{
    private const IGNORED = [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG];

    /**
     * @return array<string, list<string>>|null field => rules; null without a readable validate call
     */
    public static function from(string $actionCode): ?array
    {
        $tokens = self::tokens($actionCode);
        $count = count($tokens);

        for ($i = 2; $i < $count - 1; $i++) {
            [$type, $text] = $tokens[$i];

            if ($type !== T_STRING || ! in_array($text, ['validate', 'validateWithBag'], true)) {
                continue;
            }

            if (! in_array($tokens[$i - 1][0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true) || $tokens[$i + 1][1] !== '(') {
                continue;
            }

            $arguments = self::arguments($tokens, $i + 1);

            if ($arguments === []) {
                // Validator::make(...)->validate() and the like: the rules are elsewhere.
                continue;
            }

            $onController = $tokens[$i - 2][0] === T_VARIABLE && $tokens[$i - 2][1] === '$this';
            $position = $text === 'validateWithBag' || $onController ? 1 : 0;

            return isset($arguments[$position]) ? self::rules($tokens, $arguments[$position]) : null;
        }

        return null;
    }

    /**
     * @return list<array{0: int|string, 1: string}>
     */
    private static function tokens(string $code): array
    {
        $tokens = [];

        foreach (token_get_all('<?php '.$code) as $token) {
            if (is_array($token)) {
                if (! in_array($token[0], self::IGNORED, true)) {
                    $tokens[] = [$token[0], $token[1]];
                }

                continue;
            }

            $tokens[] = [$token, $token];
        }

        // End markers, so reading past truncated code meets a token that is never a literal.
        return [...$tokens, [0, ''], [0, ''], [0, '']];
    }

    /**
     * Start index of each top-level argument of the call whose "(" is at $open.
     *
     * @param  list<array{0: int|string, 1: string}>  $tokens
     * @return list<int>
     */
    private static function arguments(array $tokens, int $open): array
    {
        $starts = [];
        $depth = 0;
        $count = count($tokens);

        for ($i = $open; $i < $count; $i++) {
            $text = $tokens[$i][1];

            if (in_array($text, ['(', '[', '{'], true)) {
                $depth++;

                if ($depth === 1 && $tokens[$i + 1][1] !== ')') {
                    $starts[] = $i + 1;
                }

                continue;
            }

            if (in_array($text, [')', ']', '}'], true)) {
                $depth--;

                if ($depth === 0) {
                    break;
                }

                continue;
            }

            if ($text === ',' && $depth === 1 && isset($tokens[$i + 1]) && $tokens[$i + 1][1] !== ')') {
                $starts[] = $i + 1;
            }
        }

        return $starts;
    }

    /**
     * @param  list<array{0: int|string, 1: string}>  $tokens
     * @return array<string, list<string>>|null
     */
    private static function rules(array $tokens, int $start): ?array
    {
        if ($tokens[$start][1] !== '[') {
            return null;
        }

        $rules = [];
        $i = $start + 1;

        while (true) {
            if ($tokens[$i][1] === ']') {
                return $rules;
            }

            $field = self::literal($tokens[$i]);

            if ($field === null || $tokens[$i + 1][0] !== T_DOUBLE_ARROW) {
                return null;
            }

            $i += 2;

            if ($tokens[$i][1] === '[') {
                $list = [];
                $i++;

                while ($tokens[$i][1] !== ']') {
                    $rule = self::literal($tokens[$i]);

                    if ($rule === null) {
                        return null;
                    }

                    $list[] = $rule;
                    $i++;

                    if ($tokens[$i][1] === ',') {
                        $i++;
                    } elseif ($tokens[$i][1] !== ']') {
                        return null;
                    }
                }
            } else {
                $rule = self::literal($tokens[$i]);

                if ($rule === null) {
                    return null;
                }

                $list = explode('|', $rule);
            }

            $rules[$field] = $list;
            $i++;

            if ($tokens[$i][1] === ',') {
                $i++;
            } elseif ($tokens[$i][1] !== ']') {
                return null;
            }
        }
    }

    /**
     * @param  array{0: int|string, 1: string}  $token
     */
    private static function literal(array $token): ?string
    {
        if ($token[0] !== T_CONSTANT_ENCAPSED_STRING) {
            return null;
        }

        $quote = $token[1][0];
        $inner = substr($token[1], 1, -1);

        return $quote === "'" ? str_replace(["\\'", '\\\\'], ["'", '\\'], $inner) : stripcslashes($inner);
    }
}
