<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Contracts;

interface TokenValidatorInterface extends ValidatorInterface
{
    /**
     * Perform some checks on the value.
     */
    public function check(string $value): string;

    /**
     * Helper function to return a boolean.
     */
    public function isValid(string $value): bool;
}
