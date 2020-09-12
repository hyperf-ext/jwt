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

use HyperfExt\Jwt\Blacklist;
use HyperfExt\Jwt\Payload;
use HyperfExt\Jwt\Token;

interface ManagerInterface
{
    /**
     * Encode a Payload and return the Token.
     */
    public function encode(Payload $payload): Token;

    /**
     * Decode a Token and return the Payload.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenBlacklistedException
     */
    public function decode(Token $token, bool $checkBlacklist = true): Payload;

    /**
     * Refresh a Token and return a new Token.
     *
     * @throws \HyperfExt\Jwt\Exceptions\TokenBlacklistedException
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function refresh(Token $token, bool $forceForever = false): Token;

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @throws \HyperfExt\Jwt\Exceptions\JwtException
     */
    public function invalidate(Token $token, bool $forceForever = false): bool;
}
