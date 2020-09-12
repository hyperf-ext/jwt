<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Claims;

class Issuer extends AbstractClaim
{
    protected $name = 'iss';

    public function validate(bool $ignoreExpired = false): bool
    {
        return true;
    }
}
