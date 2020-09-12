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

use HyperfExt\Jwt\Exceptions\TokenExpiredException;

class Expiration extends AbstractClaim
{
    use DatetimeTrait;

    protected $name = 'exp';

    public function validate(bool $ignoreExpired = false): bool
    {
        if (! $ignoreExpired and $this->isPast($this->getValue())) {
            throw new TokenExpiredException('Token has expired');
        }
        return true;
    }
}
