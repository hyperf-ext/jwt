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

use HyperfExt\Jwt\Exceptions\TokenInvalidException;

class NotBefore extends AbstractClaim
{
    use DatetimeTrait;

    protected $name = 'nbf';

    public function validate(bool $ignoreExpired = false): bool
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future');
        }
        return true;
    }
}
