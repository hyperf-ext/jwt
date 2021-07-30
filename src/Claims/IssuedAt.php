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

use HyperfExt\Jwt\Exceptions\InvalidClaimException;
use HyperfExt\Jwt\Exceptions\TokenExpiredException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;

class IssuedAt extends AbstractClaim
{
    use DatetimeTrait {
        validateCreate as commonValidateCreate;
    }

    protected $name = 'iat';

    public function validateCreate($value)
    {
        $this->commonValidateCreate($value);

        if ($this->isFuture($value)) {
            throw new InvalidClaimException($this);
        }

        return $value;
    }

    public function validate(bool $ignoreExpired = false): bool
    {
        if ($this->isFuture($value = $this->getValue())) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future');
        }

        if (
            ($refreshTtl = $this->getFactory()->getRefreshTtl()) !== null && $this->isPast($value + $refreshTtl)
        ) {
            throw new TokenExpiredException('Token has expired and can no longer be refreshed');
        }

        return true;
    }
}
