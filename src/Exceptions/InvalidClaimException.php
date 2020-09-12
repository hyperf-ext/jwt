<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Exceptions;

use Exception;
use HyperfExt\Jwt\Contracts\ClaimInterface;

class InvalidClaimException extends JwtException
{
    /**
     * Constructor.
     *
     * @param int $code
     */
    public function __construct(ClaimInterface $claim, $code = 0, Exception $previous = null)
    {
        parent::__construct('Invalid value provided for claim [' . $claim->getName() . ']', $code, $previous);
    }
}
