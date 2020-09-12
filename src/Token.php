<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt;

use Hyperf\Utils\ApplicationContext;
use HyperfExt\Jwt\Contracts\TokenValidatorInterface;

class Token
{
    /**
     * @var string
     */
    private $value;

    /**
     * @var \HyperfExt\Jwt\Contracts\TokenValidatorInterface
     */
    private $validator;

    /**
     * Create a new JSON Web Token.
     */
    public function __construct(string $value)
    {
        $this->validator = ApplicationContext::getContainer()->get(TokenValidatorInterface::class);
        $this->value = (string) $this->validator->check($value);
    }

    /**
     * Get the token when casting to string.
     */
    public function __toString(): string
    {
        return $this->get();
    }

    /**
     * Get the token.
     */
    public function get(): string
    {
        return $this->value;
    }
}
