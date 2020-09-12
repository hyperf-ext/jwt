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

use Hyperf\Contract\ConfigInterface;
use HyperfExt\Jwt\Contracts\JwtFactoryInterface;

class JwtFactory implements JwtFactoryInterface
{
    protected $lockSubject = true;

    public function __construct(ConfigInterface $config)
    {
        $this->lockSubject = (bool) $config->get('jwt.lock_subject');
    }

    public function make(): Jwt
    {
        return make(Jwt::class)->setLockSubject($this->lockSubject);
    }
}
