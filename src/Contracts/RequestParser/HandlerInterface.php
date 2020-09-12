<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Contracts\RequestParser;

use Psr\Http\Message\ServerRequestInterface;

interface HandlerInterface
{
    /**
     * Parse the request.
     *
     * @param \Hyperf\HttpServer\Request|\Psr\Http\Message\ServerRequestInterface $request
     */
    public function parse(ServerRequestInterface $request): ?string;
}
