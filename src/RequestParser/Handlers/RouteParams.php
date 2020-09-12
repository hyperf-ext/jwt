<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\RequestParser\Handlers;

use HyperfExt\Jwt\Contracts\RequestParser\HandlerInterface as ParserContract;
use Psr\Http\Message\ServerRequestInterface;

class RouteParams implements ParserContract
{
    use KeyTrait;

    /**
     * @param \Hyperf\HttpServer\Request|\Psr\Http\Message\ServerRequestInterface $request
     */
    public function parse(ServerRequestInterface $request): ?string
    {
        return $request->route($this->key);
    }
}
