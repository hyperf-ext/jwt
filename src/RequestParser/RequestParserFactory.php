<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\RequestParser;

use HyperfExt\Jwt\RequestParser\Handlers\AuthHeaders;
use HyperfExt\Jwt\RequestParser\Handlers\Cookies;
use HyperfExt\Jwt\RequestParser\Handlers\InputSource;
use HyperfExt\Jwt\RequestParser\Handlers\QueryString;
use HyperfExt\Jwt\RequestParser\Handlers\RouteParams;

class RequestParserFactory
{
    public function __invoke()
    {
        return make(RequestParser::class)->setHandlers([
            new AuthHeaders(),
            new QueryString(),
            new InputSource(),
            new RouteParams(),
            new Cookies(),
        ]);
    }
}
