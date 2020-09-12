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

use HyperfExt\Jwt\Contracts\RequestParser\RequestParserInterface;
use Psr\Http\Message\ServerRequestInterface;

class RequestParser implements RequestParserInterface
{
    /**
     * @var \HyperfExt\Jwt\Contracts\RequestParser\HandlerInterface[]
     */
    private $handlers;

    /**
     * @param \HyperfExt\Jwt\Contracts\RequestParser\HandlerInterface[] $handlers
     */
    public function __construct(array $handlers = [])
    {
        $this->handlers = $handlers;
    }

    public function getHandlers(): array
    {
        return $this->handlers;
    }

    public function setHandlers(array $handlers)
    {
        $this->handlers = $handlers;

        return $this;
    }

    public function parseToken(ServerRequestInterface $request): ?string
    {
        foreach ($this->handlers as $handler) {
            if ($token = $handler->parse($request)) {
                return $token;
            }
        }
        return null;
    }

    public function hasToken(ServerRequestInterface $request): bool
    {
        return $this->parseToken($request) !== null;
    }
}
