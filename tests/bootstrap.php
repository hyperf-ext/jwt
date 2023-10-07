<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
use Hyperf\Config\Config;
use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\ClassLoader;
use Hyperf\Di\Container;
use Hyperf\Di\Definition\DefinitionSourceFactory;
use Hyperf\HttpMessage\Server\Request;
use Hyperf\HttpServer\Request as HttpServerRequest;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Context\Context;
use HyperfExt\Jwt\Contracts\PayloadValidatorInterface;
use HyperfExt\Jwt\Contracts\TokenValidatorInterface;
use HyperfExt\Jwt\Validators\PayloadValidator;
use HyperfExt\Jwt\Validators\TokenValidator;
use Psr\Http\Message\ServerRequestInterface;

! defined('BASE_PATH') && define('BASE_PATH', dirname(__DIR__, 1));
! defined('SWOOLE_HOOK_FLAGS') && define('SWOOLE_HOOK_FLAGS', SWOOLE_HOOK_ALL);

Swoole\Runtime::enableCoroutine(true);

require_once dirname(dirname(__FILE__)) . '/vendor/autoload.php';

ClassLoader::init();

$container = new Container((new DefinitionSourceFactory(true))());
$container->set(ConfigInterface::class, $config = new Config([]));

$container->set(PayloadValidatorInterface::class, new PayloadValidator($config));
$container->set(TokenValidatorInterface::class, new TokenValidator());
$container->set(ServerRequestInterface::class, new HttpServerRequest());
Context::set(ServerRequestInterface::class, new Request('GET', '/'));

ApplicationContext::setContainer($container);

$container->get(Hyperf\Contract\ApplicationInterface::class);
