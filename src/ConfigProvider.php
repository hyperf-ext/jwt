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

use HyperfExt\Jwt\Commands\GenJwtKeypairCommand;
use HyperfExt\Jwt\Commands\GenJwtSecretCommand;
use HyperfExt\Jwt\Contracts\JwtFactoryInterface;
use HyperfExt\Jwt\Contracts\ManagerInterface;
use HyperfExt\Jwt\Contracts\PayloadValidatorInterface;
use HyperfExt\Jwt\Contracts\RequestParser\RequestParserInterface;
use HyperfExt\Jwt\Contracts\TokenValidatorInterface;
use HyperfExt\Jwt\RequestParser\RequestParserFactory;
use HyperfExt\Jwt\Validators\PayloadValidator;
use HyperfExt\Jwt\Validators\TokenValidator;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                ManagerInterface::class => ManagerFactory::class,
                TokenValidatorInterface::class => TokenValidator::class,
                PayloadValidatorInterface::class => PayloadValidator::class,
                RequestParserInterface::class => RequestParserFactory::class,
                JwtFactoryInterface::class => JwtFactory::class,
            ],
            'commands' => [
                GenJwtSecretCommand::class,
                GenJwtKeypairCommand::class,
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for hyperf-ext/jwt.',
                    'source' => __DIR__ . '/../publish/jwt.php',
                    'destination' => BASE_PATH . '/config/autoload/jwt.php',
                ],
            ],
        ];
    }
}
