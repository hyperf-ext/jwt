<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfExt\Jwt\Commands;

use Hyperf\Utils\Str;

class GenJwtSecretCommand extends AbstractGenCommand
{
    protected $name = 'gen:jwt-secret';

    protected $description = 'Set the JWT secret key used to sign the tokens';

    public function handle()
    {
        $key = base64_encode(random_bytes(64));

        if ($this->getOption('show')) {
            $this->comment($key);
            return;
        }

        if (file_exists($path = $this->envFilePath()) === false) {
            $this->displayKey($key);
            return;
        }

        if (Str::contains(file_get_contents($path), 'JWT_SECRET') === false) {
            file_put_contents($path, "\nJWT_SECRET={$key}\n", FILE_APPEND);
        } else {
            if ($this->getOption('always-no')) {
                $this->comment('Secret key already exists. Skipping...');
                return;
            }

            if ($this->isConfirmed() === false) {
                $this->comment('Phew... No changes were made to your secret key.');
                return;
            }

            file_put_contents($path, preg_replace(
                "~JWT_SECRET=[^\n]*~",
                "JWT_SECRET=\"{$key}\"",
                file_get_contents($path)
            ));
        }

        $this->displayKey($key);
    }

    protected function displayKey(string $key): void
    {
        $this->info("JWT secret [<comment>{$key}</comment>] (base64 encoded) set successfully.");
    }

    protected function isConfirmed(): bool
    {
        return $this->getOption('force') ? true : $this->confirm(
            'Are you sure you want to override the key? This will invalidate all existing tokens.'
        );
    }
}
