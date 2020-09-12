<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfTest;

use HyperfExt\Jwt\Codec;
use HyperfExt\Jwt\Exceptions\JwtException;
use HyperfExt\Jwt\Exceptions\TokenInvalidException;
use InvalidArgumentException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Mockery;

/**
 * @internal
 * @coversNothing
 */
class CodecTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $parser;

    /**
     * @var \Mockery\MockInterface
     */
    protected $builder;

    public function setUp()
    {
        parent::setUp();

        $this->builder = Mockery::mock(Builder::class);
        $this->parser = Mockery::mock(Parser::class);
    }

    /** @test */
    public function itShouldSetTheAlgo()
    {
        $codec = $this->getCodec('secret', 'HS256', []);
        $codec->setAlgo('HS512');

        $this->assertSame('HS512', $codec->getAlgo());
    }

    /** @test */
    public function itShouldSetTheSecret()
    {
        $codec = $this->getCodec('secret', 'HS256', []);
        $codec->setSecret('foo');

        $this->assertSame('foo', $codec->getSecret());
    }

    /** @test */
    public function itShouldReturnTheTokenWhenPassingAValidPayloadToEncode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->builder->shouldReceive('withClaim')->times(count($payload));
        $this->builder->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');
        $this->builder->shouldReceive('sign')->never();

        $token = $this->getCodec('secret', 'HS256')->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /** @test */
    public function itShouldThrowAnInvalidExceptionWhenThePayloadCouldNotBeEncoded()
    {
        $this->expectExceptionMessage('Could not create token:');
        $this->expectException(JwtException::class);
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->builder->shouldReceive('withClaim')->times(count($payload));
        $this->builder->shouldReceive('sign')->never();

        $this->getCodec('secret', 'HS256')->encode($payload);
    }

    /** @test */
    public function itShouldReturnThePayloadWhenPassingAValidTokenToDecode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $jwt = Mockery::mock(Token::class);
        $jwt->shouldReceive('verify')->once()->with(Mockery::any(), Mockery::any())->andReturn(true);
        $jwt->shouldReceive('getClaims')->once()->andReturn($payload);
        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn($jwt);

        $this->assertSame($payload, $this->getCodec('secret', 'HS256')->decode('foo.bar.baz'));
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecodedDueToABadSignature()
    {
        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('Token Signature could not be verified.');

        $jwt = Mockery::mock(Token::class);
        $jwt->shouldReceive('verify')->once()->with(Mockery::any(), Mockery::any())->andReturn(false);
        $jwt->shouldReceive('getClaims')->never();
        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andReturn(Mockery::self());

        $this->getCodec('secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldThrowATokenInvalidExceptionWhenTheTokenCouldNotBeDecoded()
    {
        $this->expectExceptionMessage('Could not decode token:');
        $this->expectException(TokenInvalidException::class);
        $this->parser->shouldReceive('parse')->once()->with('foo.bar.baz')->andThrow(new InvalidArgumentException());
        $this->parser->shouldReceive('verify')->never();
        $this->parser->shouldReceive('getClaims')->never();

        $this->getCodec('secret', 'HS256')->decode('foo.bar.baz');
    }

    /** @test */
    public function itShouldGenerateATokenWhenUsingAnRsaAlgorithm()
    {
        $codec = $this->getCodec(
            'does_not_matter',
            'RS256',
            ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $this->builder->shouldReceive('withClaim')->times(count($payload));
        $this->builder->shouldReceive('getToken')->once()->andReturn('foo.bar.baz');

        $token = $codec->encode($payload);

        $this->assertSame('foo.bar.baz', $token);
    }

    /** @test */
    public function itShouldThrowAExceptionWhenTheAlgorithmPassedIsInvalid()
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('The given algorithm could not be found');

        $jwt = Mockery::mock(Token::class);
        $this->parser->shouldReceive('parse')->andReturn($jwt);
        $this->parser->shouldReceive('verify')->never();

        $this->getCodec('secret', 'AlgorithmWrong')->decode('foo.bar.baz');
    }

    /**
     * @test
     */
    public function itShouldReturnThePublicKey()
    {
        $codec = $this->getCodec(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys['public'], $codec->getPublicKey());
    }

    /**
     * @test
     */
    public function itShouldReturnTheKeys()
    {
        $codec = $this->getCodec(
            'does_not_matter',
            'RS256',
            $keys = ['private' => $this->getDummyPrivateKey(), 'public' => $this->getDummyPublicKey()]
        );

        $this->assertSame($keys, $codec->getKeys());
    }

    /**
     * @param $secret
     * @param $algo
     *
     * @return \HyperfExt\Jwt\Codec|\PHPUnit\Framework\MockObject\MockObject
     */
    public function getCodec($secret, $algo, array $keys = [])
    {
        $codec = $this->getMockBuilder(Codec::class)
            ->setMethods(['getBuilder', 'getParser'])
            ->setConstructorArgs([$secret, $algo, $keys])
            ->getMock();
        $codec->method('getBuilder')->willReturn($this->builder);
        $codec->method('getParser')->willReturn($this->parser);
        return $codec;
    }

    public function getDummyPrivateKey()
    {
        return file_get_contents(__DIR__ . '/Keys/id_rsa');
    }

    public function getDummyPublicKey()
    {
        return file_get_contents(__DIR__ . '/Keys/id_rsa.pub');
    }
}
