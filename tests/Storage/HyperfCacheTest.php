<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */
namespace HyperfTest\Storage;

use Hyperf\Cache\Cache;
use HyperfExt\Jwt\Storage\HyperfCache;
use HyperfTest\AbstractTestCase;
use Mockery;

/**
 * @internal
 * @coversNothing
 */
class HyperfCacheTest extends AbstractTestCase
{
    /**
     * @var \Hyperf\Cache\Cache|\Mockery\MockInterface
     */
    protected $cache;

    /**
     * @var \HyperfExt\Jwt\Storage\HyperfCache
     */
    protected $storage;

    /**
     * @var string
     */
    protected $tag;

    public function setUp(): void
    {
        parent::setUp();

        $this->cache = Mockery::mock(Cache::class);
        $this->tag = 'jwt.default';
        $this->storage = new HyperfCache($this->cache, $this->tag);
    }

    /** @test */
    public function itShouldAddTheItemToStorage()
    {
        $this->cache->shouldReceive('set')->with($this->resolveKey('foo'), 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
        $this->assertTrue(true);
    }

    /** @test */
    public function itShouldAddTheItemToStorageForever()
    {
        $this->cache->shouldReceive('set')->with($this->resolveKey('foo'), 'bar')->once();

        $this->storage->forever('foo', 'bar');
        $this->assertTrue(true);
    }

    /** @test */
    public function itShouldGetAnItemFromStorage()
    {
        $this->cache->shouldReceive('get')->with($this->resolveKey('foo'))->once()->andReturn(['foo' => 'bar']);

        $this->assertSame(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function itShouldRemoveTheItemFromStorage()
    {
        $this->cache->shouldReceive('delete')->with($this->resolveKey('foo'))->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function itShouldRemoveAllItemsFromStorage()
    {
        $this->cache->shouldReceive('clear')->withNoArgs()->once();

        $this->storage->flush();
        $this->assertTrue(true);
    }

    /** @test */
    public function itShouldAddTheItemToTaggedStorage()
    {
        $this->cache->shouldReceive('set')->with($this->resolveKey('foo'), 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
        $this->assertTrue(true);
    }

    /** @test */
    public function itShouldAddTheItemToTaggedStorageForever()
    {
        $this->cache->shouldReceive('set')->with($this->resolveKey('foo'), 'bar')->once();

        $this->storage->forever('foo', 'bar');
        $this->assertTrue(true);
    }

    /** @test */
    public function itShouldGetAnItemFromTaggedStorage()
    {
        $this->cache->shouldReceive('get')->with($this->resolveKey('foo'))->once()->andReturn(['foo' => 'bar']);

        $this->assertSame(['foo' => 'bar'], $this->storage->get('foo'));
    }

    protected function resolveKey(string $key)
    {
        return $this->tag . '.' . $key;
    }
}
