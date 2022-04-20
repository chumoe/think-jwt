<?php

declare(strict_types=1);

namespace chumoe\jwt;

use chumoe\jwt\excep\JwtCacheTokenException;
use think\facade\Cache;

class CacheHandler
{
    /**
     * @desc: 生成设备缓存令牌
     * （1）登录时，判断该账号是否在其它设备登录，如果有，就请空之前key清除，
     * （2）重新设置key 。然后存储用户信息和ip地址拼接为key，存储在redis当中
     * @param array $args
     * @author Tinywan(ShaoBo Wan)
     */
    public static function generateToken(array $args): void
    {
        $cacheKey = $args['cache_token_pre'].$args['uid'].':'.$args['ip'];
        $key = Cache::get($cacheKey);
        if (!empty($key)) {
            Cache::delete($cacheKey);
        }
        Cache::set($cacheKey, $args['extend'], $args['cache_token_ttl']);
    }

    /**
     * @desc: 检查设备缓存令牌
     * @param string $pre
     * @param string $uid
     * @param string $ip
     * @return bool
     * @author Tinywan(ShaoBo Wan)
     */
    public static function verifyToken(string $pre, string $uid, string $ip): bool
    {
        $cacheKey = $pre.$uid.':'.$ip;
        if (!empty(Cache::get($cacheKey))) {
            throw new JwtCacheTokenException('该账号已在其他设备登录，强制下线');
        }
        return true;
    }
}
