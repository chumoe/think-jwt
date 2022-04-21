<?php

declare(strict_types=1);

namespace chumoe\jwt;

use chumoe\jwt\exception\JwtCacheTokenException;
use chumoe\jwt\exception\JwtConfigException;
use chumoe\jwt\exception\JwtRefreshTokenExpiredException;
use chumoe\jwt\exception\JwtTokenException;
use chumoe\jwt\exception\JwtTokenExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use think\facade\Request;
use UnexpectedValueException;

class JwtToken
{
    /**
     * access_token.
     */
    private const ACCESS_TOKEN = 1;

    /**
     * refresh_token.
     */
    private const REFRESH_TOKEN = 2;

    /**
     * 获取用户真实IP
     * @return array|false|mixed|string
     */
    public static function getRealIp()
    {
        if (isset($_SERVER['HTTP_X_SHOPIFY_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_X_SHOPIFY_CLIENT_IP'];
        } else {
            if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
                $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            } else {
                if (getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
                    $ip = getenv('HTTP_CLIENT_IP');
                } elseif (getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
                    $ip = getenv('HTTP_X_FORWARDED_FOR');
                } elseif (getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
                    $ip = getenv('REMOTE_ADDR');
                } elseif (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'],
                        'unknown')) {
                    $ip = $_SERVER['REMOTE_ADDR'];
                }
            }
        }
        return $ip;
    }

    /**
     * 获取当前登录ID
     * @return mixed
     * @throws JwtTokenException
     * @author Tinywan(ShaoBo Wan)
     */
    public static function getCurrentId()
    {
        return self::getExtendVal('id') ?? 0;
    }

    /**
     * 获取指定令牌扩展内容字段的值
     * @param string $val
     * @return mixed|string
     * @throws JwtTokenException
     */
    public static function getExtendVal(string $val)
    {
        return self::getTokenExtend()[$val] ?? '';
    }

    /**
     * @desc 获取指定令牌扩展内容
     * @return array
     * @throws JwtTokenException
     */
    public static function getExtend(): array
    {
        return self::getTokenExtend();
    }

    /**
     * 刷新令牌
     * @return array|string[]
     * @throws JwtTokenException
     */
    public static function refreshToken(): array
    {
        $token = self::getTokenFromHeaders();
        $config = self::_getConfig();
        try {
            $tokenPayload = self::verifyToken($token, self::REFRESH_TOKEN);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtTokenException('刷新令牌无效');
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtTokenException('刷新令牌尚未生效');
        } catch (ExpiredException $expiredException) {
            throw new JwtRefreshTokenExpiredException('刷新令牌会话已过期，请再次登录！');
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtTokenException('刷新令牌获取的扩展字段不存在');
        } catch (JwtCacheTokenException|\Exception $exception) {
            throw new JwtTokenException($exception->getMessage());
        }
        $tokenPayload['exp'] = time() + $config['access_exp'];
        $secretKey = self::getPrivateKey($config);
        $token = self::makeToken($tokenPayload, $secretKey, $config['algorithms']);

        return ['access_token' => $token];
    }

    /**
     * 生成令牌
     * @param array $extend
     * @param int|null $access_exp
     * @param bool|null $refresh_disable
     * @return array
     */
    public static function generateToken(array $extend, int $access_exp = null, bool $refresh_disable = null): array
    {
        if (!isset($extend['uid'])) {
            throw new JwtTokenException('缺少全局唯一字段：uid');
        }
        $config = self::_getConfig();
        $config['access_exp'] = $access_exp ?? $config['access_exp'];
        $config['refresh_disable'] = $refresh_disable ?? $config['refresh_disable'];
        $payload = self::generatePayload($config, $extend);
        $secretKey = self::getPrivateKey($config);
        $token = [
            'token_type'   => 'Bearer',
            'expires_in'   => $config['access_exp'],
            'access_token' => self::makeToken($payload['accessPayload'], $secretKey, $config['algorithms'])
        ];
        if (!isset($config['refresh_disable']) || (isset($config['refresh_disable']) && $config['refresh_disable'] === false)) {
            $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
            $token['refresh_token'] = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']);
        }
        return $token;
    }

    /**
     * 验证令牌
     * @param int $tokenType
     * @param string|null $token
     * @return array
     * @throws JwtTokenException
     * @author Tinywan(ShaoBo Wan)
     */
    public static function verify(int $tokenType = self::ACCESS_TOKEN, string $token = null): array
    {
        $token = $token ?? self::getTokenFromHeaders();
        try {
            return self::verifyToken($token, $tokenType);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtTokenException('身份验证令牌无效');
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtTokenException('身份验证令牌尚未生效');
        } catch (ExpiredException $expiredException) {
            throw new JwtTokenExpiredException('身份验证会话已过期，请重新登录！');
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtTokenException('获取的扩展字段不存在');
        } catch (JwtCacheTokenException|\Exception $exception) {
            throw new JwtTokenException($exception->getMessage());
        }
    }

    /**
     * 获取扩展字段.
     * @return array
     * @throws JwtTokenException
     */
    private static function getTokenExtend(): array
    {
        return (array)self::verify()['extend'];
    }

    /**
     * 获令牌有效期剩余时长.
     * @param int $tokenType
     * @return int
     */
    public static function getTokenExp(int $tokenType = self::ACCESS_TOKEN): int
    {
        return (int)self::verify($tokenType)['exp'] - time();
    }

    /**
     * 获取Header头部authorization令牌
     * @throws JwtTokenException
     */
    private static function getTokenFromHeaders(): string
    {
        $authorization = Request::header('authorization');
        if (!$authorization || 'undefined' == $authorization) {
            throw new JwtTokenException('请求未携带authorization信息');
        }

        if (self::REFRESH_TOKEN != substr_count($authorization, '.')) {
            throw new JwtTokenException('非法的authorization信息');
        }

        if (2 != count(explode(' ', $authorization))) {
            throw new JwtTokenException('Bearer验证中的凭证格式有误，中间必须有个空格');
        }

        [$type, $token] = explode(' ', $authorization);
        if ('Bearer' !== $type) {
            throw new JwtTokenException('接口认证方式需为Bearer');
        }
        if (!$token || 'undefined' === $token) {
            throw new JwtTokenException('尝试获取的Authorization信息不存在');
        }

        return $token;
    }

    /**
     * 校验令牌
     * @param string $token
     * @param int $tokenType
     * @return array
     * @author Tinywan(ShaoBo Wan)
     */
    private static function verifyToken(string $token, int $tokenType): array
    {
        $config = self::_getConfig();
        $publicKey = self::ACCESS_TOKEN == $tokenType ? self::getPublicKey($config['algorithms']) : self::getPublicKey($config['algorithms'], self::REFRESH_TOKEN);
        JWT::$leeway = $config['leeway'];

        $decoded = JWT::decode($token, new Key($publicKey, $config['algorithms']));
        $token = json_decode(json_encode($decoded), true);
        if ($config['is_single_device']) {
            CacheHandler::verifyToken($config['cache_token_pre'], (string)$token['extend']['id'], self::getRealIp());
        }
        return $token;
    }

    /**
     * 生成令牌
     * @param array $payload 载荷信息
     * @param string $secretKey 签名key
     * @param string $algorithms 算法
     * @return string
     */
    private static function makeToken(array $payload, string $secretKey, string $algorithms): string
    {
        return JWT::encode($payload, $secretKey, $algorithms);
    }

    /**
     * 获取加密载体
     * @param array $config 配置文件
     * @param array $extend 扩展加密字段
     * @return array
     */
    private static function generatePayload(array $config, array $extend): array
    {
        if ($config['is_single_device']) {
            CacheHandler::generateToken([
                'uid'              => $extend['uid'],
                'ip'              => self::getRealIp(),
                'extend'          => json_encode($extend),
                'cache_token_ttl' => $config['cache_token_ttl'],
                'cache_token_pre' => $config['cache_token_pre']
            ]);
        }
        $basePayload = [
            'iss'    => $config['iss'],
            'iat'    => time(),
            'exp'    => time() + $config['access_exp'],
            'extend' => $extend
        ];
        $resPayLoad['accessPayload'] = $basePayload;
        $basePayload['exp'] = time() + $config['refresh_exp'];
        $resPayLoad['refreshPayload'] = $basePayload;

        return $resPayLoad;
    }

    /**
     * 根据签名算法获取【公钥】签名值
     * @param string $algorithm 算法
     * @param int $tokenType 类型
     * @return string
     * @throws JwtConfigException
     */
    private static function getPublicKey(string $algorithm, int $tokenType = self::ACCESS_TOKEN): string
    {
        $config = self::_getConfig();
        switch ($algorithm) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_public_key'] : $config['refresh_public_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }

        return $key;
    }

    /**
     * 根据签名算法获取【私钥】签名值
     * @param array $config 配置文件
     * @param int $tokenType 令牌类型
     * @return string
     */
    private static function getPrivateKey(array $config, int $tokenType = self::ACCESS_TOKEN): string
    {
        switch ($config['algorithms']) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_private_key'] : $config['refresh_private_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }

        return $key;
    }

    /**
     * 获取配置文件
     * @return array
     * @throws JwtConfigException
     */
    private static function _getConfig(): array
    {
        $config = config('jwt.jwt');
        if (empty($config)) {
            throw new JwtConfigException('jwt配置文件不存在');
        }
        return $config;
    }
}
