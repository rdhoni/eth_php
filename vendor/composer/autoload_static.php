<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitd2b2cd4d9fadbd87956947654ebf93b0
{
    public static $files = array (
        '0e6d7bf4a5811bfa5cf40c5ccd6fae6a' => __DIR__ . '/..' . '/symfony/polyfill-mbstring/bootstrap.php',
    );

    public static $prefixLengthsPsr4 = array (
        'k' => 
        array (
            'kornrunner\\' => 11,
        ),
        'S' => 
        array (
            'Symfony\\Polyfill\\Mbstring\\' => 26,
            'Symfony\\Component\\Dotenv\\' => 25,
            'Sop\\CryptoTypes\\' => 16,
            'Sop\\CryptoEncoding\\' => 19,
            'Sop\\ASN1\\' => 9,
        ),
        'R' => 
        array (
            'Rdhoni\\EthPhp\\' => 14,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'kornrunner\\' => 
        array (
            0 => __DIR__ . '/..' . '/kornrunner/keccak/src',
        ),
        'Symfony\\Polyfill\\Mbstring\\' => 
        array (
            0 => __DIR__ . '/..' . '/symfony/polyfill-mbstring',
        ),
        'Symfony\\Component\\Dotenv\\' => 
        array (
            0 => __DIR__ . '/..' . '/symfony/dotenv',
        ),
        'Sop\\CryptoTypes\\' => 
        array (
            0 => __DIR__ . '/..' . '/sop/crypto-types/lib/CryptoTypes',
        ),
        'Sop\\CryptoEncoding\\' => 
        array (
            0 => __DIR__ . '/..' . '/sop/crypto-encoding/lib/CryptoEncoding',
        ),
        'Sop\\ASN1\\' => 
        array (
            0 => __DIR__ . '/..' . '/sop/asn1/lib/ASN1',
        ),
        'Rdhoni\\EthPhp\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitd2b2cd4d9fadbd87956947654ebf93b0::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitd2b2cd4d9fadbd87956947654ebf93b0::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitd2b2cd4d9fadbd87956947654ebf93b0::$classMap;

        }, null, ClassLoader::class);
    }
}
