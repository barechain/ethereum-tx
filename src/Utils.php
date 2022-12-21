<?php

namespace Barechain\EthereumTx;

use Elliptic\EC;
use Elliptic\EC\Signature;
use kornrunner\Keccak;

class Utils
{
    private const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    protected EC $secp256k1;

    /**
     * Utils constructor
     */
    public function __construct()
    {
        $this->secp256k1 = new EC('secp256k1');
    }

    /**
     * Check if value is hex string
     *
     * @param string $value
     * @return bool
     */
    public function isHex(string $value): bool
    {
        return preg_match('/^(0x)?[a-fA-F0-9]+$/', $value) === 1;
    }

    /**
     * Check if value has 0x prefix
     *
     * @param string $value
     * @return bool
     */
    public function is0xPrefix(string $value): bool
    {
        return strpos($value, '0x') === 0;
    }

    /**
     * Strip 0x prefix
     *
     * @param string $value
     * @return string
     */
    public function strip0xPrefix(string $value): string
    {
        if (!$this->is0xPrefix($value)) {
            return $value;
        }

        return preg_replace('/^0x/', '', $value);
    }

    /**
     * Append 0x prefix
     *
     * @param string $value
     * @return string
     */
    public function append0xPrefix(string $value): string
    {
        if ($this->is0xPrefix($value)) {
            return $value;
        }

        return empty($value) ? '0x0' : '0x' . $value;
    }

    /**
     * Check if value is empty hex
     *
     * @param string $value
     * @return bool
     */
    public function isEmptyHex(string $value): bool
    {
        return $value === '0x' || gmp_strval($value) === '0';
    }

    /**
     * Zero string left pad
     *
     * @param string $value
     * @param int $length
     * @return string
     */
    public function zeroLeftPad(string $value, int $length): string
    {
        return str_pad($value, $length, 0, STR_PAD_LEFT);
    }

    /**
     * Get sha3 hash
     *
     * @param string $value
     * @return string
     */
    public function sha3(string $value): string
    {
        try {
            $hash = Keccak::hash($value, 256);

            if ($hash === self::SHA3_NULL_HASH) {
                return '';
            }

            return $hash;
        } catch (\Exception $e) {
            throw new \RuntimeException('Invalid sha3 hash: ' . $e->getMessage());
        }
    }

    /**
     * Recovery publicKey
     *
     * @param string $hash
     * @param string $r
     * @param string $s
     * @param int $v
     * @return string
     */
    public function recoverPublicKey(string $hash, string $r, string $s, int $v): string
    {
        if (!$this->isHex($hash)) {
            throw new \InvalidArgumentException('Invalid hash format.');
        }

        $hash = $this->strip0xPrefix($hash);

        if (!$this->isHex($r) || !$this->isHex($s)) {
            throw new \InvalidArgumentException('Invalid signature format.');
        }

        $r = $this->strip0xPrefix($r);
        $s = $this->strip0xPrefix($s);

        if (strlen($r) !== 64 || strlen($s) !== 64) {
            throw new \InvalidArgumentException('Invalid signature length.');
        }

        try {
            $publicKey = $this->secp256k1->recoverPubKey($hash, [
                'r' => $r,
                's' => $s
            ], $v);

            $publicKey = $publicKey->encode('hex');

            return $this->append0xPrefix($publicKey);
        } catch (\Exception $e) {
            throw new \RuntimeException('Invalid recovery publicKey:' . $e->getMessage());
        }
    }

    /**
     * Convert publicKey to address
     *
     * @param string $publicKey
     * @return string
     */
    public function publicKeyToAddress(string $publicKey): string
    {
        if (!$this->isHex($publicKey)) {
            throw new \InvalidArgumentException('Invalid public key format.');
        }

        $publicKey = $this->strip0xPrefix($publicKey);

        if (strlen($publicKey) !== 130) {
            throw new \InvalidArgumentException('Invalid public key length.');
        }

        $address = substr($this->sha3(substr(hex2bin($publicKey), 1)), 24);

        return $this->append0xPrefix($address);
    }

    /**
     * Ecliptic sign
     *
     * @param string $privateKey
     * @param string $message
     * @return Signature
     */
    public function ecSign(string $privateKey, string $message): Signature
    {
        if (!$this->isHex($privateKey)) {
            throw new \InvalidArgumentException('Invalid private key format.');
        }

        $privateKeyLength = strlen($this->strip0xPrefix($privateKey));

        if ($privateKeyLength !== 64) {
            throw new \InvalidArgumentException('Private key length was wrong.');
        }

        $signature = $this->secp256k1->keyFromPrivate($privateKey, 'hex')->sign($message, [
            'canonical' => true
        ]);

        // Ethereum v is recovery param + 35
        // Or recovery param + 35 + (chain id * 2)
        $signature->recoveryParam += 35;

        return $signature;
    }
}