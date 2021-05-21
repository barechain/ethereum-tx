<?php

namespace Barechain\EthereumTx;

use Barechain\RLP\RLP;

class Transaction
{
    private const TX_FIELDS =  ['nonce', 'gasPrice', 'gasLimit', 'to', 'value', 'data', 'v', 'r', 's'];

    // secp256k1n/2
    private const N_DIV_2 = '0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0';

    private string $nonce;
    private string $gasPrice;
    private string $gasLimit;
    private ?string $to;
    private string $value;
    private string $data;
    private ?string $v;
    private ?string $r;
    private ?string $s;

    private int $chainId;

    private RLP $rlp;
    private Utils $utils;

    /**
     * Transaction constructor
     *
     * @param array $txData
     * @param int $chainId
     */
    public function __construct(array $txData = [], int $chainId = 1)
    {
        $this->initDependencies();

        $this->chainId = $chainId;
        $this->validateRequired($txData);
        $this->setupFields($txData);
    }

    /**
     * Get tx field
     *
     * @param string $name
     * @return mixed
     */
    public function __get(string $name)
    {
        if (!in_array($name, self::TX_FIELDS)) {
            throw new \RuntimeException("Transaction field {$name} not exists");
        }

        return $this->{$name};
    }

    /**
     * Convert to array
     *
     * @return array
     */
    public function toArray(): array
    {
        $txData = [];

        foreach (self::TX_FIELDS as $field) {
            $txData[$field] = $this->{$field};
        }

        return $txData;
    }

    /**
     * Check if tx is signed
     *
     * @return bool
     */
    public function isSigned(): bool
    {
        return $this->v && $this->r && $this->s;
    }

    /**
     * Get tx hash
     *
     * @param bool $signed
     * @return string
     */
    public function hash(bool $signed = false): string
    {
        $txData = $this->toArray();

        $txData['r'] = $this->utils->append0xPrefix(gmp_strval($txData['r'], 16));
        $txData['s'] = $this->utils->append0xPrefix(gmp_strval($txData['s'], 16));

        if (!$signed) {
            unset($txData['v'], $txData['r'], $txData['s']);

            if ($this->signedTxImplementsEIP155()) {
                $txData['v'] = $this->chainId;
                $txData['r'] = '';
                $txData['s'] = '';
            }
        }

        $serializedTx = $this->rlp->encode($txData)->__toString();

        return $this->utils->sha3(hex2bin($serializedTx));
    }

    /**
     * Get tx hash
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->hash($this->isSigned());
    }

    /**
     * Get sender address
     *
     * @return string
     */
    public function getSenderAddress(): string
    {
        return $this->utils->publicKeyToAddress($this->getSenderPublicKey());
    }

    /**
     * Return RLP encode tx
     *
     * @return string
     */
    public function serialize(): string
    {
        $txData = $this->toArray();

        $txData['r'] = $this->utils->append0xPrefix(gmp_strval($txData['r'], 16));
        $txData['s'] = $this->utils->append0xPrefix(gmp_strval($txData['s'], 16));

        if (!$this->isSigned()) {
            unset($txData['v'], $txData['r'], $txData['s']);
        }

        return $this->rlp->encode($txData)->__toString();
    }

    /**
     * Sign tx with given hex encoded private key
     *
     * @param string $privateKey
     * @return string
     */
    public function sign(string $privateKey): string
    {
        $signature = $this->utils->ecSign($privateKey, $this->hash());

        unset($this->v, $this->r, $this->s);

        $this->r = $this->utils->append0xPrefix($signature->r->toString(16));
        $this->s = $this->utils->append0xPrefix($signature->s->toString(16));

        $v = $signature->recoveryParam + $this->chainId * 2;
        $this->v = $this->utils->append0xPrefix(dechex($v));

        return $this->serialize();
    }

    /**
     * Instantiate transaction from the serialized tx
     *
     * @param string $serializedTx
     * @param int $chainId
     * @return static
     */
    public static function fromSerializedTx(string $serializedTx, int $chainId = 1): self
    {
        $values = (new RLP())->decode($serializedTx);

        if (!is_array($values)) {
            throw new \RuntimeException('Invalid serialized tx input. Must be array.');
        }

        if (count($values) !== 6 && count($values) !== 9) {
            throw new \RuntimeException(
                'Invalid transaction. Only expecting 6 values (for unsigned tx) or 9 values (for signed tx).'
            );
        }

        $stringValues = array_map(fn ($item) => $item->__toString(), $values);

        $txData = array_combine(self::TX_FIELDS, array_pad($stringValues, 9, ''));

        return new self($txData);
    }

    /**
     * Init classes
     */
    private function initDependencies()
    {
        $this->rlp = new RLP();
        $this->utils = new Utils();
    }

    /**
     * Setup fields
     *
     * @param array $txData
     */
    private function setupFields(array $txData): void
    {
        $this->nonce = $this->utils->append0xPrefix($txData['nonce']);
        $this->gasPrice = $this->utils->append0xPrefix($txData['gasPrice']);
        $this->gasLimit = $this->utils->append0xPrefix($txData['gasLimit']);
        $this->to = !empty($txData['to']) ? $this->utils->append0xPrefix($txData['to']) : '';

        $this->value = !empty($txData['value']) ? $this->utils->append0xPrefix($txData['value']) : '';

        $this->data = !empty($txData['data']) ? $this->utils->append0xPrefix($txData['data']) : '';

        $this->v = !empty($txData['v']) ? $this->utils->append0xPrefix($txData['v']) : '';

        $this->r = !empty($txData['r']) ?
            $this->utils->append0xPrefix($this->utils->zeroLeftPad($txData['r'], 64)) : '';

        $this->s = !empty($txData['s']) ?
            $this->utils->append0xPrefix($this->utils->zeroLeftPad($txData['s'], 64)) : '';
    }

    /**
     * Validate required fields
     *
     * @param array $txData
     */
    private function validateRequired(array $txData): void
    {
        foreach (['nonce', 'gasPrice', 'gasLimit'] as $field) {
            if (empty($txData[$field])) {
                throw new \RuntimeException("Field {$field} is required");
            }
        }
    }

    /**
     * Check if raw tx is signed and implement EIP155
     *
     * @return bool
     */
    private function signedTxImplementsEIP155(): bool
    {
        if (!$this->isSigned()) {
            throw new \RuntimeException('This transaction is not signed');
        }

        $v = hexdec($this->v);

        // EIP155 spec
        return $v === ($this->chainId * 2 + 35) || $v === ($this->chainId * 2 + 36);
    }

    /**
     * Get sender publicKey
     *
     * @return string
     */
    private function getSenderPublicKey(): string
    {
        if (!$this->isSigned()) {
            throw new \RuntimeException('Missing values to derive sender public key from signed tx');
        }

        // All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid
        if (gmp_cmp($this->s, self::N_DIV_2) === 1) {
            throw new \RuntimeException('Invalid Signature: s-values greater than secp256k1n/2 are considered invalid');
        }

        try {
            return $this->utils->recoverPublicKey(
                $this->hash(),
                $this->r,
                $this->s,
                $this->calculateSigRecovery()
            );
        } catch (\Exception $e) {
            throw new \RuntimeException('Invalid Signature');
        }
    }

    /**
     * Calculate signature recovery
     *
     * @return int
     */
    private function calculateSigRecovery(): int
    {
        $v = hexdec($this->v);
        return $this->signedTxImplementsEIP155() ? $v - (2 * $this->chainId + 35) : ($v - 27);
    }
}