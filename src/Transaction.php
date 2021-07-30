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
    private ?string $data;
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

        $this->validate($txData);
        $txData = $this->prepareFields($txData);
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
     * @return string
     */
    public function hash(): string
    {
        $serializedTx = $this->serialize();
        $hash = $this->utils->sha3(hex2bin($serializedTx));

        return $this->utils->append0xPrefix($hash);
    }

    /**
     * Get tx hash
     *
     * @return string
     */
    public function __toString(): string
    {
        return $this->hash();
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
        return $this->rlp->encode($this->raw())->__toString();
    }

    /**
     * Sign tx with given hex encoded private key
     *
     * @param string $privateKey
     * @return string
     */
    public function sign(string $privateKey): string
    {
        $signature = $this->utils->ecSign($privateKey, $this->getMessageToSign());

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
     * Validate fields
     *
     * @param array $txData
     */
    private function validate(array $txData): void
    {
        $required = array_slice(self::TX_FIELDS, 0, 5);

        foreach (self::TX_FIELDS as $field) {
            if (!isset($txData[$field]) && in_array($field, $required)) {
                throw new \RuntimeException("Field '{$field}' is required");
            }

            if (!isset($txData[$field])) {
                continue;
            }

            $value = $txData[$field];

            if (!is_string($value)) {
                throw new \RuntimeException("Field '{$field}' must be a string");
            }

            if (strlen($value) > 0 && $value !== '0x' && !$this->utils->isHex($value)) {
                throw new \RuntimeException("Field '{$field}' must be a hex");
            }
        }
    }

    /**
     * Prepare fields
     *
     * @param array $txData
     * @return array
     */
    private function prepareFields(array $txData): array
    {
        $fields = [];

        foreach (self::TX_FIELDS as $field) {
            $value = $txData[$field] ?? '';

            if (in_array($field, ['r', 's'])) {
                $value = $this->utils->zeroLeftPad($value, 64);
            }

            $fields[$field] = $this->utils->append0xPrefix($value);
        }

        return $fields;
    }

    /**
     * Setup fields
     *
     * @param array $txData
     */
    private function setupFields(array $txData): void
    {
        $this->nonce = $this->utils->isEmptyHex($txData['nonce']) ? '0x' : $txData['nonce'];
        $this->gasPrice = $this->utils->isEmptyHex($txData['gasPrice']) ? '0x' : $txData['gasPrice'];
        $this->gasLimit = $this->utils->isEmptyHex($txData['gasLimit']) ? '0x' : $txData['gasLimit'];
        $this->to = $this->utils->isEmptyHex($txData['to']) ? null : $txData['to'];
        $this->value = $this->utils->isEmptyHex($txData['value']) ? '0x' : $txData['value'];
        $this->data = $this->utils->isEmptyHex($txData['data']) ? null : $txData['data'];
        $this->v = $this->utils->isEmptyHex($txData['v']) ? null : $txData['v'];
        $this->r = $this->utils->isEmptyHex($txData['r']) ? null : $txData['r'];
        $this->s = $this->utils->isEmptyHex($txData['s']) ? null : $txData['s'];
    }

    /**
     * Get raw tx fields
     *
     * @return array
     */
    private function raw(): array
    {
        return [
            ($this->nonce === '0x') ? null : $this->nonce,
            ($this->gasPrice === '0x') ? null : $this->gasPrice,
            ($this->gasLimit === '0x') ? null : $this->gasLimit,
            $this->to,
            ($this->value === '0x') ? null : $this->value,
            $this->data,
            $this->v,
            empty($this->r) ? null : $this->utils->append0xPrefix(gmp_strval($this->r, 16)),
            empty($this->s) ? null : $this->utils->append0xPrefix(gmp_strval($this->s, 16))
        ];
    }

    /**
     * Returns the serialized unsigned tx
     *
     * @return string
     */
    private function getMessageToSign(): string
    {
        $message = array_slice($this->raw(), 0, 6);

        if ($this->implementsEIP155()) {
            $message[] = $this->chainId;
            $message[] = null;
            $message[] = null;
        }

        $serializedMessage = $this->rlp->encode($message)->__toString();

        return $this->utils->sha3(hex2bin($serializedMessage));
    }

    /**
     * Check if raw tx is implement EIP155
     *
     * @return bool
     */
    private function implementsEIP155(): bool
    {
        if (!$this->isSigned()) {
            return true;
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
                $this->getMessageToSign(),
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
        return $this->implementsEIP155() ? $v - (2 * $this->chainId + 35) : ($v - 27);
    }
}