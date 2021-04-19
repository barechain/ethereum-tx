<?php

namespace Barechain\EthereumTx;

use {ArrayAccess, InvalidArgumentException, RuntimeException};
use Barechain\RLP\RLP;
use Elliptic\EC;
use Elliptic\EC\KeyPair;

class Transaction implements ArrayAccess
{
    private string $nonce;
    private string $gasPrice;
    private string $gasLimit;
    private ?string $to;
    private string $value;
    private string $data;
    private string $v;
    private string $r;
    private string $s;

    protected RLP $rlp;
    protected EC $ec;

    /**
     * Transaction constructor
     *
     * @param array $txData
     */
    public function __construct(array $txData = [])
    {
        $this->initDependencies();

        foreach ($txData as $key => $data) {
            $this->offsetSet($key, $data);
        }
    }

    public function __get(string $name)
    {
        $method = 'get' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], []);
        }
    }

    public function __set(string $name, $value)
    {
        $method = 'set' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], [$value]);
        }
    }

    public function __toString(): string
    {
        return '';
//        return $this->hash(false);
    }

    public function offsetExists($offset): bool
    {

    }

    public function offsetGet($offset)
    {

    }

    public function offsetSet($offset, $value)
    {

    }

    public function offsetUnset($offset): void
    {

    }

    /**
     * Instantiate transaction from the serialized tx
     *
     * @param string $serializedTx
     * @return static
     */
    public static function fromSerializedTx(string $serializedTx): self
    {
        $values = (new RLP())->decode($serializedTx);

        if (!is_array($values)) {
            throw new RuntimeException('Invalid serialized tx input. Must be array.');
        }

        if (count($values) !== 6 && count($values) !== 9) {
            throw new RuntimeException(
                'Invalid transaction. Only expecting 6 values (for unsigned tx) or 9 values (for signed tx).'
            );
        }

        $txData = array_combine(
            ['nonce', 'gasPrice', 'gasLimit', 'to', 'value', 'data', 'v', 'r', 's'],
            array_pad($values, 9, null)
        );

        return new self($txData);
    }

    /**
     * Init classes
     */
    private function initDependencies()
    {
        $this->rlp = new RLP();
        $this->ec = new EC('secp256k1');
    }
}