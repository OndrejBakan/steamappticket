<?php

namespace OndrejBakan\SteamAppTicket;

use DateTime;
use Exception;
use OndrejBakan\ByteBuffer\ByteBuffer;
use SteamID\SteamID;

class SteamAppTicket
{
    public const STEAM_PUBLIC_KEY = <<<EOD
    -----BEGIN PUBLIC KEY-----
    MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T
    2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY
    gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6
    6WOiu4gZKODnFMBCiQIBEQ==
    -----END PUBLIC KEY-----
    EOD;

    private $ticket;
    private $stream;

    private $ownershipTicketOffset;
    private $ownershipTicketLength;

    public $authTicket;
    public $gcToken;
    public $tokenGenerated;
    public $sessionHeader;
    public $sessionExternalIP;
    public $clientConnectionTime;
    public $clientConnectionCount;

    public $version;
    public $steamID;
    public $appID;

    public $ownershipTicketExternalIP;
    public $ownershipTicketInternalIP;
    public $ownershipFlags;
    public $ownershipTicketGenerated;
    public $ownershipTicketExpires;

    public $licenses;
    public $dlcs;

    public $signature;

    public function __construct($ticket, bool $allowInvalidSignature = false)
    {
        $this->ticket = hex2bin($ticket);
        if ($this->ticket === false) {
            throw new Exception('Invalid ticket format.');
        }

        $this->stream = new ByteBuffer($this->ticket);

        if ($this->stream->readUint32() === 20) {
            $this->authTicket = substr($this->ticket, $this->stream->position() - 4, 52);
            $this->gcToken = $this->stream->readUint64();
            $this->stream->skip(8); // SteamID
            $this->tokenGenerated = $this->stream->readUint32();
            $this->sessionHeader = $this->stream->readUint32();
            $this->stream->skip(4); // unknown 1
            $this->stream->skip(4); // unknown 2
            $this->sessionExternalIP = long2ip($this->stream->readUint32());
            $this->stream->skip(4); // filler
            $this->clientConnectionTime = $this->stream->readUint32();
            $this->clientConnectionCount = $this->stream->readUint32();

            if ($this->stream->readUint32() + $this->stream->position() != $this->stream->limit()) {
                throw new Exception('Invalid ticket format.');
            }
        } else {
            $this->stream->seek(-4, SEEK_CUR);
        }

        $this->ownershipTicketOffset = $this->stream->position();
        $this->ownershipTicketLength = $this->stream->readUint32();

        if ($this->ownershipTicketOffset + $this->ownershipTicketLength != $this->stream->limit() &&
            $this->ownershipTicketOffset + $this->ownershipTicketLength + 128 != $this->stream->limit()
        ) {
            throw new Exception('Invalid ticket format.');
        }

        $this->version = $this->stream->readUint32();
        $this->steamID = new SteamID($this->stream->readUint64());
        $this->appID = $this->stream->readUint32();

        $this->ownershipTicketExternalIP = long2ip($this->stream->readUint32());
        $this->ownershipTicketInternalIP = long2ip($this->stream->readUint32());
        $this->ownershipFlags = $this->stream->readUint32();
        $this->ownershipTicketGenerated = (new DateTime())->setTimestamp($this->stream->readUint32());
        $this->ownershipTicketExpires = (new DateTime())->setTimestamp($this->stream->readUint32());

        $this->parseLicenses();
        $this->parseDLCs();

        $this->stream->skip(2);

        if ($this->stream->position() + 128 === $this->stream->limit()) {
            $this->signature = substr($this->ticket, $this->stream->position(), 128);
        }

        $this->validate()
            || $allowInvalidSignature
            || throw new Exception('Invalid app ticket signature.');
    }

    private function parseDLCs(): void
    {
        $this->dlcs = [];
        $dlcsCount = $this->stream->readUint16();

        for ($i = 0; $i < $dlcsCount; $i++) {
            $appID = $this->stream->readUint32();
            $licensesCount = $this->stream->readUint16();
            $licenses = [];

            for ($j = 0; $j < $licensesCount; $j++) {
                $licenses[] = $this->stream->readUint32();
            }

            $this->dlcs[] = new DLC($appID, $licenses);
        }
    }

    private function parseLicenses(): void
    {
        $this->licenses = [];
        $licensesCount = $this->stream->readUint16();

        for ($i = 0; $i < $licensesCount; $i++) {
            $this->licenses[] = $this->stream->readUint32();
        }
    }

    public static function parse($ticket, bool $allowInvalidSignature = false): SteamAppTicket|false
    {
        try {
            return new SteamAppTicket($ticket, $allowInvalidSignature);
        } catch (Exception $e) {
            return false;
        }
    }

    public function validate(): bool
    {
        return (bool) $this->signature && openssl_verify(substr($this->ticket, $this->ownershipTicketOffset, $this->ownershipTicketLength), $this->signature, self::STEAM_PUBLIC_KEY, OPENSSL_ALGO_SHA1) === 1;
    }
}
