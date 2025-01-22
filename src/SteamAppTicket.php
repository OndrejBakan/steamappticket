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

    private $stream;

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
        $ticket = hex2bin($ticket);

        $this->stream = new ByteBuffer($ticket);

        if ($this->stream->readUint32() === 20) {
            $this->authTicket = substr($ticket, $this->stream->position() - 4, 52);
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
                throw new Exception('Invalid app ticket format.');
            }
        } else {
            $this->stream->seek(-4, SEEK_CUR);
        }

        $ownershipTicketOffset = $this->stream->position();
        $ownershipTicketLength = $this->stream->readUint32();

        if ($ownershipTicketOffset + $ownershipTicketLength != $this->stream->limit()
            && $ownershipTicketOffset + $ownershipTicketLength + 128 != $this->stream->limit()
        ) {
            throw new Exception('Invalid app ticket format.');
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
            $this->signature = substr($ticket, $this->stream->position(), 128);
        }

        openssl_verify(substr($ticket, $ownershipTicketOffset, $ownershipTicketLength), $this->signature, self::STEAM_PUBLIC_KEY, OPENSSL_ALGO_SHA1) === 1
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

    public static function parse($ticket, bool $allowInvalidSignature = true): SteamAppTicket
    {
        return new SteamAppTicket($ticket, $allowInvalidSignature);
    }

}
