<?php

namespace OndrejBakan\SteamAppTicket;

class DLC
{
    public function __construct(
        public int $appID,
        public array $licenses
    ) {
    }
}
