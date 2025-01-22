<?php

use PHPUnit\Framework\TestCase;

class SteamAppTicketTest extends TestCase
{
    public function test()
    {
        $ticket = OndrejBakan\SteamAppTicket\SteamAppTicket::parse();
        var_dump($ticket->steamID->getSteamID64());
        $this->assertInstanceOf(OndrejBakan\SteamAppTicket\SteamAppTicket::class, $ticket);
    }
}