<?php

use PHPUnit\Framework\TestCase;

class SteamAppTicketTest extends TestCase
{
    public function testValidTicket()
    {
        $ticket = OndrejBakan\SteamAppTicket\SteamAppTicket::parse("");
        $this->assertInstanceOf(OndrejBakan\SteamAppTicket\SteamAppTicket::class, $ticket);
        $this->assertEquals(76561198028859166, $ticket->steamID->getSteamID64());
    }

    public function testInvalidTicket()
    {
        $ticket = OndrejBakan\SteamAppTicket\SteamAppTicket::parse("");
        $this->assertFalse($ticket);
    }

    public function testInvalidTicketLength()
    {
        $ticket = \OndrejBakan\SteamAppTicket\SteamAppTicket::parse("");
        $this->assertFalse($ticket);
    }
}