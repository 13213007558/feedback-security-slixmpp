import unittest

from slixmpp import ComponentXMPP, Iq, Message
from slixmpp.roster import RosterItem
from slixmpp.test import SlixTest


class TestPermissions(SlixTest):
    def setUp(self):
        self.stream_start(
            mode="component",
            plugins=["xep_0356"],
            jid="pubsub.capulet.lit",
            server="capulet.net",
        )

    def testPluginEnd(self):
        exc = False
        try:
            self.xmpp.plugin.disable("xep_0356")
        except Exception as e:
            exc = True
        self.assertFalse(exc)

    def testGrantedPrivileges(self):
        # https://xmpp.org/extensions/xep-0356.html#example-4
        results = {"event": False}
        self.xmpp.add_event_handler(
            "privileges_advertised", lambda msg: results.__setitem__("event", True)
        )
        self.recv(
            """
            <message from='capulet.net' to='pubub.capulet.lit' id='54321'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='both'/>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(self.xmpp["xep_0356"].granted_privileges["roster"], "both")
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges["message"], "outgoing"
        )
        self.assertEqual(self.xmpp["xep_0356"].granted_privileges["presence"], "none")
        self.assertTrue(results["event"])

    def testGetRosterIq(self):
        iq = self.xmpp["xep_0356"]._make_get_roster("juliet@example.com")
        xmlstring = """
        <iq xmlns="jabber:component:accept"
            id='1'
            from='pubsub.capulet.lit'
            to='juliet@example.com'
            type='get'>
                <query xmlns='jabber:iq:roster'/>
        </iq>
        """
        self.check(iq, xmlstring, use_values=False)

    def testSetRosterIq(self):
        jid = "juliet@example.com"
        items = {
            "friend1@example.com": {
                "name": "Friend 1",
                "subscription": "both",
                "groups": ["group1", "group2"],
            },
            "friend2@example.com": {
                "name": "Friend 2",
                "subscription": "from",
                "groups": ["group3"],
            },
        }
        iq = self.xmpp["xep_0356"]._make_set_roster(jid, items)
        xmlstring = f"""
        <iq xmlns="jabber:component:accept"
            id='1'
            from='pubsub.capulet.lit'
            to='{jid}'
            type='set'>
                <query xmlns='jabber:iq:roster'>
                    <item name='Friend 1' jid='friend1@example.com' subscription='both'>
                        <group>group1</group>
                        <group>group2</group>
                    </item>
                    <item name='Friend 2' jid='friend2@example.com' subscription='from'>
                        <group>group3</group>
                    </item>
                </query>
        </iq>
        """
        self.check(iq, xmlstring, use_values=False)

    def testMakeOutgoingMessage(self):
        xmlstring = """
        <message xmlns="jabber:component:accept" from='pubsub.capulet.lit' to='capulet.net'>
            <privilege xmlns='urn:xmpp:privilege:2'>
                <forwarded xmlns='urn:xmpp:forward:0'>
                    <message from="juliet@capulet.lit" to="romeo@montague.lit" xmlns="jabber:client">
                        <body>I do not hate you</body>
                    </message>
                </forwarded>
            </privilege>
        </message>
        """
        msg = Message()
        msg["from"] = "juliet@capulet.lit"
        msg["to"] = "romeo@montague.lit"
        msg["body"] = "I do not hate you"

        priv_msg = self.xmpp["xep_0356"]._make_privileged_message(msg)
        self.check(priv_msg, xmlstring, use_values=False)

    def _make_user_msg(self):
        msg = Message()
        msg["from"] = "juliet@capulet.lit"
        msg["to"] = "romeo@montague.lit"
        msg["body"] = "I do not hate you"
        return msg

    def testForgedPrivilegeFromUserIgnored(self):
        """A privilege advertisement from a normal user must not grant anything."""
        results = {"event": False}
        self.xmpp.add_event_handler(
            "privileges_advertised", lambda msg: results.__setitem__("event", True)
        )
        self.recv(
            """
            <message from='juliet@capulet.lit' to='pubsub.capulet.lit' id='666'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='both'/>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges,
            {"roster": "none", "message": "none", "presence": "none"},
        )
        self.assertFalse(results["event"])

    def testForgedPrivilegeFromOtherServerIgnored(self):
        """A privilege advertisement from another server must not grant anything."""
        self.recv(
            """
            <message from='evil.montague.lit' to='pubsub.capulet.lit' id='666'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='both'/>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges,
            {"roster": "none", "message": "none", "presence": "none"},
        )

    def testPrivilegeAdvertisementReplacesPrevious(self):
        """Each advertisement is the complete set: unlisted perms fall to none."""
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='1'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='both'/>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(self.xmpp["xep_0356"].granted_privileges["message"], "outgoing")
        # Downgrade: the server now only grants roster get.
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='2'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='get'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges,
            {"roster": "get", "message": "none", "presence": "none"},
        )

    def testUnknownPermValuesIgnored(self):
        """Unknown access types and values must not be stored."""
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='1'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='admin'/>
                    <perm access='superuser' type='both'/>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges,
            {"roster": "none", "message": "outgoing", "presence": "none"},
        )

    def testSendPrivilegedMessageUnauthorized(self):
        """Without a grant, sending must fail observably and send nothing."""
        with self.assertRaises(ValueError):
            self.xmpp["xep_0356"].send_privileged_message(self._make_user_msg())
        self.send(None)

    def testRosterUnauthorized(self):
        """Without a grant, roster operations must fail observably."""
        items = {"friend1@example.com": {"name": "Friend 1"}}
        with self.assertRaises(ValueError):
            self.run_coro(self.xmpp["xep_0356"].get_roster("juliet@capulet.lit"))
        with self.assertRaises(ValueError):
            self.run_coro(
                self.xmpp["xep_0356"].set_roster("juliet@capulet.lit", items)
            )
        self.send(None)

    def testGetRosterGranted(self):
        """A granted roster=get permission lets the iq through."""
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='1'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='get'/>
                </privilege>
            </message>
            """
        )
        results = {}

        async def run():
            results["roster"] = await self.xmpp["xep_0356"].get_roster(
                "juliet@capulet.lit"
            )

        test_run = self.xmpp.wrap(run())
        self.wait_()
        self.send(
            """
            <iq xmlns="jabber:component:accept"
                id='1'
                from='pubsub.capulet.lit'
                to='juliet@capulet.lit'
                type='get'>
                <query xmlns='jabber:iq:roster'/>
            </iq>
            """,
            use_values=False,
        )
        self.recv(
            """
            <iq xmlns="jabber:component:accept"
                id='1'
                from='juliet@capulet.lit'
                to='pubsub.capulet.lit'
                type='result'>
                <query xmlns='jabber:iq:roster'>
                    <item jid='romeo@montague.lit' subscription='both'/>
                </query>
            </iq>
            """
        )
        self.run_coro(test_run)
        self.assertEqual(
            list(results["roster"]["roster"]["items"].keys()), ["romeo@montague.lit"]
        )
        # roster=get does not allow set_roster
        with self.assertRaises(ValueError):
            self.run_coro(
                self.xmpp["xep_0356"].set_roster("juliet@capulet.lit", {})
            )

    def testDisconnectResetsPrivileges(self):
        """Privileges do not survive a reconnection."""
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='1'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='both'/>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges["message"], "outgoing"
        )
        self.xmpp.event("disconnected")
        self.assertEqual(
            self.xmpp["xep_0356"].granted_privileges,
            {"roster": "none", "message": "none", "presence": "none"},
        )
        with self.assertRaises(ValueError):
            self.xmpp["xep_0356"].send_privileged_message(self._make_user_msg())
        self.send(None)

    def testPrivilegeLifecycleOffline(self):
        """
        Chain a forged grant, a legit grant, a downgrade and a reconnect,
        and check which privileged stanzas actually go out.
        """
        plugin = self.xmpp["xep_0356"]

        # 1. A user forges a grant: nothing must be granted or sent.
        self.recv(
            """
            <message from='juliet@capulet.lit' to='pubsub.capulet.lit' id='f1'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        with self.assertRaises(ValueError):
            plugin.send_privileged_message(self._make_user_msg())
        self.send(None)

        # 2. The server grants message=outgoing: the privileged stanza goes out.
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='s1'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='message' type='outgoing'/>
                </privilege>
            </message>
            """
        )
        plugin.send_privileged_message(self._make_user_msg())
        self.send(
            """
            <message xmlns="jabber:component:accept"
                     from='pubsub.capulet.lit' to='capulet.net'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <forwarded xmlns='urn:xmpp:forward:0'>
                        <message from="juliet@capulet.lit" to="romeo@montague.lit"
                                 xmlns="jabber:client">
                            <body>I do not hate you</body>
                        </message>
                    </forwarded>
                </privilege>
            </message>
            """,
            use_values=False,
        )

        # 3. The server downgrades to roster=get only: message is revoked.
        self.recv(
            """
            <message from='capulet.net' to='pubsub.capulet.lit' id='s2'>
                <privilege xmlns='urn:xmpp:privilege:2'>
                    <perm access='roster' type='get'/>
                </privilege>
            </message>
            """
        )
        with self.assertRaises(ValueError):
            plugin.send_privileged_message(self._make_user_msg())
        self.send(None)
        # ...while the roster entry point now works.
        test_run = self.xmpp.wrap(plugin.get_roster("juliet@capulet.lit"))
        self.wait_()
        self.send(
            """
            <iq xmlns="jabber:component:accept"
                id='1'
                from='pubsub.capulet.lit'
                to='juliet@capulet.lit'
                type='get'>
                <query xmlns='jabber:iq:roster'/>
            </iq>
            """,
            use_values=False,
        )
        self.recv(
            """
            <iq xmlns="jabber:component:accept"
                id='1'
                from='juliet@capulet.lit'
                to='pubsub.capulet.lit'
                type='result'>
                <query xmlns='jabber:iq:roster'/>
            </iq>
            """
        )
        self.run_coro(test_run)

        # 4. Reconnection wipes the remaining grants.
        self.xmpp.event("disconnected")
        with self.assertRaises(ValueError):
            plugin.send_privileged_message(self._make_user_msg())
        with self.assertRaises(ValueError):
            self.run_coro(plugin.get_roster("juliet@capulet.lit"))
        self.send(None)


suite = unittest.TestLoader().loadTestsFromTestCase(TestPermissions)
