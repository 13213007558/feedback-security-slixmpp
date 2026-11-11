"""
Replayable demo: what slixmpp's XEP-0045 layer actually tells an audit
consumer about occupant identity, in three event chains.

Run:  python -m unittest audit_muc_identity_demo -v
"""
import unittest
from slixmpp import JID
from slixmpp.test import SlixTest

ROOM = 'darkcave@muc.example.com'


class AuditRecorder:
    """What a naive audit backend keyed on (room, nick) would see."""

    def __init__(self, xmpp, room):
        self.log = []
        self.xmpp = xmpp
        self.room = room
        for ev in ('got_online', 'got_offline', 'presence', 'self-presence'):
            xmpp.add_event_handler('muc::%s::%s' % (room, ev),
                                   lambda p, ev=ev: self.record(ev, p))
        xmpp.add_event_handler('groupchat_message', self.record_msg)

    def record(self, ev, p):
        muc = p['muc']
        item = muc['item']
        self.log.append({
            'event': ev,
            'occupant': str(p['from']),           # room JID + nick  (always known)
            'type': p['type'] or 'available',
            'codes': sorted(muc['status_codes']),
            'item_jid': str(item['jid'] or ''),   # real JID (only if room reveals it)
            'item_nick': item['nick'],            # new nick on 303, else ''
            'actor': str(muc['item']['actor']['jid'] or ''),
        })

    def record_msg(self, m):
        self.log.append({
            'event': 'message',
            'occupant': str(m['from']),
            'item_jid': str(m['muc']['item']['jid'] or ''),  # always '' here
            'body': m['body'],
        })

    def dump(self, title):
        print('\n=== %s ===' % title)
        for row in self.log:
            print('  %s' % row)
        rooms = self.xmpp.plugin['xep_0045'].rooms[JID(ROOM)]
        print('  plugin.rooms[%s] keys -> %s' % (ROOM, list(rooms)))
        for nick, entry in rooms.items():
            print('    %-8s jid=%r affiliation=%s role=%s alt_nick=%r'
                  % (nick, str(entry.get('jid') or ''), entry.get('affiliation'),
                     entry.get('role'), entry.get('alt_nick')))


class TestMucIdentity(SlixTest):
    def setUp(self):
        self.stream_start(jid='tester@localhost/auditbot',
                          plugins={'xep_0045'})
        self.muc = self.xmpp.plugin['xep_0045']
        # pretend join_muc_wait() already ran
        self.muc.rooms[JID(ROOM)] = {}
        self.muc.our_nicks[JID(ROOM)] = 'auditbot'
        self.audit = AuditRecorder(self.xmpp, ROOM)

    def tearDown(self):
        self.stream_close()

    def test_scenario_1_nick_change_303_anonymous_room(self):
        """Same human changes nick alice -> alice_ in an anonymous room."""
        self.recv("""
          <presence from='%s/alice' to='tester@localhost/auditbot'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='member' role='participant'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <presence from='%s/alice' type='unavailable'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='member' role='none' nick='alice_'/>
              <status code='303'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <presence from='%s/alice_'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='member' role='participant'/>
            </x>
          </presence>""" % ROOM)
        self.audit.dump('S1: 303 nick change, anonymous room')
        # The library emits got_offline(alice) + got_online(alice_):
        # indistinguishable from a leave+join without reading code 303.
        events = [r['event'] for r in self.audit.log]
        self.assertEqual(events, ['presence', 'got_online',
                                  'presence', 'got_offline',
                                  'presence', 'got_online'])
        # Old nick entry is gone; nothing in rooms[] links alice_ to alice.
        self.assertNotIn('alice', self.muc.rooms[JID(ROOM)])
        self.assertIn('alice_', self.muc.rooms[JID(ROOM)])
        self.assertFalse(self.muc.rooms[JID(ROOM)]['alice_'].get('jid'))

    def test_scenario_2_kick_307_then_nick_reuse(self):
        """bob is kicked; a DIFFERENT human later joins as bob. Anonymous room."""
        self.recv("""
          <presence from='%s/bob'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='none' role='participant'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <presence from='%s/bob' type='unavailable'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='none' role='none'>
                <actor jid='mod@example.com'/>
              </item>
              <status code='307'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <presence from='%s/bob'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='none' role='participant'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <message from='%s/bob' type='groupchat'>
            <body>hi, I am the second bob</body>
          </message>""" % ROOM)
        self.audit.dump('S2: kick 307 + nick reuse, anonymous room')
        # Event shape is IDENTICAL to S1 (offline+online for one nick).
        # Only the status code differs (307 vs 303), and 307 says nothing
        # about who the next 'bob' is.
        events = [r['event'] for r in self.audit.log]
        self.assertEqual(events, ['presence', 'got_online',
                                  'presence', 'got_offline',
                                  'presence', 'got_online',
                                  'message'])
        msg = self.audit.log[-1]
        self.assertEqual(msg['item_jid'], '')   # messages never carry real JID

    def test_scenario_3_nonanonymous_self_presence(self):
        """Non-anonymous room: real JIDs arrive in presence items; 110 marks self."""
        self.recv("""
          <presence from='%s/auditbot'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='member' role='participant'
                    jid='tester@localhost/auditbot'/>
              <status code='110'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <presence from='%s/carol'>
            <x xmlns='http://jabber.org/protocol/muc#user'>
              <item affiliation='owner' role='moderator'
                    jid='carol@example.com/phone'/>
            </x>
          </presence>""" % ROOM)
        self.recv("""
          <message from='%s/carol' type='groupchat'>
            <body>hello audit</body>
          </message>""" % ROOM)
        self.audit.dump('S3: non-anonymous room, self-presence 110')
        kinds = [r['event'] for r in self.audit.log]
        self.assertIn('self-presence', kinds)
        carol = self.muc.rooms[JID(ROOM)]['carol']
        self.assertEqual(str(carol['jid']), 'carol@example.com/phone')
        # Message itself still carries no real JID: correlation happens
        # only via the presence cache, keyed by nick, at message time.
        self.assertEqual(self.audit.log[-1]['item_jid'], '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
