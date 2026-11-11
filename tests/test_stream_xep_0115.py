"""Offline replay tests for XEP-0115 (Entity Capabilities) validation.

These tests drive presence/disco#info exchanges over the mock socket and
observe two distinct data structures:

* the verification-string cache (``xep_0115.cache``), keyed by ``ver`` and
  shared between entities;
* the entity -> verstring mapping (``xep_0115.static.jid_vers``).

The expected verification strings are computed by an independent
implementation of the XEP-0115 canonicalization in :class:`CapsOracle`,
which never imports slixmpp code, so the tests do not judge the plugin by
its own output.
"""
import base64
import hashlib
import unittest

from slixmpp.plugins.xep_0004.stanza import Form, FormField
from slixmpp.test import SlixTest


DISCO_NS = 'http://jabber.org/protocol/disco#info'
CAPS_NS = 'http://jabber.org/protocol/caps'
NODE = 'http://example.test/client'


class CapsOracle:
    """Independent XEP-0115 §5 verification-string implementation."""

    hashes = {'sha-1': hashlib.sha1, 'md5': hashlib.md5}

    @staticmethod
    def canonical_bytes(identities, features, forms):
        # forms: list of (form_type, {field_var: [values]})
        string = ''
        string += '<'.join(
            sorted('/'.join(part or '' for part in identity)
                   for identity in identities)) + '<'
        string += '<'.join(sorted(features)) + '<'

        grouped = {}
        for form_type, fields in forms:
            grouped.setdefault(form_type, []).append(fields)
        for form_type in sorted(grouped):
            for fields in grouped[form_type]:
                string += '%s<' % form_type
                for var in sorted(key for key in fields if key != 'FORM_TYPE'):
                    string += '%s<' % var
                    values = fields[var]
                    if values is None:
                        string += '<'
                    else:
                        if not isinstance(values, list):
                            values = [values]
                        string += '<'.join(sorted(values)) + '<'
        return string.encode('utf-8')

    @classmethod
    def verstring(cls, identities, features, forms=None, hash_name='sha-1'):
        forms = forms or []
        digest = cls.hashes[hash_name](
            cls.canonical_bytes(identities, features, forms)).digest()
        return base64.b64encode(digest).decode('utf-8')


class TestStreamCaps(SlixTest):

    def tearDown(self):
        self.stream_close()

    # -- helpers --------------------------------------------------------

    def start(self):
        self.stream_start(
            mode='client',
            jid='tester@localhost/resource',
            plugins=['xep_0030', 'xep_0004', 'xep_0128', 'xep_0115'])
        self.xmpp.exception = lambda exc: self.fail(
            'unhandled stream exception: %r' % exc)
        self.caps = self.xmpp['xep_0115']

    async def _pump(self, count=20):
        import asyncio
        for _ in range(count):
            await asyncio.sleep(0)

    def pump(self):
        self.run_coro(self._pump())

    def send_caps_presence(self, frm, ver, hash_name='sha-1', node=NODE):
        self.recv("""
          <presence from="%(frm)s">
            <c xmlns="%(caps)s" hash="%(hash)s" node="%(node)s" ver="%(ver)s"/>
          </presence>
        """ % {'frm': frm, 'caps': CAPS_NS, 'hash': hash_name,
               'node': node, 'ver': ver})
        self.pump()
        self.wait_for_send_queue()

    def next_iq_id(self):
        sent = self.xmpp.socket.next_sent(timeout=0.05)
        self.assertIsNotNone(sent, 'expected an outgoing disco query')
        sent = sent.decode()
        self.assertIn('disco#info', sent)
        return sent.split('id="')[1].split('"')[0], sent

    def recv_disco(self, iq_id, frm, ver, body, node=NODE):
        self.recv("""
          <iq type="result" id="%(id)s" from="%(frm)s"
              to="tester@localhost/resource">
            <query xmlns="%(ns)s" node="%(node)s#%(ver)s">
              %(body)s
            </query>
          </iq>
        """ % {'id': iq_id, 'frm': frm, 'ns': DISCO_NS,
               'node': node, 'ver': ver, 'body': body})
        self.pump()

    def assertCached(self, ver):
        self.assertIn(ver, self.caps.cache.cache)

    def assertNotCached(self, ver):
        self.assertNotIn(ver, self.caps.cache.cache)

    def assertMapped(self, jid, ver):
        self.assertEqual(self.caps.static.jid_vers.get(jid), ver)

    def assertNotMapped(self, jid):
        self.assertNotIn(jid, self.caps.static.jid_vers)

    # -- cases ----------------------------------------------------------

    def testValidCapsAreCachedAndMapped(self):
        """A valid presence/disco exchange populates cache and mapping."""
        self.start()
        identities = [('client', 'bot', None, None)]
        features = [DISCO_NS, 'urn:xmpp:ping']
        ver = CapsOracle.verstring(identities, features)
        frm = 'alice@example.com/resource'

        self.send_caps_presence(frm, ver)
        iq_id, sent = self.next_iq_id()
        self.assertIn('node="%s#%s"' % (NODE, ver), sent)

        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
          <feature var="urn:xmpp:ping"/>
        """ % {'ns': DISCO_NS})

        self.assertCached(ver)
        self.assertMapped(frm, ver)
        info = self.run_coro(self.caps.get_caps(verstring=ver))
        self.assertEqual(set(info['features']), set(features))

    def testCanonicalBytesMatchOracle(self):
        """The plugin's verstring must equal the independent oracle."""
        self.start()
        identities = [('client', 'bot', None, None),
                      ('pubsub', 'service', 'en', 'PeP')]
        features = [DISCO_NS, 'urn:xmpp:ping']
        forms = [('urn:xmpp:dataforms:softwareinfo',
                  {'os': ['Mac'], 'name': ['Slix']})]
        ver = CapsOracle.verstring(identities, features, forms)

        info = self.xmpp['xep_0030'].stanza.DiscoInfo()
        for category, itype, lang, name in identities:
            info.add_identity(category, itype, name, lang)
        for feature in features:
            info.add_feature(feature)
        form = self.xmpp['xep_0004'].make_form(ftype='result')
        form.add_field(var='FORM_TYPE', ftype='hidden',
                       value='urn:xmpp:dataforms:softwareinfo')
        form.add_field(var='os', value='Mac')
        form.add_field(var='name', value='Slix')
        info.append(form)

        self.assertEqual(self.caps.generate_verstring(info, 'sha-1'), ver)

    def testReorderedLegalResponseIsAccepted(self):
        """Element ordering is irrelevant: sorting happens in the hash."""
        self.start()
        identities = [('client', 'bot', None, None)]
        features = [DISCO_NS, 'urn:xmpp:ping']
        ver = CapsOracle.verstring(identities, features)
        frm = 'order@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        # features before identity, features in reverse order
        self.recv_disco(iq_id, frm, ver, """
          <feature var="urn:xmpp:ping"/>
          <feature var="%(ns)s"/>
          <identity type="bot" category="client"/>
        """ % {'ns': DISCO_NS})

        self.assertCached(ver)
        self.assertMapped(frm, ver)

    def testDuplicateIdentityIsRejected(self):
        self.start()
        ver = CapsOracle.verstring([('client', 'bot', None, None)], [DISCO_NS])
        frm = 'dup-id@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
        """ % {'ns': DISCO_NS})

        self.assertNotCached(ver)
        self.assertNotMapped(frm)

    def testDuplicateFeatureIsRejected(self):
        self.start()
        ver = CapsOracle.verstring([('client', 'bot', None, None)], [DISCO_NS])
        frm = 'dup-feat@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
          <feature var="%(ns)s"/>
        """ % {'ns': DISCO_NS})

        self.assertNotCached(ver)
        self.assertNotMapped(frm)

    def testDuplicateFormTypeIsRejected(self):
        self.start()
        forms = [('urn:test:ft', {'field1': ['value1']})]
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS], forms)
        frm = 'dup-ft@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
          <x xmlns="jabber:x:data" type="result">
            <field var="FORM_TYPE" type="hidden">
              <value>urn:test:ft</value>
            </field>
            <field var="field1"><value>value1</value></field>
          </x>
          <x xmlns="jabber:x:data" type="result">
            <field var="FORM_TYPE" type="hidden">
              <value>urn:test:ft</value>
            </field>
            <field var="field1"><value>value1</value></field>
          </x>
        """ % {'ns': DISCO_NS})

        self.assertNotCached(ver)
        self.assertNotMapped(frm)

    def testDuplicateFormTypeValuesAreRejected(self):
        self.start()
        forms = [('urn:test:ft', {'field1': ['value1']})]
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS], forms)
        frm = 'dup-ftv@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
          <x xmlns="jabber:x:data" type="result">
            <field var="FORM_TYPE" type="hidden">
              <value>urn:test:ft</value>
              <value>urn:test:ft</value>
            </field>
            <field var="field1"><value>value1</value></field>
          </x>
        """ % {'ns': DISCO_NS})

        self.assertNotCached(ver)
        self.assertNotMapped(frm)

    def testDuplicateFormFieldVarIsRejected(self):
        """Repeated field vars must not be deduped into a valid ver."""
        self.start()
        # Oracle computes the ver over the *deduped* view, which is exactly
        # what an attacker would put in the presence to attempt laundering.
        forms = [('urn:test:ft', {'dupfield': ['second'], 'other': ['z']})]
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS], forms)
        frm = 'dup-field@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
          <x xmlns="jabber:x:data" type="result">
            <field var="FORM_TYPE" type="hidden">
              <value>urn:test:ft</value>
            </field>
            <field var="dupfield"><value>first</value></field>
            <field var="dupfield"><value>second</value></field>
            <field var="other"><value>z</value></field>
          </x>
        """ % {'ns': DISCO_NS})

        self.assertNotCached(ver)
        self.assertNotMapped(frm)

    def testNonHiddenFormTypeIsRejectedForHash(self):
        """A non-hidden FORM_TYPE form is excluded; its data cannot hash."""
        self.start()
        # Ver only covers identity+feature because the form must be dropped.
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS])
        frm = 'visible-ft@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
          <x xmlns="jabber:x:data" type="result">
            <field var="FORM_TYPE" type="text-single">
              <value>urn:test:ft</value>
            </field>
            <field var="field1"><value>value1</value></field>
          </x>
        """ % {'ns': DISCO_NS})

        self.assertNotMapped(frm)

    def testUnknownHashFetchesBareDiscoAndCachesNothing(self):
        """Unknown hashes fall back to plain disco#info, never into caps."""
        self.start()
        frm = 'weirdhash@example.com/r'

        self.send_caps_presence(frm, 'anything=', hash_name='nonsense-hash')
        # A query is still sent (the coroutine must be awaited), but without
        # a caps node.
        sent = self.xmpp.socket.next_sent(timeout=0.05)
        self.assertIsNotNone(sent)
        sent = sent.decode()
        self.assertIn('to="%s"' % frm, sent)
        self.assertNotIn('node=', sent)
        self.assertEqual(self.caps.cache.cache, {})
        self.assertNotMapped(frm)

    def testSameVerFromTwoEntitiesReusesVerifiedCache(self):
        """Cache reuse across entities is safe once one result verified."""
        self.start()
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS])
        first = 'first@example.com/r1'
        second = 'second@example.com/r2'

        self.send_caps_presence(first, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, first, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
        """ % {'ns': DISCO_NS})
        self.assertCached(ver)
        self.assertMapped(first, ver)

        # The second entity claims the same ver: no new query must be sent,
        # and the mapping is created from the already verified cache.
        self.send_caps_presence(second, ver, node='http://other.example/x')
        self.pump()
        self.wait_for_send_queue()
        self.assertIsNone(self.xmpp.socket.next_sent(timeout=0.05))
        self.assertMapped(second, ver)
        self.assertEqual(len(self.caps.cache.cache), 1)

    def testUnverifiedVerIsNotReused(self):
        """An entity cannot inherit caps whose ver was never verified."""
        self.start()
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS])
        first = 'bad@example.com/r1'
        second = 'copycat@example.com/r2'

        self.send_caps_presence(first, ver)
        iq_id, _ = self.next_iq_id()
        # Reply with data that does not match the advertised ver.
        self.recv_disco(iq_id, first, ver, """
          <identity category="client" type="pc"/>
          <feature var="%(ns)s"/>
        """ % {'ns': DISCO_NS})
        self.assertNotCached(ver)
        self.assertNotMapped(first)

        self.send_caps_presence(second, ver)
        iq_id2, _ = self.next_iq_id()
        self.assertIsNotNone(iq_id2)
        self.assertNotMapped(second)

    def testLateDiscoReplyDoesNotOverwriteNewerVer(self):
        """A stale reply for an old ver must not overwrite the mapping."""
        self.start()
        ver_old = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS])
        ver_new = CapsOracle.verstring(
            [('client', 'pc', None, None)],
            [DISCO_NS, 'urn:xmpp:ping'])
        frm = 'mobile@example.com/r'

        # First presence triggers a query for ver_old.
        self.send_caps_presence(frm, ver_old)
        id_old, _ = self.next_iq_id()

        # New presence before the first reply arrives.
        self.send_caps_presence(frm, ver_new)
        id_new, _ = self.next_iq_id()

        # The fresh reply is validated and mapped first.
        self.recv_disco(id_new, frm, ver_new, """
          <identity category="client" type="pc"/>
          <feature var="%(ns)s"/>
          <feature var="urn:xmpp:ping"/>
        """ % {'ns': DISCO_NS})
        self.assertMapped(frm, ver_new)

        # Then the late reply for the old ver arrives.
        self.recv_disco(id_old, frm, ver_old, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
        """ % {'ns': DISCO_NS})
        self.assertMapped(frm, ver_new)
        # The old result remains usable in the shared cache by itself,
        # but it must not be bound to the entity anymore.
        self.assertCached(ver_old)
        self.assertCached(ver_new)

    def testLateFirstReplyStillBindsWhenNothingNewerArrived(self):
        """Normal slow replies must not be rejected by the staleness guard."""
        self.start()
        ver = CapsOracle.verstring(
            [('client', 'bot', None, None)], [DISCO_NS])
        frm = 'slow@example.com/r'

        self.send_caps_presence(frm, ver)
        iq_id, _ = self.next_iq_id()
        self.recv_disco(iq_id, frm, ver, """
          <identity category="client" type="bot"/>
          <feature var="%(ns)s"/>
        """ % {'ns': DISCO_NS})
        self.assertCached(ver)
        self.assertMapped(frm, ver)

    def testValidationUsesRawStanzaNotDedupedView(self):
        """Unit-level check: duplicate field vars are detected on raw XML."""
        self.start()
        form = Form()
        form['type'] = 'result'
        first = FormField()
        first['var'] = 'dup'
        first['value'] = 'a'
        second = FormField()
        second['var'] = 'dup'
        second['value'] = 'b'
        form.append(first)
        form.append(second)
        # The dict view hides the duplication.
        self.assertEqual(len(form.get_fields()), 1)
        # The raw substanza list still exposes it.
        vars_ = [field['var'] for field in form['substanzas']
                 if isinstance(field, FormField)]
        self.assertNotEqual(len(vars_), len(set(vars_)))


suite = unittest.TestLoader().loadTestsFromTestCase(TestStreamCaps)
