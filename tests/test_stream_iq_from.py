import unittest

from slixmpp.test import SlixTest
from slixmpp.exceptions import IqError, IqTimeout


class TestStreamIqFrom(SlixTest):
    """
    Security regression tests for IQ response provenance.

    A matching IQ 'id' alone is not enough to complete a pending IQ:
    the 'from' of a result/error must belong to an entity allowed to
    answer the request. Per RFC 6120 (server-stamped 'from') and
    RFC 6121 (the server itself answers IQs addressed to a bare JID,
    a domain, or the local account), the legitimate senders of a reply
    are:

      - the full JID the IQ was sent to;
      - its bare JID or domain (server answering on its behalf);
      - our own bare JID or domain, or an empty 'from', when the
        server answers for the local account (e.g. no 'to' at all).

    Replies from any other entity (another user on our domain, another
    resource of the peer, an unrelated domain) must be ignored: they
    must neither complete the future nor remove the pending handler,
    so that the legitimate reply can still arrive and be processed.
    """

    def setUp(self):
        self.stream_start(mode='client', jid='tester@localhost/resource')

    def tearDown(self):
        self.stream_close()

    # ------------------------------------------------------------------
    # Helpers

    def _send_iq(self, to=None, iq_id='1'):
        """Send an IQ get through the real stream, return its future."""
        iq = self.Iq()
        iq['type'] = 'get'
        iq['id'] = iq_id
        if to is not None:
            iq['to'] = to
        iq['query'] = 'test:iq-from'
        future = iq.send()
        self.send(iq)
        return future

    def _recv_result(self, iq_id='1', from_=None):
        if from_ is None:
            self.recv('<iq type="result" id="%s" />' % iq_id)
        else:
            self.recv('<iq type="result" id="%s" from="%s" />' % (iq_id, from_))

    def _recv_error(self, iq_id='1', from_=None):
        from_attr = '' if from_ is None else ' from="%s"' % from_
        self.recv("""
          <iq type="error" id="%s"%s>
            <error type="cancel">
              <service-unavailable xmlns="urn:ietf:params:xml:ns:xmpp-stanzas" />
            </error>
          </iq>
        """ % (iq_id, from_attr))

    def _check_spoofed_ignored(self, future, iq_id, spoofed_from,
                               legit_from, spoofed_type='result'):
        """A spoofed reply must be ignored, the legit one processed."""
        if spoofed_type == 'result':
            self._recv_result(iq_id, from_=spoofed_from)
        else:
            self._recv_error(iq_id, from_=spoofed_from)
        self.assertFalse(future.done(),
                "Future completed by spoofed %s from <%s>" % (
                    spoofed_type, spoofed_from))

        # The legitimate handler must still be in place: the real
        # reply arriving afterwards has to be processed normally.
        self._recv_result(iq_id, from_=legit_from)
        self.assertTrue(future.done(),
                "Legitimate reply from <%s> was not processed" % legit_from)
        self.assertEqual(str(future.result()['from']), legit_from)

    # ------------------------------------------------------------------
    # Positive cases: replies from entities allowed to answer

    def test_result_to_full_jid(self):
        """IQ to a full JID: full JID, bare JID and domain may reply."""
        future = self._send_iq('user@localhost/res1', '1')
        self._recv_result('1', from_='user@localhost/res1')
        self.assertTrue(future.done())
        self.assertEqual(str(future.result()['from']), 'user@localhost/res1')

        # Server answering on behalf of the bare JID (RFC 6121).
        future = self._send_iq('user@localhost/res1', '2')
        self._recv_result('2', from_='user@localhost')
        self.assertTrue(future.done())

        # Server answering on behalf of the domain.
        future = self._send_iq('user@localhost/res1', '3')
        self._recv_result('3', from_='localhost')
        self.assertTrue(future.done())

    def test_result_to_bare_jid(self):
        """IQ to a bare JID: the bare JID or the domain may reply."""
        future = self._send_iq('user@localhost', '1')
        self._recv_result('1', from_='user@localhost')
        self.assertTrue(future.done())

        future = self._send_iq('user@localhost', '2')
        self._recv_result('2', from_='localhost')
        self.assertTrue(future.done())

    def test_result_to_domain(self):
        """IQ to a domain: the domain or an empty from may reply."""
        future = self._send_iq('localhost', '1')
        self._recv_result('1', from_='localhost')
        self.assertTrue(future.done())

        future = self._send_iq('localhost', '2')
        self._recv_result('2')
        self.assertTrue(future.done())

    def test_result_to_own_server(self):
        """IQ without 'to': own server/account JIDs or empty from reply."""
        future = self._send_iq(None, '1')
        self._recv_result('1')
        self.assertTrue(future.done())

        future = self._send_iq(None, '2')
        self._recv_result('2', from_='localhost')
        self.assertTrue(future.done())

        future = self._send_iq(None, '3')
        self._recv_result('3', from_='tester@localhost')
        self.assertTrue(future.done())

    def test_error_from_legit_sender(self):
        """An error from the queried entity completes with IqError."""
        future = self._send_iq('user@localhost/res1', '1')
        self._recv_error('1', from_='user@localhost/res1')
        self.assertTrue(future.done())
        self.assertIsInstance(future.exception(), IqError)

    # ------------------------------------------------------------------
    # Negative cases: spoofed senders must be ignored

    def test_spoofed_result_from_same_domain_user(self):
        """A result from another user of our domain must be ignored."""
        cases = [
            ('1', 'user@localhost/res1', 'user@localhost/res1'),
            ('2', 'user@localhost', 'user@localhost'),
            ('3', 'localhost', 'localhost'),
            ('4', None, 'localhost'),
        ]
        for iq_id, to, legit_from in cases:
            future = self._send_iq(to, iq_id)
            self._check_spoofed_ignored(future, iq_id,
                                        spoofed_from='other@localhost',
                                        legit_from=legit_from)

    def test_spoofed_error_from_same_domain_user(self):
        """An error from another user of our domain must be ignored."""
        future = self._send_iq('user@localhost/res1', '1')
        self._check_spoofed_ignored(future, '1',
                                    spoofed_from='other@localhost',
                                    legit_from='user@localhost/res1',
                                    spoofed_type='error')

    def test_spoofed_result_from_other_resource(self):
        """A result from another resource of the peer must be ignored."""
        future = self._send_iq('user@localhost/res1', '1')
        self._check_spoofed_ignored(future, '1',
                                    spoofed_from='user@localhost/res2',
                                    legit_from='user@localhost/res1')

        # IQs to a bare JID are answered by the server itself, not
        # by one of the account's resources.
        future = self._send_iq('user@localhost', '2')
        self._check_spoofed_ignored(future, '2',
                                    spoofed_from='user@localhost/res1',
                                    legit_from='user@localhost')

        # Same for IQs to our own account.
        future = self._send_iq('tester@localhost', '3')
        self._check_spoofed_ignored(future, '3',
                                    spoofed_from='tester@localhost/attacker',
                                    legit_from='tester@localhost')

    def test_spoofed_result_from_foreign_domain(self):
        """A result from an unrelated domain must be ignored."""
        cases = [
            ('1', 'user@localhost/res1', 'user@localhost/res1'),
            ('2', 'user@localhost', 'user@localhost'),
            ('3', 'localhost', 'localhost'),
            ('4', None, 'localhost'),
        ]
        for iq_id, to, legit_from in cases:
            future = self._send_iq(to, iq_id)
            self._check_spoofed_ignored(future, iq_id,
                                        spoofed_from='evil.example.com',
                                        legit_from=legit_from)

    def test_spoofed_error_from_foreign_domain(self):
        """An error from an unrelated domain must be ignored."""
        future = self._send_iq('user@localhost/res1', '1')
        self._check_spoofed_ignored(future, '1',
                                    spoofed_from='evil.example.com',
                                    legit_from='user@localhost/res1',
                                    spoofed_type='error')

    def test_multiple_spoofed_replies_then_legit(self):
        """Several spoofed replies must not wear down the handler."""
        future = self._send_iq('user@localhost/res1', '1')
        self._recv_result('1', from_='evil.example.com')
        self._recv_error('1', from_='other@localhost')
        self._recv_result('1', from_='user@localhost/res2')
        self.assertFalse(future.done())
        self._recv_result('1', from_='user@localhost/res1')
        self.assertTrue(future.done())

    # ------------------------------------------------------------------
    # IQs sent before resource binding has completed

    def test_prebind_result_from_server(self):
        """Pre-bind IQs are answered by the server (domain/empty from)."""
        self.xmpp.session_bind_event.clear()

        future = self._send_iq('localhost', '1')
        self._recv_result('1', from_='localhost')
        self.assertTrue(future.done())

        future = self._send_iq('localhost', '2')
        self._recv_result('2')
        self.assertTrue(future.done())

        future = self._send_iq(None, '3')
        self._recv_result('3', from_='tester@localhost')
        self.assertTrue(future.done())

    def test_prebind_spoofed_result_from_foreign_domain(self):
        """Pre-bind, a result from an unrelated domain must be ignored."""
        self.xmpp.session_bind_event.clear()

        future = self._send_iq('localhost', '1')
        self._check_spoofed_ignored(future, '1',
                                    spoofed_from='evil.example.com',
                                    legit_from='localhost')

    def test_prebind_spoofed_result_from_same_domain_user(self):
        """Pre-bind, a result from another user must be ignored."""
        self.xmpp.session_bind_event.clear()

        future = self._send_iq('localhost', '1')
        self._check_spoofed_ignored(future, '1',
                                    spoofed_from='other@localhost',
                                    legit_from='localhost')

    def test_prebind_spoofed_error(self):
        """Pre-bind, an error from an unrelated domain must be ignored."""
        self.xmpp.session_bind_event.clear()

        future = self._send_iq('localhost', '1')
        self._check_spoofed_ignored(future, '1',
                                    spoofed_from='evil.example.com',
                                    legit_from='localhost',
                                    spoofed_type='error')


if __name__ == '__main__':
    unittest.main()
