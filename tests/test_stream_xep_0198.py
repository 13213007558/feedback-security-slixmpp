import unittest

from slixmpp.test import SlixTest
from slixmpp.plugins.xep_0198.stream_management import MAX_SEQ


class TestStreamManagement(SlixTest):
    """
    Test the XEP-0198 ack/resume validation logic.

    The outgoing sequence counter is seeded near the 2**32 wraparound
    point so that boundary behaviour is covered with a handful of
    in-memory stanzas instead of billions of messages.
    """

    def setUp(self):
        self.stream_start(plugins=['xep_0198'])
        self.sm = self.xmpp['xep_0198']
        self.acked = []
        self.resumed_sessions = []
        self.failed = []
        self.xmpp.add_event_handler('stanza_acked', self._on_acked)
        self.xmpp.add_event_handler('session_resumed', self._on_resumed)
        self.xmpp.add_event_handler('sm_failed', self._on_failed)

    def tearDown(self):
        self.stream_close()

    # ------------------------------------------------------------------
    # Helpers

    def _on_acked(self, stanza):
        self.acked.append(stanza['body'])

    def _on_resumed(self, stanza):
        self.resumed_sessions.append(stanza)

    def _on_failed(self, stanza):
        self.failed.append(stanza)

    def _enable_sm(self, seq=0):
        """Force the plugin into the enabled state with the outgoing
        counter at the given value."""
        self.sm.enabled_in = True
        self.sm.enabled_out = True
        self.sm.seq = seq
        self.sm.last_ack = seq

    def _send_messages(self, *bodies):
        """Send chat messages through the real outgoing filter chain
        so they get sequenced and queued like normal stanzas."""
        for body in bodies:
            msg = self.Message()
            msg['to'] = 'user@localhost'
            msg['type'] = 'chat'
            msg['body'] = body
            self.xmpp.send(msg)
        self.wait_for_send_queue()
        return self._drain_socket()

    def _drain_socket(self):
        sent = []
        while True:
            data = self.xmpp.socket.next_sent()
            if data is None:
                break
            if isinstance(data, str):
                data = data.encode('utf-8')
            sent.append(data)
        return sent

    def _queue_bodies(self):
        return [stanza['body'] for _, stanza in self.sm.unacked_queue]

    def _queue_seqs(self):
        return [seq for seq, _ in self.sm.unacked_queue]

    def _assert_stream_aborted(self, sent):
        self.assertTrue(
            any(b'handled-count-too-high' in data for data in sent),
            'No handled-count-too-high stream error in %r' % sent)
        self.assertTrue(
            any(b'</stream:stream>' in data for data in sent),
            'Stream was not closed: %r' % sent)

    def _assert_sm_state_reset(self):
        self.assertIsNone(self.sm.sm_id)
        self.assertEqual(self._queue_bodies(), [])
        self.assertEqual(self.sm.seq, 0)
        self.assertEqual(self.sm.last_ack, 0)
        self.assertEqual(self.sm.handled, 0)
        self.assertFalse(self.sm.enabled_in)
        self.assertFalse(self.sm.enabled_out)

    # ------------------------------------------------------------------
    # Normal ack path

    def test_ack_normal(self):
        """Regular acks free the queue and emit stanza_acked in order."""
        self._enable_sm()
        self._send_messages('m1', 'm2', 'm3')
        self.assertEqual(self._queue_bodies(), ['m1', 'm2', 'm3'])
        self.assertEqual(self._queue_seqs(), [1, 2, 3])

        self.recv("<a xmlns='urn:xmpp:sm:3' h='2'/>")
        self.assertEqual(self.acked, ['m1', 'm2'])
        self.assertEqual(self._queue_bodies(), ['m3'])
        self.assertEqual(self.sm.last_ack, 2)

        self.recv("<a xmlns='urn:xmpp:sm:3' h='3'/>")
        self.assertEqual(self.acked, ['m1', 'm2', 'm3'])
        self.assertEqual(self._queue_bodies(), [])
        self.assertEqual(self.sm.last_ack, 3)

    def test_ack_wraparound(self):
        """Acks crossing the 2**32 boundary are computed mod 2**32."""
        self._enable_sm(seq=MAX_SEQ - 2)
        self._send_messages('m1', 'm2', 'm3')
        self.assertEqual(self._queue_seqs(), [MAX_SEQ - 1, 0, 1])

        # Server handled the first two stanzas: h wrapped to 0.
        self.recv("<a xmlns='urn:xmpp:sm:3' h='0'/>")
        self.assertEqual(self.acked, ['m1', 'm2'])
        self.assertEqual(self._queue_bodies(), ['m3'])
        self.assertEqual(self.sm.last_ack, 0)

        self.recv("<a xmlns='urn:xmpp:sm:3' h='1'/>")
        self.assertEqual(self.acked, ['m1', 'm2', 'm3'])
        self.assertEqual(self._queue_bodies(), [])
        self.assertEqual(self.sm.last_ack, 1)

    def test_ack_duplicate(self):
        """A duplicate ack (h == last_ack) is a no-op."""
        self._enable_sm()
        self._send_messages('m1', 'm2')
        self.recv("<a xmlns='urn:xmpp:sm:3' h='2'/>")
        self.recv("<a xmlns='urn:xmpp:sm:3' h='2'/>")
        self.assertEqual(self.acked, ['m1', 'm2'])
        self.assertEqual(self._queue_bodies(), [])
        self.assertEqual(self.sm.last_ack, 2)

    def test_ack_missing_h_ignored(self):
        """A malformed ack without h must not ack anything."""
        self._enable_sm()
        self._send_messages('m1')
        self.recv("<a xmlns='urn:xmpp:sm:3'/>")
        self.assertEqual(self.acked, [])
        self.assertEqual(self._queue_bodies(), ['m1'])

    def test_ack_too_high_aborts_stream(self):
        """An ack for more stanzas than were sent must not produce
        stanza_acked events; the stream is aborted instead."""
        self._enable_sm(seq=MAX_SEQ - 2)
        self._send_messages('m1', 'm2', 'm3')

        # h=2 with last_ack=2**32-2 claims 4 freshly handled stanzas,
        # but only 3 are in the queue.
        self.recv("<a xmlns='urn:xmpp:sm:3' h='2'/>")

        self.assertEqual(self.acked, [])
        sent = self._drain_socket()
        self._assert_stream_aborted(sent)
        self._assert_sm_state_reset()

    def test_ack_out_of_range_aborts_stream(self):
        """An h value outside the 32 bit range is a protocol error."""
        self._enable_sm()
        self._send_messages('m1')
        self.recv("<a xmlns='urn:xmpp:sm:3' h='%d'/>" % (MAX_SEQ + 1))

        self.assertEqual(self.acked, [])
        sent = self._drain_socket()
        self._assert_stream_aborted(sent)
        self._assert_sm_state_reset()

    # ------------------------------------------------------------------
    # Resumption path

    def _prepare_resume(self):
        """Simulate an established, then interrupted, SM session with
        three unacked stanzas around the wraparound boundary."""
        self._enable_sm(seq=MAX_SEQ - 2)
        self._send_messages('m1', 'm2', 'm3')
        self.sm.sm_id = 'sm-123'
        self.sm.enabled_in = False
        self.sm.enabled_out = False

    def test_resume_resends_unacked(self):
        """A valid resumption acks confirmed stanzas and resends the
        remaining ones in their original order."""
        self._prepare_resume()

        # Server handled the first two stanzas (h wrapped to 0).
        self.recv("<resumed xmlns='urn:xmpp:sm:3' h='0' previd='sm-123'/>")

        self.assertEqual(self.acked, ['m1', 'm2'])
        self.assertEqual(len(self.resumed_sessions), 1)
        self.assertEqual(self.resumed_sessions[0].name, 'resumed')
        self.assertEqual(self.sm.last_ack, 0)

        self.wait_for_send_queue()
        sent = self._drain_socket()
        self.assertEqual(len(sent), 1)
        self.assertTrue(b'>m3<' in sent[0], sent)

    def test_resume_wrong_previd_aborts(self):
        """A resumption for a different stream id must not ack,
        resend, or mix old stanzas into the new session."""
        self._prepare_resume()

        self.recv("<resumed xmlns='urn:xmpp:sm:3' h='0' previd='WRONG'/>")

        self.assertEqual(self.acked, [])
        self.assertEqual(self.resumed_sessions, [])
        self.wait_for_send_queue()
        sent = self._drain_socket()
        self.assertFalse(any(b'>m1<' in data for data in sent), sent)
        self.assertFalse(any(b'>m2<' in data for data in sent), sent)
        self.assertFalse(any(b'>m3<' in data for data in sent), sent)
        self._assert_stream_aborted(sent)
        self._assert_sm_state_reset()

    def test_resume_too_high_aborts(self):
        """A resumption acking more stanzas than were sent must not
        produce stanza_acked events or a session_resumed event."""
        self._prepare_resume()

        # h=2 with last_ack=2**32-2 claims 4 stanzas, only 3 were sent.
        self.recv("<resumed xmlns='urn:xmpp:sm:3' h='2' previd='sm-123'/>")

        self.assertEqual(self.acked, [])
        self.assertEqual(self.resumed_sessions, [])
        self.wait_for_send_queue()
        sent = self._drain_socket()
        self.assertFalse(any(b'>m1<' in data for data in sent), sent)
        self.assertFalse(any(b'>m2<' in data for data in sent), sent)
        self.assertFalse(any(b'>m3<' in data for data in sent), sent)
        self._assert_stream_aborted(sent)
        self._assert_sm_state_reset()

    def test_resume_failed_clears_queue_without_acking(self):
        """A failed resumption drops the unacked queue (so old
        stanzas cannot leak into the new session) and emits
        sm_failed, but never stanza_acked."""
        self._prepare_resume()

        self.recv("<failed xmlns='urn:xmpp:sm:3'/>")

        self.assertEqual(self.acked, [])
        self.assertEqual(len(self.failed), 1)
        self.assertEqual(self._queue_bodies(), [])
        self.assertFalse(self.sm.enabled_in)
        self.assertFalse(self.sm.enabled_out)


suite = unittest.TestLoader().loadTestsFromTestCase(TestStreamManagement)
