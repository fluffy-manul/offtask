"""Regression tests for Docker endpoint refresh; requires no Docker daemon."""
import unittest
from unittest.mock import Mock
from docker_test_helpers import container_state, published_port, restart_container


class DockerEndpointTests(unittest.TestCase):
    def test_restart_refreshes_reassigned_port_before_health_check(self):
        events = []
        def docker(*args):
            events.append(args)
            return {'restart': 'fixture', 'port': '127.0.0.1:32002\n', 'inspect': '{"Running":true,"ExitCode":0}'}[args[0]]
        class Client:
            port = 32001
            def request(self):
                return self.port
            def ready(self):
                events.append(('ready', self.port))
        client = Client()
        retained_request = client.request
        restart_container(docker, 'fixture', client)
        self.assertEqual(retained_request(), 32002)
        self.assertEqual(events, [('restart', 'fixture'), ('port', 'fixture', '80/tcp'), ('ready', 32002), ('inspect', '--format', '{{json .State}}', 'fixture')])

    def test_restart_also_accepts_a_stable_mapping(self):
        docker = Mock(side_effect=['fixture', '127.0.0.1:32001', '{"Running":true}'])
        client = Mock(port=32001)
        restart_container(docker, 'fixture', client)
        self.assertEqual(client.port, 32001)
        client.ready.assert_called_once_with()

    def test_state_diagnostics_do_not_emit_errors_or_environment(self):
        docker = Mock(return_value='{"Running":false,"ExitCode":137,"OOMKilled":true,"Error":"sensitive","Env":["secret"]}')
        state = container_state(docker, 'fixture')
        self.assertEqual(state['ExitCode'], 137)
        self.assertTrue(state['OOMKilled'])
        self.assertNotIn('Error', state)
        self.assertNotIn('Env', state)

    def test_mapping_must_be_verified_and_loopback_only(self):
        for binding in ['', '0.0.0.0:32001', '127.0.0.1:0', '127.0.0.1:65536',
                        '127.0.0.1:abc', '127.0.0.1:32001\n127.0.0.1:32002']:
            with self.subTest(binding=binding), self.assertRaises(AssertionError):
                published_port(lambda *args: binding, 'fixture')


if __name__ == '__main__':
    unittest.main()
