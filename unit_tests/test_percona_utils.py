import collections
import os
import tempfile

from unittest import mock

from charmhelpers.fetch import SourceConfigError

import percona_utils

from test_utils import CharmTestCase, patch_open, FakeKvStore

os.environ['JUJU_UNIT_NAME'] = 'percona-cluster/2'


class UtilsTests(CharmTestCase):
    TO_PATCH = [
        'config',
        'kv',
        'is_leader',
        'leader_get',
        'log',
        'relation_ids',
        'related_units',
        'relation_get',
        'relation_set',
        'get_db_helper',
        'yaml',
    ]

    def setUp(self):
        super(UtilsTests, self).setUp(percona_utils, self.TO_PATCH)

    @mock.patch("percona_utils.log")
    def test_update_empty_hosts_file(self, mock_log):
        _map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name
            percona_utils.HOSTS_FILE = tmpfile.name
            percona_utils.update_hosts_file(_map)

        with open(tmpfile.name, 'r', encoding="UTF-8") as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0],
                         "{} {}\n".format(list(_map.keys())[0],
                                          list(_map.values())[0]))

    @mock.patch("percona_utils.log")
    def test_update_hosts_file_w_dup(self, mock_log):
        _map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w', encoding="UTF-8") as fd:
                fd.write("{} {}\n".format(list(_map.keys())[0],
                                          list(_map.values())[0]))

            percona_utils.update_hosts_file(_map)

        with open(tmpfile.name, 'r', encoding="UTF-8") as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0],
                         "{} {}\n".format(list(_map.keys())[0],
                                          list(_map.values())[0]))

    @mock.patch("percona_utils.log")
    def test_update_hosts_file_entry(self, mock_log):
        altmap = {'1.1.1.1': 'alt-host'}
        _map = collections.OrderedDict()
        _map['1.1.1.1'] = 'hostA'
        _map['2.2.2.2'] = 'hostB'
        _map['3.3.3.3'] = 'hostC'
        _map['4.4.4.4'] = 'hostD'
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            percona_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w', encoding="UTF-8") as fd:
                fd.write("#somedata\n")
                fd.write("{} {}\n".format(list(altmap.keys())[0],
                                          list(altmap.values())[0]))

            percona_utils.update_hosts_file(_map)

        with open(percona_utils.HOSTS_FILE, 'r', encoding="UTF-8") as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], "#somedata\n")
        self.assertEqual(lines[1],
                         "{} {}\n".format(list(_map.keys())[0],
                                          list(_map.values())[0]))
        self.assertEqual(lines[4],
                         "{} {}\n".format(list(_map.keys())[3],
                                          list(_map.values())[3]))

    @mock.patch("percona_utils.get_cluster_host_ip")
    @mock.patch("percona_utils.log")
    @mock.patch("percona_utils.config")
    @mock.patch("percona_utils.update_hosts_file")
    @mock.patch("percona_utils.relation_get")
    @mock.patch("percona_utils.related_units")
    @mock.patch("percona_utils.relation_ids")
    def test_get_cluster_hosts(self, mock_rel_ids, mock_rel_units,
                               mock_rel_get,
                               mock_update_hosts_file, mock_config,
                               mock_log,
                               mock_get_cluster_host_ip):
        mock_rel_ids.return_value = [1]
        mock_rel_units.return_value = [2]
        mock_get_cluster_host_ip.return_value = '10.2.0.1'

        def _mock_rel_get(*args, **kwargs):
            return {'private-address': '10.2.0.2',
                    'bootstrap-uuid': 'UUID'}

        mock_rel_get.side_effect = _mock_rel_get
        mock_config.side_effect = lambda k: False

        hosts = percona_utils.get_cluster_hosts()

        self.assertFalse(mock_update_hosts_file.called)
        mock_rel_get.assert_called_with(rid=1, unit=2)
        self.assertEqual(hosts, ['10.2.0.2'])

    @mock.patch("percona_utils.get_cluster_host_ip")
    @mock.patch("percona_utils.update_hosts_file")
    def test_get_cluster_hosts_sorted(self, mock_update_hosts_file,
                                      mock_get_cluster_host_ip):
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [5, 4, 3]
        mock_get_cluster_host_ip.return_value = '10.2.0.1'

        def _mock_rel_get(*args, **kwargs):
            unit_id = kwargs.get('unit')
            # Generate list in reverse sort order
            return {'private-address': '10.2.0.{}'.format(unit_id - 1),
                    'bootstrap-uuid': 'UUUID'}

        self.relation_get.side_effect = _mock_rel_get
        self.config.side_effect = lambda k: False

        hosts = percona_utils.get_cluster_hosts()

        self.assertFalse(mock_update_hosts_file.called)
        # Verify the IPs are sorted
        self.assertEqual(hosts, ['10.2.0.2', '10.2.0.3', '10.2.0.4'])

    @mock.patch("percona_utils.get_cluster_host_ip")
    @mock.patch("percona_utils.update_hosts_file")
    def test_get_cluster_hosts_none_bootstrapped(self, mock_update_hosts_file,
                                                 mock_get_cluster_host_ip):
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [4, 3, 2]
        mock_get_cluster_host_ip.return_value = '10.2.0.1'

        def _mock_rel_get(*args, **kwargs):
            unit_id = kwargs.get('unit')
            # None set bootstrap-uuid
            return {'private-address': '10.2.0.{}'.format(unit_id)}

        self.relation_get.side_effect = _mock_rel_get
        self.config.side_effect = lambda k: False

        hosts = percona_utils.get_cluster_hosts()

        self.assertFalse(mock_update_hosts_file.called)
        # Verify empty list
        self.assertEqual(hosts, [])

    @mock.patch("percona_utils.get_cluster_host_ip")
    @mock.patch("percona_utils.update_hosts_file")
    def test_get_cluster_hosts_one_not_bootstrapped(self,
                                                    mock_update_hosts_file,
                                                    mock_get_cluster_host_ip):
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [4, 3, 2]
        mock_get_cluster_host_ip.return_value = '10.2.0.1'

        def _mock_rel_get(*args, **kwargs):
            unit_id = kwargs.get('unit')
            if unit_id == 3:
                # unit/3 does not set bootstrap-uuid
                return {'private-address': '10.2.0.{}'.format(unit_id)}
            else:
                return {'private-address': '10.2.0.{}'.format(unit_id),
                        'bootstrap-uuid': 'UUUID'}

        self.relation_get.side_effect = _mock_rel_get
        self.config.side_effect = lambda k: False

        hosts = percona_utils.get_cluster_hosts()

        self.assertFalse(mock_update_hosts_file.called)
        # Verify unit/3 not in the list
        self.assertEqual(hosts, ['10.2.0.2', '10.2.0.4'])

    @mock.patch.object(percona_utils, 'socket')
    @mock.patch("percona_utils.get_cluster_host_ip")
    @mock.patch.object(percona_utils, 'get_ipv6_addr')
    @mock.patch.object(percona_utils, 'log')
    @mock.patch.object(percona_utils, 'config')
    @mock.patch.object(percona_utils, 'update_hosts_file')
    @mock.patch.object(percona_utils, 'relation_get')
    @mock.patch.object(percona_utils, 'related_units')
    @mock.patch.object(percona_utils, 'relation_ids')
    def test_get_cluster_hosts_ipv6(self, mock_rel_ids, mock_rel_units,
                                    mock_rel_get,
                                    mock_update_hosts_file, mock_config,
                                    mock_log, mock_get_ipv6_addr,
                                    mock_get_cluster_host_ip,
                                    mock_socket):
        ipv6addr = '2001:db8:1:0:f816:3eff:fe79:cd'
        mock_get_ipv6_addr.return_value = [ipv6addr]
        mock_rel_ids.return_value = [88]
        mock_rel_units.return_value = [1, 2]
        mock_get_cluster_host_ip.return_value = 'hostA'
        mock_socket.gethostname.return_value = 'hostA'

        def _mock_rel_get(*args, **kwargs):
            host_suffix = 'BC'
            id = kwargs.get('unit')
            hostname = "host{}".format(host_suffix[id - 1])
            return {'private-address': '10.0.0.{}'.format(id + 1),
                    'hostname': hostname,
                    'bootstrap-uuid': 'UUID'}

        config = {'prefer-ipv6': True}
        mock_rel_get.side_effect = _mock_rel_get
        mock_config.side_effect = lambda k: config.get(k)

        hosts = percona_utils.get_cluster_hosts()

        mock_update_hosts_file.assert_called_with({ipv6addr: 'hostA',
                                                   '10.0.0.2': 'hostB',
                                                   '10.0.0.3': 'hostC'})
        mock_rel_get.assert_has_calls([mock.call(rid=88, unit=1),
                                       mock.call(rid=88, unit=2)])
        self.assertEqual(hosts, ['hostB', 'hostC'])

    @mock.patch.object(percona_utils, 'get_address_in_network')
    @mock.patch.object(percona_utils, 'log')
    @mock.patch.object(percona_utils, 'config')
    @mock.patch.object(percona_utils, 'relation_get')
    @mock.patch.object(percona_utils, 'related_units')
    @mock.patch.object(percona_utils, 'relation_ids')
    def test_get_cluster_hosts_w_cluster_network(self, mock_rel_ids,
                                                 mock_rel_units,
                                                 mock_rel_get,
                                                 mock_config,
                                                 mock_log,
                                                 mock_get_address_in_network):
        mock_rel_ids.return_value = [88]
        mock_rel_units.return_value = [1, 2]
        mock_get_address_in_network.return_value = '10.100.0.1'

        def _mock_rel_get(*args, **kwargs):
            host_suffix = 'BC'
            unit = kwargs.get('unit')
            hostname = "host{}".format(host_suffix[unit - 1])
            return {'private-address': '10.0.0.{}'.format(unit + 1),
                    'cluster-address': '10.100.0.{}'.format(unit + 1),
                    'hostname': hostname,
                    'bootstrap-uuid': 'UUID'}

        config = {'cluster-network': '10.100.0.0/24'}
        mock_rel_get.side_effect = _mock_rel_get
        mock_config.side_effect = lambda k: config.get(k)

        hosts = percona_utils.get_cluster_hosts()
        mock_rel_get.assert_has_calls([mock.call(rid=88, unit=1),
                                       mock.call(rid=88, unit=2)])
        self.assertEqual(hosts, ['10.100.0.2', '10.100.0.3'])

    @mock.patch.object(percona_utils, 'is_leader')
    @mock.patch.object(percona_utils, 'related_units')
    @mock.patch.object(percona_utils, 'relation_ids')
    @mock.patch.object(percona_utils, 'config')
    def test_is_sufficient_peers(self, mock_config, mock_relation_ids,
                                 mock_related_units, mock_is_leader):
        mock_is_leader.return_value = False
        _config = {'min-cluster-size': None}
        mock_config.side_effect = lambda key: _config.get(key)
        self.assertTrue(percona_utils.is_sufficient_peers())

        mock_is_leader.return_value = False
        mock_relation_ids.return_value = ['cluster:0']
        mock_related_units.return_value = ['test/0']
        _config = {'min-cluster-size': 3}
        mock_config.side_effect = lambda key: _config.get(key)
        self.assertFalse(percona_utils.is_sufficient_peers())

        mock_is_leader.return_value = False
        mock_related_units.return_value = ['test/0', 'test/1']
        _config = {'min-cluster-size': 3}
        mock_config.side_effect = lambda key: _config.get(key)
        self.assertTrue(percona_utils.is_sufficient_peers())

    @mock.patch.object(percona_utils, 'lsb_release')
    def test_packages_eq_wily(self, mock_lsb_release):
        mock_lsb_release.return_value = {'DISTRIB_CODENAME': 'wily'}
        self.assertEqual(percona_utils.determine_packages(),
                         ['percona-xtradb-cluster-server'])

    @mock.patch.object(percona_utils, 'lsb_release')
    def test_packages_gt_wily(self, mock_lsb_release):
        mock_lsb_release.return_value = {'DISTRIB_CODENAME': 'xenial'}
        self.assertEqual(percona_utils.determine_packages(),
                         ['percona-xtradb-cluster-server'])

    @mock.patch.object(percona_utils, 'lsb_release')
    def test_packages_lt_wily(self, mock_lsb_release):
        mock_lsb_release.return_value = {'DISTRIB_CODENAME': 'trusty'}
        self.assertEqual(percona_utils.determine_packages(),
                         ['percona-xtradb-cluster-server-5.5',
                          'percona-xtradb-cluster-client-5.5'])

    @mock.patch.object(percona_utils, 'log')
    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_get_wsrep_value(self, get_db_helper, log):
        _err_msg = '(000, "Query with \'wsrep_not_found_key\' failed")'
        _log_msg = f"Failed to get key=wsrep_not_found_key '{_err_msg}'"

        __db_helper = mock.MagicMock()
        __db_helper.get_mysql_root_password.return_value = "password"
        __db_helper.connect.return_value = True

        __cursor = mock.MagicMock()
        __cursor.execute.side_effect = Exception(_err_msg)
        __db_helper.connection.cursor.return_value = __cursor

        get_db_helper.return_value = __db_helper
        percona_utils.get_wsrep_value('wsrep_not_found_key')
        log.assert_called_with(_log_msg, 'ERROR')

    @mock.patch.object(percona_utils, 'get_wsrep_value')
    def test_cluster_in_sync_not_ready(self, _wsrep_value):
        _wsrep_value.side_effect = [None, None]
        self.assertFalse(percona_utils.cluster_in_sync())

    @mock.patch.object(percona_utils, 'get_wsrep_value')
    def test_cluster_in_sync_ready_syncing(self, _wsrep_value):
        _wsrep_value.side_effect = [True, None]
        self.assertFalse(percona_utils.cluster_in_sync())

    @mock.patch.object(percona_utils, 'get_wsrep_value')
    def test_cluster_in_sync_ready_sync(self, _wsrep_value):
        _wsrep_value.side_effect = [True, 4]
        self.assertTrue(percona_utils.cluster_in_sync())

    @mock.patch.object(percona_utils, 'get_wsrep_value')
    def test_cluster_in_sync_ready_sync_donor(self, _wsrep_value):
        _wsrep_value.side_effect = [True, 2]
        self.assertTrue(percona_utils.cluster_in_sync())

    @mock.patch("percona_utils.config")
    def test_get_wsrep_provider_options(self, mock_config):
        # Empty
        _config = {"min-cluster-size": 3}
        mock_config.side_effect = lambda key: _config.get(key)
        expected = ""
        self.assertEqual(percona_utils.get_wsrep_provider_options(),
                         expected)

        # IPv6 only
        _config = {"prefer-ipv6": True}
        mock_config.side_effect = lambda key: _config.get(key)
        expected = "gmcast.listen_addr=tcp://:::4567"
        self.assertEqual(percona_utils.get_wsrep_provider_options(),
                         expected)
        # ipv6 and peer_timeout
        _config = {"peer-timeout": "PT15S",
                   "prefer-ipv6": True}
        mock_config.side_effect = lambda key: _config.get(key)
        expected = ("gmcast.listen_addr=tcp://:::4567;"
                    "gmcast.peer_timeout=PT15S")
        self.assertEqual(percona_utils.get_wsrep_provider_options(),
                         expected)
        # set gcs.fs_limit=10000
        _config = {"gcs-fc-limit": 10000}
        mock_config.side_effect = lambda key: _config.get(key)
        expected = "gcs.fc_limit=10000"
        self.assertEqual(percona_utils.get_wsrep_provider_options(),
                         expected)
        # peer_timeout bad setting
        _config = {"peer-timeout": "10"}
        mock_config.side_effect = lambda key: _config.get(key)
        with self.assertRaises(ValueError):
            percona_utils.get_wsrep_provider_options()
        _config = {"peer-timeout": "PT10M"}
        mock_config.side_effect = lambda key: _config.get(key)
        with self.assertRaises(ValueError):
            percona_utils.get_wsrep_provider_options()

    def test_set_ready_on_peers(self):
        self.relation_ids.return_value = ["rel:1"]
        percona_utils.set_ready_on_peers()
        self.relation_set.assert_called_with(relation_id="rel:1", ready=True)

    def test_get_min_cluster_size(self):
        _config = {}
        self.config.side_effect = lambda key: _config.get(key)
        self.relation_ids.return_value = ["rel:1"]
        self.related_units.return_value = []
        self.assertEqual(percona_utils.get_min_cluster_size(), 1)

        self.related_units.return_value = ['unit/2', 'unit/9', 'unit/21']
        self.assertEqual(percona_utils.get_min_cluster_size(), 4)

        _config = {'min-cluster-size': 3}
        self.config.side_effect = lambda key: _config.get(key)
        self.assertEqual(percona_utils.get_min_cluster_size(), 3)

    @mock.patch("percona_utils.time")
    @mock.patch("percona_utils.os")
    def test_check_for_socket(self, _os, _time):
        # Socket exists checking for exists
        _os.path.exists.return_value = True
        percona_utils.check_for_socket("filename", exists=True)
        _time.sleep.assert_not_called()

        # Socket does not exist checking for exists
        _os.path.exists.return_value = False
        with self.assertRaises(Exception):
            percona_utils.check_for_socket("filename", exists=True)
        _time.sleep.assert_called_with(10)

        _time.reset_mock()

        # Socket does not exist checking for not exists
        _os.path.exists.return_value = False
        percona_utils.check_for_socket("filename", exists=False)
        _time.sleep.assert_not_called()

        # Socket exists checking for not exists
        _os.path.exists.return_value = True
        with self.assertRaises(Exception):
            percona_utils.check_for_socket("filename", exists=False)
        _time.sleep.assert_called_with(10)

    def test_check_mysql_connection(self):
        _db_helper = mock.MagicMock()
        _db_helper.get_mysql_root_password.return_value = "password"
        self.get_db_helper.return_value = _db_helper

        _db_helper.connect.return_value = mock.MagicMock()
        self.assertTrue(percona_utils.check_mysql_connection())

        # The MySQLdb module is fully mocked out, including the
        # OperationalError. Make OperationalError behave like an exception.
        percona_utils.OperationalError = Exception
        _db_helper.connect.side_effect = percona_utils.OperationalError
        self.assertFalse(percona_utils.check_mysql_connection())

    @mock.patch("percona_utils.resolve_data_dir")
    @mock.patch("percona_utils.os")
    def test_get_grastate(self, _os, _resolve_dd):
        _bootstrap = "1"
        _seqno = "5422"
        _data = {"seqno": _seqno, "safe_to_bootstrap": _bootstrap}
        _os.path.exists.return_value = True
        _resolve_dd.return_value = "/tmp"
        self.yaml.safe_load.return_value = _data
        with patch_open() as (_open, _file):
            _open.return_value = _file
            self.assertEqual(
                _data, percona_utils.get_grastate())

    @mock.patch("percona_utils.get_grastate")
    def test_get_grastate_seqno(self, _get_grastate):
        _seqno = "25"
        _get_grastate.return_value = {"seqno": _seqno}
        self.assertEqual(_seqno, percona_utils.get_grastate_seqno())

    @mock.patch("percona_utils.get_grastate")
    def test_get_grastate_safe_to_bootstrap(self, _get_grastate):
        _bootstrap = "0"
        _get_grastate.return_value = {"safe_to_bootstrap": _bootstrap}
        self.assertEqual(
            _bootstrap, percona_utils.get_grastate_safe_to_bootstrap())

    @mock.patch("percona_utils.resolve_data_dir")
    @mock.patch("percona_utils.os")
    def test_set_grastate_safe_to_bootstrap(self, _os, _resolve_dd):
        _resolve_dd.return_value = "/tmp"
        _bootstrap = "0"
        _os.path.exists.return_value = True
        self.yaml.safe_load.return_value = {"safe_to_bootstrap": _bootstrap}
        with patch_open() as (_open, _file):
            _open.return_value = _file
            _file.write = mock.MagicMock()
            percona_utils.set_grastate_safe_to_bootstrap()
            self.yaml.dump.assert_called_once_with({"safe_to_bootstrap": 1})
            _file.write.assert_called_once()

    @mock.patch("percona_utils.check_mysql_connection")
    @mock.patch("percona_utils.get_wsrep_value")
    @mock.patch("percona_utils.notify_bootstrapped")
    def test_maybe_notify_bootstrapped(
            self, _notify_bootstrapped,
            _get_wsrep_value, _check_mysql_connection):
        kvstore = mock.MagicMock()
        kvstore.get.return_value = True
        self.kv.return_value = kvstore

        _check_mysql_connection.return_value = False

        _uuid = "uuid-uuid"
        self.leader_get.return_value = _uuid
        _get_wsrep_value.return_value = _uuid

        # mysql not runnig
        percona_utils.maybe_notify_bootstrapped()
        _notify_bootstrapped.assert_not_called()

        # No clients initialized
        _check_mysql_connection.return_value = True
        kvstore.get.return_value = False
        percona_utils.maybe_notify_bootstrapped()
        _notify_bootstrapped.assert_not_called()

        # Differing UUID
        _check_mysql_connection.return_value = True
        kvstore.get.return_value = True
        _get_wsrep_value.return_value = "not-the-same-uuid"
        percona_utils.maybe_notify_bootstrapped()
        _notify_bootstrapped.assert_not_called()

        # Differing UUID
        _check_mysql_connection.return_value = True
        kvstore.get.return_value = True
        _get_wsrep_value.return_value = _uuid
        percona_utils.maybe_notify_bootstrapped()
        _notify_bootstrapped.assert_called_once_with(cluster_uuid=_uuid)

    @mock.patch("percona_utils.add_source")
    @mock.patch("percona_utils.apt_update")
    def test_update_source(self, mock_apt_update, mock_add_source):
        """Ensure that add_source and apt_update has been called"""
        percona_utils.update_source("test-source", key=None)

        mock_add_source.assert_called_once_with(
            source="test-source", key=None, fail_invalid=True)
        mock_apt_update.assert_called_once_with()

    @mock.patch("percona_utils.apt_update")
    def test_update_invalid_source(self, mock_apt_update):
        """Ensure raise error and set blocked status after invalid source"""
        with self.assertRaises(SourceConfigError):
            percona_utils.update_source("invalid-source", key=None)

        mock_apt_update.assert_not_called()

    @mock.patch.object(percona_utils, "nagios_password")
    @mock.patch.object(percona_utils, "lsb_release")
    @mock.patch.object(percona_utils, "get_db_helper")
    @mock.patch.object(percona_utils, "write_nagios_my_cnf")
    def test_create_nagios_user(self,
                                mock_create_nagios_mysql_credential,
                                mock_get_db_helper,
                                mock_lsb_release,
                                mock_nagios_password):
        mock_lsb_release.return_value = {'DISTRIB_CODENAME': 'bionic'}
        my_mock = mock.Mock()
        mock_nagios_password.return_value = "1234"
        self.is_leader.return_value = True
        mock_get_db_helper.return_value = my_mock
        mock_cursor = mock.Mock()
        my_mock.connection.cursor.return_value = mock_cursor

        percona_utils.create_nagios_user()
        my_mock.select.assert_called_once_with(
            "SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = 'nagios')"
        )
        my_mock.execute.assert_has_calls([
            mock.call(
                "CREATE USER 'nagios'@'localhost' IDENTIFIED BY '1234';"),
        ])
        mock_cursor.execute.assert_not_called()

        class OperationalError(Exception):
            pass

        percona_utils.OperationalError = OperationalError

        def mysql_create_user(*args, **kwargs):
            raise OperationalError()

        my_mock.select.return_value = False
        my_mock.execute.side_effect = mysql_create_user
        with self.assertRaises(OperationalError):
            percona_utils.create_nagios_user()
        mock_cursor.execute.assert_not_called()

        my_mock.select.return_value = True
        percona_utils.create_nagios_user()
        mock_cursor.execute.assert_has_calls([
            mock.call('UPDATE mysql.user SET authentication_string = '
                      'PASSWORD( %s ) WHERE user = %s;', ('1234', 'nagios')),
            mock.call('FLUSH PRIVILEGES;'),
        ])
        my_mock.connection.commit.assert_called_once_with()

    def test_get_nrpe_threads_connected_thresholds(self):
        """Test function for getting and verifying threshold values."""
        self.config.return_value = "a,1,2"
        with self.assertRaises(ValueError) as context:
            percona_utils.get_nrpe_threads_connected_thresholds()
            self.assertEqual(ValueError("the wrong number of values was set "
                                        "for the nrpe-threads-connected"),
                             context.exception)

        self.config.return_value = "a,1"
        with self.assertRaises(ValueError) as context:
            percona_utils.get_nrpe_threads_connected_thresholds()
            self.assertEqual(
                ValueError("invalid literal for int() with base 10: 'a'"),
                context.exception)

        self.config.return_value = "50,200"
        with self.assertRaises(ValueError) as context:
            percona_utils.get_nrpe_threads_connected_thresholds()
            self.assertEqual(ValueError("the warning threshold must be in the "
                                        "range [0,100) and the critical "
                                        "threshold must be in the range "
                                        "(0,100]"),
                             context.exception)

        self.config.return_value = "90,60"
        with self.assertRaises(ValueError) as context:
            percona_utils.get_nrpe_threads_connected_thresholds()
            self.assertEqual(ValueError("the warning threshold must be less "
                                        "than critical"),
                             context.exception)

        self.config.return_value = "80,90"
        thresholds = percona_utils.get_nrpe_threads_connected_thresholds()
        self.assertEqual(thresholds, (80, 90))

    def test_last_backup_sst(self):
        # test backup info file when backup was SST
        mock_read_data = 'incremental = N\n'
        mock_open = mock.mock_open(read_data=mock_read_data)
        with mock.patch('percona_utils.open', mock_open):
            result = percona_utils.last_backup_sst()
        self.assertEqual(result, True)

        # test backup info file when backup was IST
        mock_read_data = 'incremental = Y\n'
        mock_open = mock.mock_open(read_data=mock_read_data)
        with mock.patch('percona_utils.open', mock_open):
            result = percona_utils.last_backup_sst()
        self.assertEqual(result, False)

        # test backup info file with other 'incremental' string
        mock_read_data = 'something incremental = N\n'
        mock_open = mock.mock_open(read_data=mock_read_data)
        with mock.patch('percona_utils.open', mock_open):
            result = percona_utils.last_backup_sst()
        self.assertEqual(result, False)

        # test backup info file with two lines incremental
        mock_read_data = 'incremental incremental = Y\nincremental = N\n'
        mock_open = mock.mock_open(read_data=mock_read_data)
        with mock.patch('percona_utils.open', mock_open):
            result = percona_utils.last_backup_sst()
        self.assertEqual(result, True)

        # test non existant backup info file
        percona_utils.BACKUP_INFO = '/some/non/existant/file'
        result = percona_utils.last_backup_sst()
        self.assertEqual(result, False)


class UtilsTestsStatus(CharmTestCase):

    TO_PATCH = [
        'is_sufficient_peers',
        'is_bootstrapped',
        'config',
        'cluster_in_sync',
        'is_leader',
        'related_units',
        'relation_ids',
        'relation_get',
        'leader_get',
        'is_unit_paused_set',
        'is_clustered',
        'distributed_wait',
        'cluster_ready',
        'seeded',
        'kv',
    ]

    def setUp(self):
        super(UtilsTestsStatus, self).setUp(percona_utils, self.TO_PATCH)
        self._kvstore = FakeKvStore()
        self.kv.return_value = self._kvstore
        _m = mock.patch("charmhelpers.core.unitdata.kv")
        self.mock_kv = _m.start()
        self.addCleanup(_m.stop)

    @mock.patch.object(percona_utils, 'seeded')
    def test_single_unit(self, mock_seeded):
        mock_seeded.return_value = True
        self.config.return_value = None
        self.is_sufficient_peers.return_value = True
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'active'

    def test_insufficient_peers(self):
        self.config.return_value = 3
        self.is_sufficient_peers.return_value = False
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'blocked'

    def test_not_bootstrapped(self):
        self.config.return_value = 3
        self.is_sufficient_peers.return_value = True
        self.is_bootstrapped.return_value = False
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'waiting'

    def test_bootstrapped_in_sync(self):
        self.config.return_value = 3
        self.is_sufficient_peers.return_value = True
        self.is_bootstrapped.return_value = True
        self.cluster_in_sync.return_value = True
        self.seeded.return_value = True
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'active'

    @mock.patch('time.sleep', return_value=None)
    def test_bootstrapped_not_in_sync(self, mock_time):
        self.config.return_value = 3
        self.is_sufficient_peers.return_value = True
        self.is_bootstrapped.return_value = True
        self.cluster_in_sync.return_value = False
        self.seeded.return_value = True
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'blocked'

    @mock.patch('time.sleep', return_value=None)
    def test_bootstrapped_not_in_sync_to_synced(self, mock_time):
        self.config.return_value = 3
        self.is_sufficient_peers.return_value = True
        self.is_bootstrapped.return_value = True
        self.cluster_in_sync.side_effect = [False, False, True]
        self.seeded.return_value = True
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'active'

    @mock.patch.object(percona_utils, 'last_backup_sst')
    def test_bootstrapped_seeded_missing_sst(self, mock_last_backup_sst):
        self.is_bootstrapped.return_value = True
        self.seeded.side_effect = [False, True]
        self.config.return_value = None
        percona_utils.SEEDED_MARKER = '/tmp/seeded'
        mock_last_backup_sst.return_value = True
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'active'

    @mock.patch.object(percona_utils, 'last_backup_sst')
    def test_not_bootstrapped_seeded_missing_sst(self, mock_last_backup_sst):
        self.is_bootstrapped.return_value = False
        self.seeded.side_effect = [False, False]
        self.config.return_value = None
        percona_utils.SEEDED_MARKER = '/tmp/seeded'
        mock_last_backup_sst.return_value = True
        stat, _ = percona_utils.charm_check_func()
        assert stat == 'waiting'


class UtilsTestsCTC(CharmTestCase):
    TO_PATCH = [
        'is_sufficient_peers',
        'config',
        'cluster_in_sync',
        'is_leader',
        'related_units',
        'relation_ids',
        'relation_get',
        'leader_get',
        'is_unit_paused_set',
        'is_clustered',
        'distributed_wait',
        'clustered_once',
        'kv',
    ]

    def setUp(self):
        super(UtilsTestsCTC, self).setUp(percona_utils, self.TO_PATCH)
        kvstore = mock.MagicMock()
        kvstore.get.return_value = False
        self.kv.return_value = kvstore

    @mock.patch.object(percona_utils, 'pxc_installed')
    @mock.patch.object(percona_utils, 'determine_packages')
    @mock.patch.object(percona_utils, 'application_version_set')
    @mock.patch.object(percona_utils, 'get_upstream_version')
    def test_assess_status(self, get_upstream_version,
                           application_version_set,
                           determine_packages,
                           pxc_installed):
        get_upstream_version.return_value = '5.6.17'
        determine_packages.return_value = ['percona-xtradb-cluster-server-5.6']
        pxc_installed.return_value = True
        with mock.patch.object(percona_utils, 'assess_status_func') as asf:
            callee = mock.Mock()
            asf.return_value = callee
            percona_utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()
            get_upstream_version.assert_called_with(
                'percona-xtradb-cluster-server-5.6'
            )
            application_version_set.assert_called_with('5.6.17')

    @mock.patch.object(percona_utils, 'pxc_installed')
    @mock.patch.object(percona_utils, 'determine_packages')
    @mock.patch.object(percona_utils, 'application_version_set')
    @mock.patch.object(percona_utils, 'get_upstream_version')
    def test_assess_status_find_pkg(self, get_upstream_version,
                                    application_version_set,
                                    determine_packages,
                                    pxc_installed):
        get_upstream_version.side_effect = [None, None, '5.6.17']
        determine_packages.return_value = ['percona-xtradb-cluster-server']
        pxc_installed.return_value = True
        with mock.patch.object(percona_utils, 'assess_status_func') as asf:
            callee = mock.Mock()
            asf.return_value = callee
            percona_utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()
            get_upstream_version.assert_called_with(
                'percona-xtradb-cluster-server-5.6'
            )
            application_version_set.assert_called_with('5.6.17')

    @mock.patch.object(percona_utils, 'log')
    @mock.patch.object(percona_utils, 'pxc_installed')
    @mock.patch.object(percona_utils, 'determine_packages')
    @mock.patch.object(percona_utils, 'application_version_set')
    @mock.patch.object(percona_utils, 'get_upstream_version')
    def test_assess_status_find_pkg_fails(self, get_upstream_version,
                                          application_version_set,
                                          determine_packages,
                                          pxc_installed, log):
        get_upstream_version.return_value = None
        determine_packages.return_value = ['percona-xtradb-cluster-server']
        pxc_installed.return_value = True
        with mock.patch.object(percona_utils, 'assess_status_func') as asf:
            callee = mock.Mock()
            asf.return_value = callee
            percona_utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()
            get_upstream_version.assert_called_with(
                'percona-xtradb-cluster-server-5.7'
            )
            self.assertFalse(application_version_set.called)
            self.assertTrue(log.called)

    @mock.patch.object(percona_utils, 'services')
    @mock.patch.object(percona_utils, 'REQUIRED_INTERFACES')
    @mock.patch.object(percona_utils, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                REQUIRED_INTERFACES,
                                services):
        services.return_value = ['mysql']
        percona_utils.assess_status_func('test-config')
        # ports=None whilst port checks are disabled.
        make_assess_status_func.assert_called_once_with(
            'test-config', REQUIRED_INTERFACES, charm_func=mock.ANY,
            services=['mysql'], ports=None)
        services.assert_called_once()

    def test_pause_unit_helper(self):
        with mock.patch.object(percona_utils, '_pause_resume_helper') as prh:
            percona_utils.pause_unit_helper('random-config')
            prh.assert_called_once_with(percona_utils.pause_unit,
                                        'random-config')
        with mock.patch.object(percona_utils, '_pause_resume_helper') as prh:
            percona_utils.resume_unit_helper('random-config')
            prh.assert_called_once_with(percona_utils.resume_unit,
                                        'random-config')

    @mock.patch.object(percona_utils, 'services')
    def test_pause_resume_helper(self, services):
        f = mock.Mock()
        services.return_value = 's1'
        with mock.patch.object(percona_utils, 'assess_status_func') as asf:
            asf.return_value = 'assessor'
            percona_utils._pause_resume_helper(f, 'some-config')
            asf.assert_called_once_with('some-config')
            # ports=None whilst port checks are disabled.
            f.assert_called_once_with('assessor', services='s1', ports=None)

    @mock.patch.object(percona_utils, 'get_min_cluster_size')
    @mock.patch.object(percona_utils, 'seeded')
    @mock.patch.object(percona_utils, 'is_sufficient_peers')
    def test_is_bootstrapped(self, mock_is_sufficient_peers, mock_seeded,
                             mock_get_min_cluster_size):
        kvstore = mock.MagicMock()
        kvstore.get.return_value = False
        self.kv.return_value = kvstore

        mock_get_min_cluster_size.return_value = 1
        # Single unit not yet seeded
        self.relation_ids.return_value = []
        mock_is_sufficient_peers.return_value = True
        mock_seeded.return_value = False
        self.assertFalse(percona_utils.is_bootstrapped())
        kvstore.set.assert_not_called()

        # Single unit seeded
        self.relation_ids.return_value = []
        mock_is_sufficient_peers.return_value = True
        mock_seeded.return_value = True
        self.assertTrue(percona_utils.is_bootstrapped())
        kvstore.set.assert_called_once_with(key='initial-cluster-complete',
                                            value=True)

        # Not sufficient number of peers
        kvstore.reset_mock()
        mock_get_min_cluster_size.return_value = 3
        self.relation_ids.return_value = ['cluster:0']
        mock_is_sufficient_peers.return_value = False
        self.assertFalse(percona_utils.is_bootstrapped())

        # Not all cluster ready
        mock_is_sufficient_peers.return_value = True
        self.relation_ids.return_value = ['cluster:0']
        self.related_units.return_value = ['test/0', 'test/1']
        self.relation_get.return_value = False
        _config = {'min-cluster-size': 3}
        self.config.side_effect = lambda key: _config.get(key)
        self.assertFalse(percona_utils.is_bootstrapped())

        # kvstore.set has not been called with incomplete clusters
        kvstore.set.assert_not_called()

        # All cluster ready
        mock_is_sufficient_peers.return_value = True
        self.relation_ids.return_value = ['cluster:0']
        self.related_units.return_value = ['test/0', 'test/1']
        self.relation_get.return_value = 'UUID'
        _config = {'min-cluster-size': 3}
        self.config.side_effect = lambda key: _config.get(key)
        self.assertTrue(percona_utils.is_bootstrapped())
        kvstore.set.assert_called_once_with(key='initial-cluster-complete',
                                            value=True)

        # Now set the key for clustered at least once
        kvstore.get.return_value = True
        kvstore.set.reset_mock()

        # Not all cluster ready no min-cluster-size
        mock_is_sufficient_peers.return_value = True
        self.relation_ids.return_value = ['cluster:0']
        self.related_units.return_value = ['test/0', 'test/1']
        self.relation_get.return_value = False
        _config = {'min-cluster-size': None}
        self.config.side_effect = lambda key: _config.get(key)
        self.assertFalse(percona_utils.is_bootstrapped())
        kvstore.set.assert_not_called()

        # All cluster ready no min-cluster-size
        mock_is_sufficient_peers.return_value = True
        self.relation_ids.return_value = ['cluster:0']
        self.related_units.return_value = ['test/0', 'test/1']
        self.relation_get.return_value = 'UUID'
        _config = {'min-cluster-size': None}
        self.config.side_effect = lambda key: _config.get(key)
        self.assertTrue(percona_utils.is_bootstrapped())

    @mock.patch.object(percona_utils, 'seeded')
    def test_cluster_ready(self, mock_seeded):
        # Single unit not seeded
        _config = {}
        mock_seeded.return_value = False
        self.config.side_effect = lambda key: _config.get(key)
        self.relation_ids.return_value = ['rel:1']
        self.related_units.return_value = []
        self.assertFalse(percona_utils.cluster_ready())

        # Single unit seeded
        _config = {}
        mock_seeded.return_value = True
        self.config.side_effect = lambda key: _config.get(key)
        self.relation_ids.return_value = ['rel:1']
        self.related_units.return_value = []
        self.assertTrue(percona_utils.cluster_ready())

        # When VIP configured check is_clustered
        _config = {'vip': '10.10.10.10', 'min-cluster-size': 3}
        self.config.side_effect = lambda key: _config.get(key)
        # HACluster not ready
        self.is_clustered.return_value = False
        self.assertFalse(percona_utils.cluster_ready())

        # HACluster ready peers not ready
        self.is_clustered.return_value = True
        self.related_units.return_value = ['unit/1', 'unit/2']
        self.relation_get.return_value = None
        self.assertFalse(percona_utils.cluster_ready())

        # HACluster ready one peer ready one not
        self.relation_get.side_effect = [True, True, None]
        self.assertFalse(percona_utils.cluster_ready())

        # HACluster ready one all peers ready
        self.relation_get.side_effect = [True, True, True]
        self.assertTrue(percona_utils.cluster_ready())

    @mock.patch.object(percona_utils, 'cluster_ready')
    def test_client_node_is_ready(self, mock_cluster_ready):
        # Paused
        self.is_unit_paused_set.return_value = True
        self.assertFalse(percona_utils.client_node_is_ready())

        # Cluster not ready
        mock_cluster_ready.return_value = False
        self.assertFalse(percona_utils.client_node_is_ready())

        # Not ready
        self.is_unit_paused_set.return_value = False
        mock_cluster_ready.return_value = True
        self.relation_ids.return_value = ['shared-db:0']
        self.leader_get.return_value = {}
        self.assertFalse(percona_utils.client_node_is_ready())

        # Ready
        self.is_unit_paused_set.return_value = False
        mock_cluster_ready.return_value = True
        self.relation_ids.return_value = ['shared-db:0']
        self.leader_get.return_value = {'shared-db:0_password': 'password'}
        self.assertTrue(percona_utils.client_node_is_ready())

    @mock.patch.object(percona_utils, 'cluster_ready')
    def test_leader_node_is_ready(self, mock_cluster_ready):
        # Paused
        self.is_unit_paused_set.return_value = True
        self.assertFalse(percona_utils.leader_node_is_ready())

        # Not leader
        self.is_unit_paused_set.return_value = False
        self.is_leader.return_value = False
        self.assertFalse(percona_utils.leader_node_is_ready())

        # Not cluster ready
        self.is_unit_paused_set.return_value = False
        self.is_leader.return_value = True
        mock_cluster_ready.return_value = False
        self.assertFalse(percona_utils.leader_node_is_ready())

        # Leader ready
        self.is_unit_paused_set.return_value = False
        self.is_leader.return_value = True
        mock_cluster_ready.return_value = True
        self.assertTrue(percona_utils.leader_node_is_ready())

    def test_cluster_wait(self):
        self.relation_ids.return_value = ['amqp:27']
        self.related_units.return_value = ['unit/1', 'unit/2', 'unit/3']
        # Default check peer relation
        _config = {'known-wait': 30}
        self.config.side_effect = lambda key: _config.get(key)
        percona_utils.cluster_wait()
        self.distributed_wait.assert_called_with(modulo=4, wait=30)

        # Use Min Cluster Size
        _config = {'min-cluster-size': 5, 'known-wait': 30}
        self.config.side_effect = lambda key: _config.get(key)
        percona_utils.cluster_wait()
        self.distributed_wait.assert_called_with(modulo=5, wait=30)

        # Override with modulo-nodes
        _config = {'min-cluster-size': 5, 'modulo-nodes': 10, 'known-wait': 60}
        self.config.side_effect = lambda key: _config.get(key)
        percona_utils.cluster_wait()
        self.distributed_wait.assert_called_with(modulo=10, wait=60)

        # Just modulo-nodes
        _config = {'modulo-nodes': 10, 'known-wait': 60}
        self.config.side_effect = lambda key: _config.get(key)
        percona_utils.cluster_wait()
        self.distributed_wait.assert_called_with(modulo=10, wait=60)


class TestResolveHostnameToIP(CharmTestCase):

    TO_PATCH = []

    def setUp(self):
        super(TestResolveHostnameToIP, self).setUp(percona_utils,
                                                   self.TO_PATCH)

    @mock.patch.object(percona_utils, 'is_ipv6')
    @mock.patch.object(percona_utils, 'is_ip')
    @mock.patch.object(percona_utils, 'config', lambda *args: None)
    def test_resolve_hostname_to_ip_ips(self, mock_is_ip, mock_is_ipv6):
        ipv6_address = '2a01:348:2f4:0:dba7:dc58:659b:941f'
        ipv4_address = '10.10.10.2'
        self.assertEqual(percona_utils.resolve_hostname_to_ip(ipv6_address),
                         ipv6_address)
        self.assertTrue(mock_is_ip.called)
        self.assertFalse(mock_is_ipv6.called)
        self.assertEqual(percona_utils.resolve_hostname_to_ip(ipv4_address),
                         ipv4_address)
        self.assertTrue(mock_is_ip.called)
        self.assertFalse(mock_is_ipv6.called)

    @mock.patch.object(percona_utils, 'config', lambda *args: None)
    @mock.patch('dns.resolver.query')
    def test_resolve_hostname_to_ip_hostname_a(self,
                                               dns_query):
        mock_answer = mock.MagicMock()
        mock_answer.address = '10.10.10.20'
        dns_query.return_value = [mock_answer]
        self.assertEqual(percona_utils.resolve_hostname_to_ip('myhostname'),
                         '10.10.10.20')
        dns_query.assert_has_calls([
            mock.call('myhostname', 'A'),
        ])

    @mock.patch.object(percona_utils, 'is_ipv6')
    @mock.patch.object(percona_utils, 'is_ip')
    @mock.patch.object(percona_utils, 'config')
    @mock.patch('dns.resolver.query')
    def test_resolve_hostname_to_ip_hostname_aaaa(self, dns_query, mock_config,
                                                  mock_is_ip, mock_is_ipv6):

        def fake_config(key):
            return {'prefer-ipv6': True}.get(key)

        mock_config.side_effect = fake_config
        mock_answer = mock.MagicMock()
        mock_is_ipv6.return_value = False
        mock_answer.address = '2a01:348:2f4:0:dba7:dc58:659b:941f'
        dns_query.return_value = [mock_answer]
        self.assertEqual(percona_utils.resolve_hostname_to_ip('myhostname'),
                         '2a01:348:2f4:0:dba7:dc58:659b:941f')
        self.assertFalse(mock_is_ip.called)
        self.assertTrue(mock_is_ipv6.called)
        dns_query.assert_has_calls([
            mock.call('myhostname', 'AAAA'),
        ])

    @mock.patch.object(percona_utils, 'config', lambda *args: None)
    @mock.patch('dns.resolver.query')
    def test_resolve_hostname_to_ip_hostname_noanswer(self,
                                                      dns_query):
        dns_query.return_value = []
        self.assertEqual(percona_utils.resolve_hostname_to_ip('myhostname'),
                         None)
        dns_query.assert_has_calls([
            mock.call('myhostname', 'A'),
        ])


class TestUpdateBootstrapUUID(CharmTestCase):
    TO_PATCH = [
        'log',
        'leader_get',
        'get_wsrep_value',
        'relation_ids',
        'relation_set',
        'is_leader',
        'leader_set',
        'config',
        'leader_get',
    ]

    def setUp(self):
        super(TestUpdateBootstrapUUID, self).setUp(percona_utils,
                                                   self.TO_PATCH)
        self.log.side_effect = self.juju_log

    def juju_log(self, msg, level=None):
        print("juju-log {}: {}".format(level, msg))

    def test_no_bootstrap_uuid(self):
        self.leader_get.return_value = None
        self.assertRaises(percona_utils.LeaderNoBootstrapUUIDError,
                          percona_utils.update_bootstrap_uuid)

    def test_bootstrap_uuid_already_set(self):
        self.leader_get.return_value = '1234-abcd'

        def fake_wsrep(k):
            d = {'wsrep_ready': 'ON',
                 'wsrep_cluster_state_uuid': '1234-abcd'}
            return d[k]

        self.get_wsrep_value.side_effect = fake_wsrep
        self.relation_ids.return_value = ['cluster:2']
        self.is_leader.return_value = False
        percona_utils.update_bootstrap_uuid()
        self.relation_set.assert_called_with(relation_id='cluster:2',
                                             **{'bootstrap-uuid': '1234-abcd'})
        self.leader_set.assert_not_called()

        self.is_leader.return_value = True
        percona_utils.update_bootstrap_uuid()
        self.relation_set.assert_called_with(relation_id='cluster:2',
                                             **{'bootstrap-uuid': '1234-abcd'})
        self.leader_set.assert_called_with(**{'bootstrap-uuid': '1234-abcd'})

    @mock.patch.object(percona_utils, 'notify_bootstrapped')
    def test_bootstrap_uuid_could_not_be_retrieved(self, mock_notify):
        self.leader_get.return_value = '1234-abcd'

        def fake_wsrep(k):
            d = {'wsrep_ready': 'ON',
                 'wsrep_cluster_state_uuid': ''}
            return d[k]

        self.get_wsrep_value.side_effect = fake_wsrep
        self.assertFalse(percona_utils.update_bootstrap_uuid())
        mock_notify.assert_not_called()

    def test_bootstrap_uuid_diffent_uuids(self):
        self.leader_get.return_value = '1234-abcd'

        def fake_wsrep(k):
            d = {'wsrep_ready': 'ON',
                 'wsrep_cluster_state_uuid': '5678-dead-beef'}
            return d[k]

        self.get_wsrep_value.side_effect = fake_wsrep
        self.assertRaises(percona_utils.InconsistentUUIDError,
                          percona_utils.update_bootstrap_uuid)

    @mock.patch.object(percona_utils, 'check_mysql_connection')
    @mock.patch.object(percona_utils, 'leader_set')
    @mock.patch.object(percona_utils, 'leader_get')
    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_update_root_password(self, mock_get_db_helper,
                                  mock_leader_get,
                                  mock_leader_set,
                                  mock_check_mysql_connection):
        cur_password = 'openstack'
        new_password = 'ubuntu'
        leader_config = {
            'mysql.passwd': cur_password,
            'root-password': cur_password}

        _db_helper = mock.Mock()
        _db_helper.get_mysql_password.return_value = cur_password
        mock_get_db_helper.return_value = _db_helper
        mock_leader_get.side_effect = lambda k: leader_config[k]

        self.config.side_effect = self.test_config.get
        self.assertFalse(percona_utils.update_root_password())

        _db_helper.reset_mock()
        mock_check_mysql_connection.reset_mock()
        self.test_config.set_previous('root-password', cur_password)
        self.test_config.set('root-password', new_password)
        percona_utils.update_root_password()
        _db_helper.connect.assert_called_once_with(
            password='openstack',
            user='root')
        db_exec_calls = [
            mock.call("""SET PASSWORD = PASSWORD('ubuntu');"""),
            mock.call(
                """SET PASSWORD FOR 'root'@'localhost' """
                """= PASSWORD('ubuntu');""")
        ]
        _db_helper.execute.assert_has_calls(db_exec_calls)
        mock_check_mysql_connection.assert_called_once_with(
            password='ubuntu')
        leader_set_calls = [
            mock.call({'root-password': 'ubuntu'}),
            mock.call({'mysql.passwd': 'ubuntu'})]
        mock_leader_set.assert_has_calls(leader_set_calls)

    def test_is_leader_bootstrapped_once(self):
        leader_config = {'bootstrap-uuid': None, 'mysql.passwd': None,
                         'root-password': None, 'sst-password': None}
        self.leader_get.return_value = leader_config
        self.assertFalse(percona_utils.is_leader_bootstrapped())

        leader_config = {'bootstrap-uuid': 'UUID', 'mysql.passwd': None,
                         'root-password': None, 'sst-password': None}
        self.leader_get.return_value = leader_config
        self.assertFalse(percona_utils.is_leader_bootstrapped())

        leader_config = {'bootstrap-uuid': None, 'mysql.passwd': None,
                         'root-password': 'pass', 'sst-password': None}
        self.leader_get.return_value = leader_config
        self.assertFalse(percona_utils.is_leader_bootstrapped())

        leader_config = {'bootstrap-uuid': 'UUID', 'mysql.passwd': 'pass',
                         'root-password': 'pass', 'sst-password': 'pass',
                         'leader-ip': '10.10.10.10'}
        self.leader_get.return_value = leader_config
        self.assertTrue(percona_utils.is_leader_bootstrapped())


class TestAsynchronousReplication(CharmTestCase):
    TO_PATCH = [
        'config',
        'leader_get',
        'network_get_primary_address',
        'related_units',
        'relation_get',
        'relation_ids',
    ]

    def setUp(self):
        super(TestAsynchronousReplication, self).setUp(percona_utils,
                                                       self.TO_PATCH)

    @mock.patch.object(percona_utils, 'config')
    def test_get_databases_to_replicate_no_config_id(self, mock_config):
        config = {}
        mock_config.side_effect = lambda k: config.get(k)
        with self.assertRaises(percona_utils.ClusterIDRequired):
            percona_utils.get_databases_to_replicate()

    @mock.patch.object(percona_utils, 'config')
    def test_get_databases_to_replicate(self, mock_config):
        config = {
            'cluster-id': 3,
            'databases-to-replicate': 'db1:tb1,tb2;db2'}
        mock_config.side_effect = lambda k: config.get(k)
        percona_utils.get_databases_to_replicate()
        self.assertEqual(percona_utils.get_databases_to_replicate(),
                         ([{'database': 'db1', 'tables': ['tb1', 'tb2']},
                           {'database': 'db2', 'tables': []}]))

    @mock.patch.object(percona_utils, 'config')
    def test_get_databases_to_replicate_many(self, mock_config):
        config = {
            'cluster-id': 3,
            'databases-to-replicate': 'db1:tb1;db2:tb2;db3;db4;db5:tb5,tb6'}
        mock_config.side_effect = lambda k: config.get(k)
        percona_utils.get_databases_to_replicate()
        self.assertEqual(percona_utils.get_databases_to_replicate(),
                         ([{'database': 'db1', 'tables': ['tb1']},
                           {'database': 'db2', 'tables': ['tb2']},
                           {'database': 'db3', 'tables': []},
                           {'database': 'db4', 'tables': []},
                           {'database': 'db5', 'tables': ['tb5', 'tb6']}
                           ]))

    @mock.patch.object(percona_utils, 'config')
    def test_get_databases_to_replicate_space(self, mock_config):
        config = {
            'cluster-id': 3,
            'databases-to-replicate': 'db1 tb1; db2,tb2;db3:db4'}
        mock_config.side_effect = lambda k: config.get(k)
        with self.assertRaises(percona_utils.InvalidDatabasesToReplicate):
            percona_utils.get_databases_to_replicate()

    @mock.patch.object(percona_utils, 'config')
    def test_get_databases_to_replicate_comma(self, mock_config):
        config = {
            'cluster-id': 3,
            'databases-to-replicate': 'db1:tb1;db2,tb2;db3:db4'}
        mock_config.side_effect = lambda k: config.get(k)
        with self.assertRaises(percona_utils.InvalidDatabasesToReplicate):
            percona_utils.get_databases_to_replicate()

    @mock.patch.object(percona_utils, 'create_replication_user')
    @mock.patch.object(percona_utils, 'list_replication_users')
    def test_configure_master_slave_address_not_in_relation_data(
            self, mock_list_replication_users, mock_create_replication_user):
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [1, 2, 3]
        self.relation_get.return_value = None
        percona_utils.configure_master()
        mock_create_replication_user.assert_not_called()

    @mock.patch.object(percona_utils, 'create_replication_user')
    @mock.patch.object(percona_utils, 'list_replication_users')
    def test_configure_master_slave_address_in_relation_data_and_created(
            self, mock_list_replication_users, mock_create_replication_user):
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [1, 2, 3]

        def _mock_rel_get(*args, **kwargs):
            unit_id = kwargs.get('unit')
            return '10.0.1.{}'.format(unit_id)

        self.relation_get.side_effect = _mock_rel_get
        mock_list_replication_users.return_value = ['10.0.1.1',
                                                    '10.0.1.2',
                                                    '10.0.1.3']
        percona_utils.configure_master()
        mock_create_replication_user.assert_not_called()

    @mock.patch.object(percona_utils, 'create_replication_user')
    @mock.patch.object(percona_utils, 'list_replication_users')
    def test_configure_master_slave_address_in_relation_data_and_not_created(
            self, mock_list_replication_users, mock_create_replication_user):
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [1, 2, 3]

        def _mock_rel_get(*args, **kwargs):
            unit_id = kwargs.get('unit')
            return '10.0.1.{}'.format(unit_id)

        self.relation_get.side_effect = _mock_rel_get
        mock_list_replication_users.return_value = ['10.0.1.1', '10.0.1.2']
        self.leader_get.return_value = 'password'
        percona_utils.configure_master()
        mock_create_replication_user.assert_called_once_with('10.0.1.3',
                                                             'password')

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_configure_slave_no_leader(
            self, mock_get_db_helper):
        my_mock = mock.Mock()
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [1, 2, 3]

        def _mock_rel_get(*args, **kwargs):
            return {'private-address': '10.0.0.1'}

        self.relation_get.side_effect = _mock_rel_get
        mock_get_db_helper.return_value = my_mock
        percona_utils.configure_slave()
        my_mock.execute.assert_not_called()

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_configure_slave_leader_and_no_full_relation_data(
            self, mock_get_db_helper):
        my_mock = mock.Mock()
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [1, 2, 3]

        def _mock_rel_get(*args, **kwargs):
            return {'private-address': '10.0.0.1',
                    'leader': True}

        self.relation_get.side_effect = _mock_rel_get
        mock_get_db_helper.return_value = my_mock
        percona_utils.configure_slave()
        my_mock.execute.assert_not_called()

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_configure_slave_leader_and_full_relation_data(
            self, mock_get_db_helper):
        my_mock = mock.Mock()
        self.relation_ids.return_value = [1]
        self.related_units.return_value = [1, 2, 3]

        def _mock_rel_get(*args, **kwargs):
            return {'private-address': '10.0.0.1',
                    'leader': True,
                    'master_address': '10.0.0.1',
                    'master_file': 'file',
                    'master_password': 'password',
                    'master_position': 'position'}

        self.relation_get.side_effect = _mock_rel_get
        mock_get_db_helper.return_value = my_mock
        sql1 = "STOP SLAVE;"
        sql2 = ("CHANGE MASTER TO "
                "master_host='10.0.0.1', "
                "master_port=3306, "
                "master_user='replication', "
                "master_password='password', "
                "master_log_file='file', "
                "master_log_pos=position;")
        sql3 = "START SLAVE;"
        percona_utils.configure_slave()
        my_mock.execute.assert_any_call(sql1)
        my_mock.execute.assert_any_call(sql2)
        my_mock.execute.assert_any_call(sql3)

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_deconfigure_slave(self, mock_get_db_helper):
        my_mock = mock.Mock()
        mock_get_db_helper.return_value = my_mock
        sql1 = "STOP SLAVE;"
        sql2 = "RESET SLAVE ALL;"
        percona_utils.deconfigure_slave()
        my_mock.execute.assert_any_call(sql1)
        my_mock.execute.assert_any_call(sql2)

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_get_master_status(self, mock_get_db_helper):
        my_mock = mock.Mock()
        self.network_get_primary_address.return_value = '10.0.0.1'
        mock_get_db_helper.return_value = my_mock
        my_mock.select.return_value = [['file', 'position']]
        self.assertEqual(percona_utils.get_master_status('master'),
                         ('10.0.0.1', 'file', 'position'))

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_get_slave_status(self, mock_get_db_helper):
        my_mock = mock.Mock()
        mock_get_db_helper.return_value = my_mock
        my_mock.select.return_value = [['state', '10.0.0.1']]
        self.assertEqual(percona_utils.get_slave_status(), ('10.0.0.1'))

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_create_replication_user(self, mock_get_db_helper):
        my_mock = mock.Mock()
        slave_address = '10.0.1.1'
        master_password = 'password'
        mock_get_db_helper.return_value = my_mock
        sql = ("GRANT REPLICATION SLAVE ON *.* TO 'replication'@'{}' "
               "IDENTIFIED BY '{}';").format(slave_address, master_password)
        percona_utils.create_replication_user(slave_address, master_password)
        my_mock.execute.assert_called_with(sql)

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_delete_replication_user(self, mock_get_db_helper):
        my_mock = mock.Mock()
        slave_address = '10.0.1.1'
        mock_get_db_helper.return_value = my_mock
        sql = ("DELETE FROM mysql.user WHERE Host='{}' AND "
               "User='replication';").format(slave_address)
        percona_utils.delete_replication_user(slave_address)
        my_mock.execute.assert_called_with(sql)

    @mock.patch.object(percona_utils, 'get_db_helper')
    def test_list_replication_users(self, mock_get_db_helper):
        my_mock = mock.Mock()
        mock_get_db_helper.return_value = my_mock
        my_mock.select.return_value = [['10.0.0.1'], ['10.0.0.2']]
        self.assertEqual(percona_utils.list_replication_users(),
                         (['10.0.0.1', '10.0.0.2']))
