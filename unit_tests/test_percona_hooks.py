import mock
import shutil
import sys
import tempfile

from test_utils import CharmTestCase

sys.modules['MySQLdb'] = mock.Mock()
# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
sys.modules['apt'] = mock.Mock()

with mock.patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    import percona_hooks as hooks


TO_PATCH = ['log', 'config',
            'get_db_helper',
            'relation_ids',
            'relation_set',
            'update_nrpe_config',
            'get_iface_for_address',
            'get_netmask_for_address',
            'is_bootstrapped',
            'network_get_primary_address',
            'resolve_network_cidr',
            'unit_get',
            'resolve_hostname_to_ip',
            'is_clustered',
            'get_ipv6_addr',
            'get_hacluster_config',
            'update_dns_ha_resource_params',
            'sst_password',
            'seeded',
            'is_leader',
            'leader_node_is_ready',
            'get_db_helper',
            'peer_store_and_set',
            'leader_get',
            'relation_clear',
            'is_relation_made',
            'is_sufficient_peers',
            'peer_retrieve_by_prefix',
            'client_node_is_ready',
            'relation_set',
            'relation_get']


class TestSharedDBRelation(CharmTestCase):

    def setUp(self):
        CharmTestCase.setUp(self, hooks, TO_PATCH)
        self.network_get_primary_address.side_effect = NotImplementedError
        self.sst_password.return_value = 'ubuntu'

    def test_allowed_units_non_leader(self):
        self.seeded.return_value = True
        self.is_leader.return_value = False
        self.client_node_is_ready.return_value = True
        self.is_relation_made.return_value = True
        self.relation_ids.return_value = ['shared-db:3']
        self.peer_retrieve_by_prefix.return_value = {
            'password': 'pass123',
            'allowed_units': 'keystone/1 keystone/2'}
        hooks.shared_db_changed()
        self.relation_set.assert_called_once_with(
            allowed_units='keystone/1 keystone/2',
            password='pass123',
            relation_id='shared-db:3')

    @mock.patch.object(hooks, 'get_db_host')
    @mock.patch.object(hooks, 'configure_db_for_hosts')
    def test_allowed_units_leader(self, configure_db_for_hosts, get_db_host):
        self.config.return_value = None
        allowed_unit_mock = mock.MagicMock()
        allowed_unit_mock.get_allowed_units.return_value = [
            'keystone/1',
            'keystone/2']
        self.get_db_helper.return_value = allowed_unit_mock
        self.test_config.set('access-network', None)
        self.seeded.return_value = True
        self.is_leader.return_value = True
        self.resolve_hostname_to_ip.return_value = '10.0.0.10'
        self.relation_get.return_value = {
            'hostname': 'keystone-0',
            'database': 'keystone',
            'username': 'keyuser',
        }
        get_db_host.return_value = 'dbhost1'
        configure_db_for_hosts.return_value = 'password'
        hooks.shared_db_changed()
        self.relation_set.assert_called_once_with(
            allowed_units='keystone/1 keystone/2',
            relation_id=None)
        calls = [
            mock.call(
                relation_id=None,
                relation_settings={'access-network': None}),
            mock.call(
                relation_id=None,
                db_host='dbhost1',
                password='password',
                allowed_units='keystone/1 keystone/2')
        ]
        self.peer_store_and_set.assert_has_calls(calls)


class TestHARelation(CharmTestCase):
    def setUp(self):
        CharmTestCase.setUp(self, hooks, TO_PATCH)
        self.network_get_primary_address.side_effect = NotImplementedError
        self.sst_password.return_value = 'ubuntu'

    def test_resources(self):
        self.relation_ids.return_value = ['ha:1']
        password = 'ubuntu'
        helper = mock.Mock()
        attrs = {'get_mysql_password.return_value': password}
        helper.configure_mock(**attrs)
        self.get_db_helper.return_value = helper
        self.get_netmask_for_address.return_value = None
        self.get_iface_for_address.return_value = None
        self.test_config.set('vip', '10.0.3.3')
        self.get_hacluster_config.return_value = {
            'vip': '10.0.3.3',
            'ha-bindiface': 'eth0',
            'ha-mcastport': 5490,
        }

        def f(k):
            return self.test_config.get(k)

        self.config.side_effect = f
        hooks.ha_relation_joined()

        resources = {'res_mysql_vip': 'ocf:heartbeat:IPaddr2',
                     'res_mysql_monitor': 'ocf:percona:mysql_monitor'}
        resource_params = {'res_mysql_vip': ('params ip="10.0.3.3" '
                                             'cidr_netmask="24" '
                                             'nic="eth0"'),
                           'res_mysql_monitor':
                           hooks.RES_MONITOR_PARAMS % {'sstpass': 'ubuntu'}}
        groups = {'grp_percona_cluster': 'res_mysql_vip'}

        clones = {'cl_mysql_monitor': 'res_mysql_monitor meta interleave=true'}

        colocations = {'colo_percona_cluster': 'inf: grp_percona_cluster cl_mysql_monitor'}  # noqa

        locations = {'loc_percona_cluster':
                     'grp_percona_cluster rule inf: writable eq 1'}

        self.relation_set.assert_called_with(
            relation_id='ha:1', corosync_bindiface=f('ha-bindiface'),
            corosync_mcastport=f('ha-mcastport'), resources=resources,
            resource_params=resource_params, groups=groups,
            clones=clones, colocations=colocations, locations=locations)

    def test_resource_params_vip_cidr_iface_autodetection(self):
        """
        Auto-detected values for vip_cidr and vip_iface are used to configure
        VIPs, even when explicit config options are provided.
        """
        self.relation_ids.return_value = ['ha:1']
        helper = mock.Mock()
        self.get_db_helper.return_value = helper
        self.get_netmask_for_address.return_value = '20'
        self.get_iface_for_address.return_value = 'eth1'
        self.test_config.set('vip', '10.0.3.3')
        self.test_config.set('vip_cidr', '16')
        self.test_config.set('vip_iface', 'eth0')
        self.get_hacluster_config.return_value = {
            'vip': '10.0.3.3',
            'ha-bindiface': 'eth0',
            'ha-mcastport': 5490,
        }

        def f(k):
            return self.test_config.get(k)

        self.config.side_effect = f
        hooks.ha_relation_joined()

        resource_params = {'res_mysql_vip': ('params ip="10.0.3.3" '
                                             'cidr_netmask="20" '
                                             'nic="eth1"'),
                           'res_mysql_monitor':
                           hooks.RES_MONITOR_PARAMS % {'sstpass': 'ubuntu'}}

        call_args, call_kwargs = self.relation_set.call_args
        self.assertEqual(resource_params, call_kwargs['resource_params'])

    def test_resource_params_no_vip_cidr_iface_autodetection(self):
        """
        When autodetecting vip_cidr and vip_iface fails, values from
        vip_cidr and vip_iface config options are used instead.
        """
        self.relation_ids.return_value = ['ha:1']
        helper = mock.Mock()
        self.get_db_helper.return_value = helper
        self.get_netmask_for_address.return_value = None
        self.get_iface_for_address.return_value = None
        self.test_config.set('vip', '10.0.3.3')
        self.test_config.set('vip_cidr', '16')
        self.test_config.set('vip_iface', 'eth1')
        self.get_hacluster_config.return_value = {
            'vip': '10.0.3.3',
            'ha-bindiface': 'eth1',
            'ha-mcastport': 5490,
        }

        def f(k):
            return self.test_config.get(k)

        self.config.side_effect = f
        hooks.ha_relation_joined()

        resource_params = {'res_mysql_vip': ('params ip="10.0.3.3" '
                                             'cidr_netmask="16" '
                                             'nic="eth1"'),
                           'res_mysql_monitor':
                           hooks.RES_MONITOR_PARAMS % {'sstpass': 'ubuntu'}}

        call_args, call_kwargs = self.relation_set.call_args
        self.assertEqual(resource_params, call_kwargs['resource_params'])


class TestHostResolution(CharmTestCase):
    def setUp(self):
        CharmTestCase.setUp(self, hooks, TO_PATCH)
        self.network_get_primary_address.side_effect = NotImplementedError
        self.is_clustered.return_value = False
        self.config.side_effect = self.test_config.get
        self.test_config.set('prefer-ipv6', False)

    def test_get_db_host_defaults(self):
        '''
        Ensure that with nothing other than defaults private-address is used
        '''
        self.unit_get.return_value = 'mydbhost'
        self.resolve_hostname_to_ip.return_value = '10.0.0.2'
        self.assertEqual(hooks.get_db_host('myclient'), 'mydbhost')

    def test_get_db_host_network_spaces(self):
        '''
        Ensure that if the shared-db relation is bound, its bound address
        is used
        '''
        self.resolve_hostname_to_ip.return_value = '10.0.0.2'
        self.network_get_primary_address.side_effect = None
        self.network_get_primary_address.return_value = '192.168.20.2'
        self.assertEqual(hooks.get_db_host('myclient'), '192.168.20.2')
        self.network_get_primary_address.assert_called_with('shared-db')

    def test_get_db_host_network_spaces_clustered(self):
        '''
        Ensure that if the shared-db relation is bound and the unit is
        clustered, that the correct VIP is chosen
        '''
        self.resolve_hostname_to_ip.return_value = '10.0.0.2'
        self.is_clustered.return_value = True
        self.test_config.set('vip', '10.0.0.100 192.168.20.200')
        self.network_get_primary_address.side_effect = None
        self.network_get_primary_address.return_value = '192.168.20.2'
        self.resolve_network_cidr.return_value = '192.168.20.2/24'
        self.assertEqual(hooks.get_db_host('myclient'), '192.168.20.200')
        self.network_get_primary_address.assert_called_with('shared-db')


class TestNRPERelation(CharmTestCase):
    def setUp(self):
        patch_targets_nrpe = TO_PATCH[:]
        patch_targets_nrpe.remove("update_nrpe_config")
        patch_targets_nrpe.append("nrpe")
        patch_targets_nrpe.append("apt_install")
        CharmTestCase.setUp(self, hooks, patch_targets_nrpe)

    def test_mysql_monitored(self):
        """The mysql service is monitored by Nagios."""
        hooks.update_nrpe_config()
        self.nrpe.add_init_service_checks.assert_called_once_with(
            mock.ANY, ["mysql"], mock.ANY)


class TestConfigChanged(CharmTestCase):

    TO_PATCH = [
        'log',
        'open_port',
        'config',
        'is_unit_paused_set',
        'get_cluster_hosts',
        'is_leader_bootstrapped',
        'is_bootstrapped',
        'clustered_once',
        'is_leader',
        'is_sufficient_peers',
        'render_config_restart_on_changed',
        'update_client_db_relations',
        'install_mysql_ocf',
        'relation_ids',
        'is_relation_made',
        'ha_relation_joined',
        'update_nrpe_config',
        'assert_charm_supports_ipv6',
        'update_bootstrap_uuid',
        'update_root_password',
        'install_percona_xtradb_cluster',
        'get_cluster_hosts',
        'leader_get',
        'set_ready_on_peers',
        'is_unit_paused_set',
        'is_unit_upgrading_set',
    ]

    def setUp(self):
        CharmTestCase.setUp(self, hooks, self.TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.is_unit_paused_set.return_value = False
        self.is_unit_upgrading_set.return_value = False
        self.is_leader.return_value = False
        self.is_leader_bootstrapped.return_value = False
        self.is_bootstrapped.return_value = False
        self.clustered_once.return_value = False
        self.relation_ids.return_value = []
        self.is_relation_made.return_value = False
        self.get_cluster_hosts.return_value = []

        def _leader_get(key):
            settings = {'leader-ip': '10.10.10.10',
                        'cluster_series_upgrading': False}
            return settings.get(key)
        self.leader_get.side_effect = _leader_get

    def test_config_changed_open_port(self):
        '''Ensure open_port is called with MySQL default port'''
        self.is_leader_bootstrapped.return_value = True
        hooks.config_changed()
        self.open_port.assert_called_with(3306)

    def test_config_changed_render_leader(self):
        '''Ensure configuration is only rendered when ready for the leader'''
        self.is_leader.return_value = True

        # Render without peers, leader not bootsrapped
        self.get_cluster_hosts.return_value = []
        hooks.config_changed()
        self.install_percona_xtradb_cluster.assert_called_once()
        self.render_config_restart_on_changed.assert_called_once_with(
            [], bootstrap=True)

        # Render without peers, leader bootstrapped
        self.is_leader_bootstrapped.return_value = True
        self.get_cluster_hosts.return_value = []
        self.render_config_restart_on_changed.reset_mock()
        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            [], bootstrap=False)

        # Render without hosts, leader bootstrapped, never clustered
        self.is_leader_bootstrapped.return_value = True
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30']

        self.render_config_restart_on_changed.reset_mock()
        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            [], bootstrap=False)

        # Clustered at least once
        self.clustered_once.return_value = True

        # Render with hosts, leader bootstrapped
        self.is_leader_bootstrapped.return_value = True
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30']

        self.render_config_restart_on_changed.reset_mock()
        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            ['10.10.10.20', '10.10.10.30'], bootstrap=False)

        # In none of the prior scenarios should update_root_password have been
        # called.
        self.update_root_password.assert_not_called()

        # Render with hosts, leader and cluster bootstrapped
        self.is_leader_bootstrapped.return_value = True
        self.is_bootstrapped.return_value = True
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30']

        self.render_config_restart_on_changed.reset_mock()
        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            ['10.10.10.20', '10.10.10.30'], bootstrap=False)
        self.update_root_password.assert_called_once()

    def test_config_changed_render_non_leader(self):
        '''Ensure configuration is only rendered when ready for
        non-leaders'''

        # Avoid rendering for non-leader.
        # Bug #1738896
        # Leader not bootstrapped
        # Do not render
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30',
                                               '10.10.10.10']
        self.is_leader_bootstrapped.return_value = False
        hooks.config_changed()
        self.install_percona_xtradb_cluster.assert_called_once_with()
        self.render_config_restart_on_changed.assert_not_called()
        self.update_bootstrap_uuid.assert_not_called()

        # Leader is bootstrapped, insufficient peers
        # Do not render
        self.is_sufficient_peers.return_value = False
        self.is_leader_bootstrapped.return_value = True
        self.render_config_restart_on_changed.reset_mock()
        self.install_percona_xtradb_cluster.reset_mock()

        hooks.config_changed()
        self.install_percona_xtradb_cluster.assert_called_once_with()
        self.render_config_restart_on_changed.assert_not_called()
        self.update_bootstrap_uuid.assert_not_called()

        # Leader is bootstrapped, sufficient peers
        # Use the leader node and render.
        self.is_sufficient_peers.return_value = True
        self.is_leader_bootstrapped.return_value = True
        self.get_cluster_hosts.return_value = []
        self.render_config_restart_on_changed.reset_mock()
        self.install_percona_xtradb_cluster.reset_mock()

        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            ['10.10.10.10'])

        # Missing leader, leader bootstrapped
        # Bug #1738896
        # Leader bootstrapped
        # Add the leader node and render.
        self.render_config_restart_on_changed.reset_mock()
        self.update_bootstrap_uuid.reset_mock()
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30']

        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            ['10.10.10.10', '10.10.10.20', '10.10.10.30'])
        self.update_bootstrap_uuid.assert_called_once()

        # Leader present, leader bootstrapped
        self.render_config_restart_on_changed.reset_mock()
        self.update_bootstrap_uuid.reset_mock()
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30',
                                               '10.10.10.10']

        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            ['10.10.10.20', '10.10.10.30', '10.10.10.10'])
        self.update_bootstrap_uuid.assert_called_once()

        # In none of the prior scenarios should update_root_password have been
        # called. is_bootstrapped was defaulted to False
        self.update_root_password.assert_not_called()
        self.set_ready_on_peers.assert_not_called()

        # Leader present, leader bootstrapped, cluster bootstrapped
        self.is_bootstrapped.return_value = True
        self.render_config_restart_on_changed.reset_mock()
        self.update_bootstrap_uuid.reset_mock()
        self.get_cluster_hosts.return_value = ['10.10.10.20', '10.10.10.30',
                                               '10.10.10.10']

        hooks.config_changed()
        self.render_config_restart_on_changed.assert_called_once_with(
            ['10.10.10.20', '10.10.10.30', '10.10.10.10'])
        self.update_bootstrap_uuid.assert_called_once()
        self.update_root_password.assert_called_once()
        self.set_ready_on_peers.called_once()


class TestInstallPerconaXtraDB(CharmTestCase):

    TO_PATCH = [
        'log',
        'pxc_installed',
        'root_password',
        'sst_password',
        'configure_mysql_root_password',
        'apt_install',
        'determine_packages',
        'configure_sstuser',
        'config',
        'run_mysql_checks',
        'is_leader_bootstrapped',
        'is_leader',
    ]

    def setUp(self):
        CharmTestCase.setUp(self, hooks, self.TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.pxc_installed.return_value = False

    def test_installed(self):
        self.pxc_installed.return_value = True
        hooks.install_percona_xtradb_cluster()
        self.configure_mysql_root_password.assert_not_called()
        self.apt_install.assert_not_called()

    def test_passwords_not_initialized(self):
        self.root_password.return_value = None
        self.sst_password.return_value = None
        hooks.install_percona_xtradb_cluster()
        self.configure_mysql_root_password.assert_not_called()
        self.configure_sstuser.assert_not_called()
        self.apt_install.assert_not_called()
        self.is_leader_bootstrapped.return_value = True

        self.root_password.return_value = None
        self.sst_password.return_value = 'testpassword'
        hooks.install_percona_xtradb_cluster()
        self.configure_sstuser.assert_not_called()
        self.configure_mysql_root_password.assert_not_called()
        self.apt_install.assert_not_called()

    def test_passwords_initialized(self):
        self.root_password.return_value = 'rootpassword'
        self.sst_password.return_value = 'testpassword'
        self.determine_packages.return_value = ['pxc-5.6']
        self.is_leader_bootstrapped.return_value = True
        hooks.install_percona_xtradb_cluster()
        self.configure_mysql_root_password.assert_called_with('rootpassword')
        self.configure_sstuser.assert_called_with('testpassword')
        self.apt_install.assert_called_with(['pxc-5.6'], fatal=True)
        self.run_mysql_checks.assert_not_called()


class TestUpgradeCharm(CharmTestCase):
    TO_PATCH = [
        'config',
        'log',
        'is_leader',
        'is_unit_paused_set',
        'get_wsrep_value',
        'config_changed',
        'get_relation_ip',
        'leader_set',
        'sst_password',
        'configure_sstuser',
        'leader_get',
        'notify_bootstrapped',
        'mark_seeded',
    ]

    def print_log(self, msg, level=None):
        print('juju-log: %s: %s' % (level, msg))

    def setUp(self):
        CharmTestCase.setUp(self, hooks, self.TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.log.side_effect = self.print_log
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        CharmTestCase.tearDown(self)
        try:
            shutil.rmtree(self.tmpdir)
        except:
            pass

    def test_upgrade_charm_leader(self):
        self.is_leader.return_value = True
        self.is_unit_paused_set.return_value = False
        self.get_relation_ip.return_value = '10.10.10.10'
        self.leader_get.side_effect = [None, 'mypasswd', 'mypasswd']

        def c(k):
            values = {'wsrep_ready': 'on',
                      'wsrep_cluster_state_uuid': '1234-abcd'}
            return values[k]

        self.get_wsrep_value.side_effect = c

        hooks.upgrade()

        self.mark_seeded.assert_called_once()
        self.notify_bootstrapped.assert_called_with(cluster_uuid='1234-abcd')
        self.configure_sstuser.assert_called_once()

        self.leader_set.assert_has_calls(
            [mock.call(**{'leader-ip': '10.10.10.10'}),
             mock.call(**{'root-password': 'mypasswd'})])
