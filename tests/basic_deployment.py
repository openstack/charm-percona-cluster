# basic deployment test class for percona-xtradb-cluster

import amulet
import re
import os
import socket
import time
import telnetlib
import yaml
from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)
from charmhelpers.contrib.amulet.utils import AmuletUtils

PXC_ROOT_PASSWD = 'ubuntu'


class BasicDeployment(OpenStackAmuletDeployment):

    utils = AmuletUtils()

    def __init__(self, vip=None, units=1, series="trusty", openstack=None,
                 source=None, stable=True):
        super(BasicDeployment, self).__init__(series, openstack, source,
                                              stable)
        self.units = units
        self.master_unit = None
        self.vip = None
        self.ha = False
        if units > 1:
            self.ha = True
            if vip:
                self.vip = vip
            elif 'AMULET_OS_VIP' in os.environ:
                self.vip = os.environ.get('AMULET_OS_VIP')
            elif os.path.isfile('local.yaml'):
                with open('local.yaml', 'rb') as f:
                    self.cfg = yaml.safe_load(f.read())

                self.vip = self.cfg.get('vip')
            else:
                amulet.raise_status(amulet.SKIP,
                                    ("Please set the vip in local.yaml or "
                                     "env var AMULET_OS_VIP to run this test "
                                     "suite"))
        self.log = self.utils.get_logger()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where percona-cluster is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'percona-cluster',
                        'units': self.units}
        other_services = []
        if self.units > 1 and self.ha:
            other_services.append({'name': 'hacluster'})

        super(BasicDeployment, self)._add_services(this_service,
                                                   other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""

        if self.units > 1 and self.ha:
            relations = {'percona-cluster:ha': 'hacluster:ha'}
            super(BasicDeployment, self)._add_relations(relations)

    def _get_configs(self):
        """Configure all of the services."""
        cfg_percona = {'min-cluster-size': self.units,
                       'vip': self.vip,
                       'root-password': PXC_ROOT_PASSWD}

        cfg_ha = {'debug': True,
                  'corosync_key': ('xZP7GDWV0e8Qs0GxWThXirNNYlScgi3sRTdZk/IXKD'
                                   'qkNFcwdCWfRQnqrHU/6mb6sz6OIoZzX2MtfMQIDcXu'
                                   'PqQyvKuv7YbRyGHmQwAWDUA4ed759VWAO39kHkfWp9'
                                   'y5RRk/wcHakTcWYMwm70upDGJEP00YT3xem3NQy27A'
                                   'C1w=')}

        configs = {}
        if self.units > 1 and self.ha:
            cfg_ha['cluster_count'] = str(self.units)
            configs['hacluster'] = cfg_ha
        configs['percona-cluster'] = cfg_percona

        return configs

    def _configure_services(self):
        super(BasicDeployment, self)._configure_services(self._get_configs())

    def run(self):
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self.d.sentry.wait()
        self.test_deployment()

    def test_deployment(self):
        '''Top level test function executor'''
        self.test_pacemaker()
        self.test_pxc_running()
        self.test_bootstrapped_and_clustered()
        self.test_bootstrap_uuid_set_in_the_relation()
        self.test_restart_on_config_change()
        self.test_pause_resume()
        if self.ha:
            self.test_kill_master()

    def test_pacemaker(self):
        '''
        Ensure that pacemaker and corosync are correctly configured in
        clustered deployments.

        side effect: self.master_unit should be set after execution
        '''

        if self.units > 1 and self.ha:
            i = 0
            while i < 30 and not self.master_unit:
                self.master_unit = self.find_master(ha=self.ha)
                i += 1
                time.sleep(10)

            msg = 'percona-cluster vip not found'
            assert self.master_unit is not None, msg

            _, code = self.master_unit.run('sudo crm_verify --live-check')
            assert code == 0, "'crm_verify --live-check' failed"

            resources = ['res_mysql_vip']
            resources += ['res_mysql_monitor:%d' %
                          m for m in range(self.units)]

            assert sorted(self.get_pcmkr_resources()) == sorted(resources)
        else:
            self.master_unit = self.find_master(ha=self.ha)

    def test_pxc_running(self):
        '''
        Ensure PXC is running on all units
        '''
        for unit in self.d.sentry['percona-cluster']:
            assert self.is_mysqld_running(unit), 'mysql not running: %s' % unit

    def test_bootstrapped_and_clustered(self):
        '''
        Ensure PXC is bootstrapped and that peer units are clustered
        '''
        self.log.info('Ensuring PXC is bootstrapped')
        msg = "Percona cluster failed to bootstrap"
        assert self.is_pxc_bootstrapped(), msg

        self.log.info('Checking PXC cluster size == {}'.format(self.units))
        got = int(self.get_cluster_size())
        msg = ("Percona cluster unexpected size"
               " (wanted=%s, got=%s)" % (self.units, got))
        assert got == self.units, msg

    def test_bootstrap_uuid_set_in_the_relation(self):
        """Verify that the bootstrap-uuid attribute was set by the leader and
        all the peers where notified.
        """
        (leader_uuid, code) = self.master_unit.run("leader-get bootstrap-uuid")
        assert leader_uuid

        cmd_rel_get = ("relation-get -r `relation-ids cluster` "
                       "bootstrap-uuid %s")
        units = self.d.sentry['percona-cluster']
        for unit in units:
            for peer in units:
                cmd = cmd_rel_get % peer.info['unit_name']
                self.log.debug(cmd)
                (output, code) = unit.run(cmd)
                assert code == 0
                assert output == leader_uuid, "%s != %s" % (output,
                                                            leader_uuid)

    def test_pause_resume(self):
        '''
        Ensure pasue/resume actions stop/start mysqld on units
        '''
        self.log.info('Testing pause/resume actions')
        self.log.info('Pausing service on first PXC unit')
        unit = self.d.sentry['percona-cluster'][0]
        assert self.is_mysqld_running(unit), 'mysql not running'
        assert self.utils.status_get(unit)[0] == "active"

        action_id = self.utils.run_action(unit, "pause")
        assert self.utils.wait_on_action(action_id), "Pause action failed."
        self.d.sentry.wait()

        # Note that is_mysqld_running will print an error message when
        # mysqld is not running.  This is by design but it looks odd
        # in the output.
        assert not self.is_mysqld_running(unit=unit), \
            "mysqld is still running!"

        self.log.info('Resuming service on first PXC unit')
        assert self.utils.status_get(unit)[0] == "maintenance"
        action_id = self.utils.run_action(unit, "resume")
        assert self.utils.wait_on_action(action_id), "Resume action failed"
        assert self.utils.status_get(unit)[0] == "active"
        assert self.is_mysqld_running(unit=unit), \
            "mysqld not running after resume."
        self._auto_wait_for_status()

    def test_kill_master(self):
        '''
        Ensure that killing the mysqld on the master unit results
        in a VIP failover
        '''
        self.log.info('Testing failover of master unit on mysqld failure')
        # we are going to kill the master
        old_master = self.master_unit
        self.log.info(
            'kill -9 mysqld on {}'.format(self.master_unit.info['unit_name'])
        )
        self.master_unit.run('sudo killall -9 mysqld')

        self.log.info('looking for the new master')
        i = 0
        changed = False
        while i < 10 and not changed:
            i += 1
            time.sleep(5)  # give some time to pacemaker to react
            new_master = self.find_master(ha=self.ha)

            if (new_master and new_master.info['unit_name'] !=
                    old_master.info['unit_name']):
                self.log.info(
                    'New master unit detected'
                    ' on {}'.format(new_master.info['unit_name'])
                )
                changed = True

        assert changed, "The master didn't change"

        assert self.is_port_open(address=self.vip), 'cannot connect to vip'

    def test_change_root_password(self):
        """
        Change root password and verify the change was effectively applied.
        """

        new_root_passwd = 'openstack'

        u = self.master_unit
        root_password, _ = PXC_ROOT_PASSWD
        cmd = "mysql -uroot -p{} -e\"select 1;\" ".format(root_password)
        output, code = u.run(cmd)

        assert code == 0, output

        self.d.configure('percona-cluster', {'root-password': new_root_passwd})

        time.sleep(5)  # give some time to the unit to start the hook
        self.d.sentry.wait()  # wait until the hook finishes

        # try to connect using the new root password
        cmd = "mysql -uroot -p{} -e\"select 1;\" ".format(new_root_passwd)
        output, code = u.run(cmd)

        assert code == 0, output

    def find_master(self, ha=True):
        for unit in self.d.sentry['percona-cluster']:
            if not ha:
                return unit

            # is the vip running here?
            output, code = unit.run('sudo ip a | grep "inet %s/"' % self.vip)
            self.log.info("Checking {}".format(unit.info['unit_name']))
            self.log.debug(output)
            if code == 0:
                self.log.info('vip ({}) running in {}'.format(
                    self.vip,
                    unit.info['unit_name'])
                )
                return unit

    def get_pcmkr_resources(self, unit=None):
        if unit:
            u = unit
        else:
            u = self.master_unit

        output, code = u.run('sudo crm_resource -l')

        assert code == 0, 'could not get "crm resource list"'

        return output.split('\n')

    def is_mysqld_running(self, unit=None):
        if unit:
            u = unit
        else:
            u = self.master_unit

        _, code = u.run('pidof mysqld')
        if code != 0:
            self.log.debug("command returned non-zero '%s'" % (code))
            return False

        return True

    def get_wsrep_value(self, attr, unit=None):
        if unit:
            u = unit
        else:
            u = self.master_unit
        root_password, _ = u.run('leader-get root-password')
        cmd = ("mysql -uroot -p{} -e\"show status like '{}';\"| "
               "grep {}".format(root_password, attr, attr))
        output, code = u.run(cmd)
        if code != 0:
            self.log.debug("command returned non-zero '%s'" % (code))
            return ""

        value = re.search(r"^.+?\s+(.+)", output).group(1)
        self.log.info("%s = %s" % (attr, value))
        return value

    def is_pxc_bootstrapped(self, unit=None):
        value = self.get_wsrep_value('wsrep_ready', unit)
        return value.lower() in ['on', 'ready']

    def get_cluster_size(self, unit=None):
        return self.get_wsrep_value('wsrep_cluster_size', unit)

    def is_port_open(self, unit=None, port='3306', address=None):
        if unit:
            addr = unit.info['public-address']
        elif address:
            addr = address
        else:
            raise Exception('Please provide a unit or address')

        try:
            telnetlib.Telnet(addr, port)
            return True
        except socket.error as e:
            if e.errno == 113:
                self.log.error("could not connect to %s:%s" % (addr, port))
            if e.errno == 111:
                self.log.error("connection refused connecting"
                               " to %s:%s" % (addr,
                                              port))
            return False

    def resolve_cnf_file(self):
        if self._get_openstack_release() < self.xenial_mitaka:
            return '/etc/mysql/my.cnf'
        else:
            return '/etc/mysql/percona-xtradb-cluster.conf.d/mysqld.cnf'

    def test_restart_on_config_change(self):
        """Verify that the specified services are restarted when the
        config is changed."""

        sentry = self.d.sentry['percona-cluster'][0]
        juju_service = 'percona-cluster'

        # Expected default and alternate values
        set_default = {'peer-timeout': 'PT3S'}
        set_alternate = {'peer-timeout': 'PT15S'}

        # Config file affected by juju set config change
        conf_file = self.resolve_cnf_file()

        # Services which are expected to restart upon config change
        services = {
            'mysqld': conf_file,
        }

        # Make config change, check for service restarts
        self.utils.log.debug('Making config change on {}...'
                             .format(juju_service))
        mtime = self.utils.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)
        self._auto_wait_for_status()

        sleep_time = 40
        for s, conf_file in services.iteritems():
            self.utils.log.debug("Checking that service restarted: {}"
                                 .format(s))
            if not self.utils.validate_service_config_changed(
                    sentry, mtime, s, conf_file, retry_count=5,
                    retry_sleep_time=sleep_time,
                    sleep_time=sleep_time):
                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)
            sleep_time = 0

        self.d.configure(juju_service, set_default)
        self._auto_wait_for_status()
