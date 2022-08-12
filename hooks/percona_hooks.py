#!/usr/bin/env python3
# TODO: Support changes to root and sstuser passwords
import collections
import sys
import json
import os
import socket
import subprocess

_path = os.path.dirname(os.path.realpath(__file__))
_root = os.path.abspath(os.path.join(_path, '..'))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_root)


from charmhelpers.core.hookenv import (
    Hooks, UnregisteredHookError,
    is_relation_made,
    log,
    relation_get,
    relation_set,
    relation_ids,
    related_units,
    unit_get,
    config,
    remote_unit,
    relation_type,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    is_leader,
    network_get_primary_address,
    leader_get,
    leader_set,
    open_port,
    status_set,
)
from charmhelpers.core.host import (
    service_restart,
    service_running,
    service_stop,
    file_hash,
    lsb_release,
    mkdir,
    CompareHostReleases,
    pwgen,
    init_is_systemd
)
from charmhelpers.core.templating import render
from charmhelpers.fetch import (
    apt_update,
    apt_install,
    add_source,
    SourceConfigError,
    filter_installed_packages,
)
from charmhelpers.contrib.peerstorage import (
    peer_echo,
    peer_store_and_set,
    peer_retrieve_by_prefix,
)
from charmhelpers.contrib.database.mysql import (
    PerconaClusterHelper,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_clustered,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_ipv6_addr,
    is_address_in_network,
    resolve_network_cidr,
    get_relation_ip,
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden
from charmhelpers.contrib.hardening.mysql.checks import run_mysql_checks
from charmhelpers.contrib.openstack.utils import (
    DB_SERIES_UPGRADING_KEY,
    is_unit_paused_set,
    is_unit_upgrading_set,
    set_unit_upgrading,
    clear_unit_upgrading,
    clear_unit_paused,
)
from charmhelpers.contrib.openstack.ha.utils import (
    DNSHA_GROUP_NAME,
    JSON_ENCODE_OPTIONS,
    VIP_GROUP_NAME,
    update_hacluster_vip,
    update_hacluster_dns_ha,
)
from charmhelpers.core.unitdata import kv

from percona_utils import (
    determine_packages,
    setup_percona_repo,
    resolve_hostname_to_ip,
    get_cluster_hosts,
    configure_sstuser,
    configure_mysql_root_password,
    relation_clear,
    assert_charm_supports_ipv6,
    unit_sorted,
    get_db_helper,
    mark_seeded, seeded,
    install_mysql_ocf,
    maybe_notify_bootstrapped,
    notify_bootstrapped,
    is_bootstrapped,
    clustered_once,
    INITIAL_CLUSTERED_KEY,
    INITIAL_CLIENT_UPDATE_KEY,
    is_leader_bootstrapped,
    get_wsrep_value,
    assess_status,
    register_configs,
    resolve_cnf_file,
    create_binlogs_directory,
    bootstrap_pxc,
    get_cluster_host_ip,
    client_node_is_ready,
    leader_node_is_ready,
    DEFAULT_MYSQL_PORT,
    sst_password,
    root_password,
    pxc_installed,
    update_bootstrap_uuid,
    LeaderNoBootstrapUUIDError,
    update_root_password,
    cluster_wait,
    get_wsrep_provider_options,
    get_server_id,
    is_sufficient_peers,
    set_ready_on_peers,
    pause_unit_helper,
    resume_unit_helper,
    check_for_socket,
    get_cluster_id,
    get_databases_to_replicate,
    configure_master,
    configure_slave,
    deconfigure_slave,
    get_master_status,
    get_slave_status,
    delete_replication_user,
    list_replication_users,
    check_mysql_connection,
    set_nagios_user,
    get_nrpe_threads_connected_thresholds,
    MYSQL_NAGIOS_CREDENTIAL_FILE,
    update_source,
    ADD_APT_REPOSITORY_FAILED,
)

hooks = Hooks()

RES_MONITOR_PARAMS = ('params user="sstuser" password="%(sstpass)s" '
                      'pid="/var/run/mysqld/mysqld.pid" '
                      'socket="/var/run/mysqld/mysqld.sock" '
                      'max_slave_lag="5" '
                      'cluster_type="pxc" '
                      'op monitor interval="1s" timeout="30s" '
                      'OCF_CHECK_LEVEL="1" '
                      'meta migration-threshold=INFINITY failure-timeout=5s')

SYSTEMD_OVERRIDE_PATH = '/etc/systemd/system/mysql.service.d/charm-nofile.conf'

MYSQL_SOCKET = "/var/run/mysqld/mysqld.sock"


def install_percona_xtradb_cluster():
    '''Attempt PXC install based on seeding of passwords for users'''
    if pxc_installed():
        log('MySQL already installed, skipping')
        return

    if not is_leader() and not is_leader_bootstrapped():
        log('Non-leader waiting on leader bootstrap, skipping percona install',
            DEBUG)
        return

    _root_password = root_password()
    _sst_password = sst_password()
    if not _root_password or not _sst_password:
        log('Passwords not seeded, unable to install MySQL at this'
            ' point so deferring installation')
        return
    configure_mysql_root_password(_root_password)

    apt_install(determine_packages(), fatal=True)

    configure_sstuser(_sst_password)
    if config('harden') and 'mysql' in config('harden'):
        run_mysql_checks()


@hooks.hook('install.real')
@harden()
def install():
    execd_preinstall()
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if (config('source') is None and
            CompareHostReleases(_release) < 'trusty'):
        setup_percona_repo()
    elif config('source') is not None:
        add_source(config('source'), config('key'))
    apt_update(fatal=True)

    install_percona_xtradb_cluster()
    install_mysql_ocf()


def has_async_replication():
    """Returns whether or not an asynchronous replication is available.

    Asynchronous replication of the database is available when a user has
    related two percona-cluster applications via one of the
    mysql-async-replication relations (master or slave). This method will
    return true if one of those relations exists.

    :returns: True if an asynchronous replication relation exists, False
              otherwise.
    :rtype: bool
    """
    return is_relation_made('master') or is_relation_made('slave')


def render_override(ctx):
    # max_connections/table_open_cache are shrunk to fit within ulimits.
    # The following formula is taken from sql/mysqld.cc.
    if init_is_systemd():
        open_files_limit = max(
            (ctx['max_connections'] + 1) + 10 + (ctx['table_open_cache']*2),
            (ctx['max_connections'] + 1) * 5,
            5000)
        if not os.path.exists(os.path.dirname(SYSTEMD_OVERRIDE_PATH)):
            os.makedirs(os.path.dirname(SYSTEMD_OVERRIDE_PATH))
        pre_hash = file_hash(SYSTEMD_OVERRIDE_PATH)
        render(os.path.basename(SYSTEMD_OVERRIDE_PATH),
               SYSTEMD_OVERRIDE_PATH,
               {'open_files_limit': open_files_limit})
        if pre_hash != file_hash(SYSTEMD_OVERRIDE_PATH):
            subprocess.check_call(['systemctl', 'daemon-reload'])


def render_config(hosts=None):
    if hosts is None:
        hosts = []

    config_file = resolve_cnf_file()
    if not os.path.exists(os.path.dirname(config_file)):
        os.makedirs(os.path.dirname(config_file))

    context = {
        'cluster_name': 'juju_cluster',
        'private_address': get_cluster_host_ip(),
        'cluster_hosts': ",".join(hosts),
        'sst_method': config('sst-method'),
        'sst_password': sst_password(),
        'innodb_file_per_table': config('innodb-file-per-table'),
        'table_open_cache': config('table-open-cache'),
        'use_syslog': config('use-syslog'),
        'binlogs_path': config('binlogs-path'),
        'enable_binlogs': config('enable-binlogs'),
        'binlogs_max_size': config('binlogs-max-size'),
        'binlogs_expire_days': config('binlogs-expire-days'),
        'performance_schema': config('performance-schema'),
        'max_connect_errors': config('max-connect-errors'),
        'is_leader': is_leader(),
        'server_id': get_server_id(),
        'series_upgrade': is_unit_upgrading_set(),
    }

    if config('prefer-ipv6'):
        # NOTE(hopem): this is a kludge to get percona working with ipv6.
        # See lp 1380747 for more info. This is intended as a stop gap until
        # percona package is fixed to support ipv6.
        context['bind_address'] = '::'
        context['ipv6'] = True
    else:
        context['ipv6'] = False

    wsrep_provider_options = get_wsrep_provider_options()
    if wsrep_provider_options:
        context['wsrep_provider_options'] = wsrep_provider_options

    if config('wsrep-slave-threads') is not None:
        context['wsrep_slave_threads'] = config('wsrep-slave-threads')

    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) < 'bionic':
        # myisam_recover is not valid for PXC 5.7 (introduced in Bionic) so we
        # only set it for PXC 5.6.
        context['myisam_recover'] = 'BACKUP'
        context['wsrep_provider'] = '/usr/lib/libgalera_smm.so'
        if 'wsrep_slave_threads' not in context:
            context['wsrep_slave_threads'] = 1
    elif CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) >= 'bionic':
        context['wsrep_provider'] = '/usr/lib/galera3/libgalera_smm.so'
        context['default_storage_engine'] = 'InnoDB'
        context['wsrep_log_conflicts'] = True
        context['innodb_autoinc_lock_mode'] = '2'
        context['pxc_strict_mode'] = config('pxc-strict-mode')
        if 'wsrep_slave_threads' not in context:
            context['wsrep_slave_threads'] = 48

    if config('databases-to-replicate') and has_async_replication():
        context['databases_to_replicate'] = get_databases_to_replicate()

    context['server-id'] = get_server_id()

    context.update(PerconaClusterHelper().parse_config())
    render(os.path.basename(config_file), config_file, context, perms=0o444)

    render_override(context)


def render_config_restart_on_changed(hosts):
    """Render mysql config and restart mysql service if file changes as a
    result.

    If bootstrap is True we do a bootstrap-pxc in order to bootstrap the
    percona cluster. This should only be performed once at cluster creation
    time.

    If percona is already bootstrapped we can get away with just ensuring that
    it is started so long as the new node to be added is guaranteed to have
    been restarted so as to apply the new config.
    """
    if is_leader() and not is_leader_bootstrapped():
        bootstrap = True
    else:
        bootstrap = False

    config_file = resolve_cnf_file()
    pre_hash_config = file_hash(config_file)
    pre_hash_override = file_hash(SYSTEMD_OVERRIDE_PATH)
    render_config(hosts)
    create_binlogs_directory()
    update_db_rels = False

    hashes_changed = (file_hash(config_file) != pre_hash_config) or \
                     (file_hash(SYSTEMD_OVERRIDE_PATH) != pre_hash_override)

    if hashes_changed or bootstrap:
        if bootstrap:
            bootstrap_pxc()
            # NOTE(dosaboy): this will not actually do anything if no cluster
            # relation id exists yet.
            notify_bootstrapped()
            update_db_rels = True
        else:
            # NOTE(jamespage):
            # if mysql@bootstrap is running, then the native
            # bootstrap systemd service was used to start this
            # instance, and it was the initial seed unit
            # stop the bootstap version before restarting normal mysqld
            if service_running('mysql@bootstrap'):
                service_stop('mysql@bootstrap')

            attempts = 0
            max_retries = 5

            cluster_wait()
            while not service_restart('mysql'):
                if attempts == max_retries:
                    raise Exception("Failed to start mysql (max retries "
                                    "reached)")

                log("Failed to start mysql - retrying per distributed wait",
                    WARNING)
                attempts += 1
                cluster_wait()

        # If we get here we assume prior actions have succeeded to always
        # this unit is marked as seeded so that subsequent calls don't result
        # in a restart.
        mark_seeded()

        if update_db_rels:
            update_client_db_relations()
    else:
        log("Config file '{}' unchanged".format(config_file), level=DEBUG)


def update_client_db_relations():
    """ Upate client db relations IFF ready
    """
    if ((leader_node_is_ready() or
            client_node_is_ready()) and check_mysql_connection()):
        for r_id in relation_ids('shared-db'):
            for unit in related_units(r_id):
                shared_db_changed(r_id, unit)
        for r_id in relation_ids('db'):
            for unit in related_units(r_id):
                db_changed(r_id, unit, admin=False)
        for r_id in relation_ids('db-admin'):
            for unit in related_units(r_id):
                db_changed(r_id, unit, admin=True)

        kvstore = kv()
        update_done = kvstore.get(INITIAL_CLIENT_UPDATE_KEY, False)
        if not update_done:
            kvstore.set(key=INITIAL_CLIENT_UPDATE_KEY, value=True)
            kvstore.flush()


@hooks.hook('pre-series-upgrade')
def prepare():
    # Use the pause feature to stop mysql during the duration of the upgrade
    pause_unit_helper(register_configs())
    # Set this unit to series upgrading
    set_unit_upgrading()
    # The leader will "bootstrap" with no wrep peers
    # Non-leaders will point only at the newly upgraded leader until the
    # cluster series upgrade is completed.
    # Set cluster_series_upgrading for the duration of the cluster series
    # upgrade. This will be unset with the action
    # complete-cluster-series-upgrade on the leader node.
    hosts = []

    if not leader_get('cluster_series_upgrade_leader'):
        leader_set(cluster_series_upgrading=True)
        leader_set(
            cluster_series_upgrade_leader=get_relation_ip('cluster'))
        for r_id in relation_ids('shared-db'):
            relation_set(
                relation_id=r_id,
                relation_settings={DB_SERIES_UPGRADING_KEY: True})
    else:
        hosts = [leader_get('cluster_series_upgrade_leader')]

    # Render config
    render_config(hosts)


@hooks.hook('post-series-upgrade')
def series_upgrade():

    # Set this unit to series upgrading
    set_unit_upgrading()

    # The leader will "bootstrap" with no wrep peers
    # Non-leaders will point only at the newly upgraded leader until the
    # cluster series upgrade is completed.
    # Set cluster_series_upgrading for the duration of the cluster series
    # upgrade. This will be unset with the action
    # complete-cluster-series-upgrade on the leader node.
    if (leader_get('cluster_series_upgrade_leader') ==
            get_relation_ip('cluster')):
        hosts = []
    else:
        hosts = [leader_get('cluster_series_upgrade_leader')]

    # New series after series upgrade and reboot
    _release = lsb_release()['DISTRIB_CODENAME'].lower()

    if _release == "xenial":
        # Guarantee /var/run/mysqld exists
        _dir = '/var/run/mysqld'
        mkdir(_dir, owner="mysql", group="mysql", perms=0o755)

    # Install new versions of the percona packages
    apt_install(determine_packages())
    service_stop("mysql")

    if _release == "bionic":
        render_config(hosts)

    if _release == "xenial":
        # Move the packaged version empty DB out of the way.
        cmd = ["mv", "/var/lib/percona-xtradb-cluster",
               "/var/lib/percona-xtradb-cluster.dpkg"]
        subprocess.check_call(cmd)

        # Symlink the previous versions data to the new
        cmd = ["ln", "-s", "/var/lib/mysql", "/var/lib/percona-xtradb-cluster"]
        subprocess.check_call(cmd)

    # Start mysql temporarily with no wrep for the upgrade
    cmd = ["mysqld"]
    if _release == "bionic":
        cmd.append("--skip-grant-tables")
        cmd.append("--user=mysql")
    cmd.append("--wsrep-provider=none")
    log("Starting mysqld --wsrep-provider='none' and waiting ...")
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE)

    # Wait for the mysql socket to exist
    check_for_socket(MYSQL_SOCKET, exists=True)

    # Execute the upgrade process
    log("Running mysql_upgrade")
    cmd = ['mysql_upgrade']
    if _release == "xenial":
        cmd.append('-p{}'.format(root_password()))
    subprocess.check_call(cmd)

    # Terminate the temporary mysql
    proc.terminate()

    # Wait for the mysql socket to be removed
    check_for_socket(MYSQL_SOCKET, exists=False)

    # Clear states
    clear_unit_paused()
    clear_unit_upgrading()

    if _release == "xenial":
        # Point at the correct my.cnf
        cmd = ["update-alternatives", "--set", "my.cnf",
               "/etc/mysql/percona-xtradb-cluster.cnf"]
        subprocess.check_call(cmd)

    # Render config
    render_config(hosts)

    resume_unit_helper(register_configs())

    # finally update the sstuser if needed.
    # BUG: #1838044
    _sst_password = sst_password()
    if _sst_password:
        configure_sstuser(_sst_password)


@hooks.hook('upgrade-charm')
@harden()
def upgrade():

    if is_leader():
        if is_unit_paused_set() or is_unit_upgrading_set():
            log('Unit is paused, skiping upgrade', level=INFO)
            return

        # Leader sets on upgrade
        leader_set(**{'leader-ip': get_relation_ip('cluster')})
        configure_sstuser(sst_password())
        if not leader_get('root-password') and leader_get('mysql.passwd'):
            leader_set(**{'root-password': leader_get('mysql.passwd')})

        # move the nagios password out of nagios-password and into
        # mysql-nagios.passwd
        # BUG: #1925042
        nagios_password = leader_get('nagios-password')
        if nagios_password:
            leader_set(**{"mysql-nagios.passwd": nagios_password,
                          "nagios-password": None})

        # On upgrade-charm we assume the cluster was complete at some point
        kvstore = kv()
        initial_clustered = kvstore.get(INITIAL_CLUSTERED_KEY, False)
        if not initial_clustered:
            kvstore.set(key=INITIAL_CLUSTERED_KEY, value=True)
            kvstore.flush()

        # broadcast the bootstrap-uuid
        wsrep_ready = get_wsrep_value('wsrep_ready') or ""
        if wsrep_ready.lower() in ['on', 'ready']:
            cluster_state_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
            if cluster_state_uuid:
                mark_seeded()
                notify_bootstrapped(cluster_uuid=cluster_state_uuid)
    else:
        # Ensure all the peers have the bootstrap-uuid attribute set
        # as this is all happening during the upgrade-charm hook is reasonable
        # to expect the cluster is running.

        # Wait until the leader has set the
        try:
            update_bootstrap_uuid()
        except LeaderNoBootstrapUUIDError:
            status_set('waiting', "Waiting for bootstrap-uuid set by leader")


@hooks.hook('config-changed')
@harden()
def config_changed():

    # if we are paused or upgrading, delay doing any config changed hooks.
    # It is forced on the resume.
    if is_unit_paused_set() or is_unit_upgrading_set():
        log("Unit is paused or upgrading. Skipping config_changed", "WARN")
        return

    # It is critical that the installation is attempted first before any
    # rendering of the configuration files occurs.
    # install_percona_xtradb_cluster has the code to decide if this is the
    # leader or if the leader is bootstrapped and therefore ready for install.
    install_percona_xtradb_cluster()

    # run a package update if the source or key has changed
    cfg = config()
    kvstore = kv()
    if cfg.changed("source") or cfg.changed("key"):
        status_set("maintenance", "Upgrading Percona packages")
        try:
            update_source(source=cfg["source"], key=cfg["key"])
            kvstore.set(ADD_APT_REPOSITORY_FAILED, False)
        except (subprocess.CalledProcessError, SourceConfigError):
            # NOTE (rgildein): Need to store the local state to prevent
            # `assess_status` from running, which changes the unit state
            # to "Unit is ready"
            kvstore.set(ADD_APT_REPOSITORY_FAILED, True)
        kvstore.flush()

    if kvstore.get(ADD_APT_REPOSITORY_FAILED, False):
        return

    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    hosts = get_cluster_hosts()
    leader_bootstrapped = is_leader_bootstrapped()

    # Cluster upgrade adds some complication
    cluster_series_upgrading = leader_get("cluster_series_upgrading")
    if cluster_series_upgrading:
        leader = (leader_get('cluster_series_upgrade_leader') ==
                  get_relation_ip('cluster'))
        leader_ip = leader_get('cluster_series_upgrade_leader')
    else:
        leader = is_leader()
        leader_ip = leader_get('leader-ip')

    # (re)install pcmkr agent
    install_mysql_ocf()

    if leader:
        # If the cluster has not been fully bootstrapped once yet, use an empty
        # hosts list to avoid restarting the leader node's mysqld during
        # cluster buildup.
        # After, the cluster has bootstrapped at least one time, it is much
        # less likely to have restart collisions. It is then safe to use the
        # full hosts list and have the leader node's mysqld restart.
        # Empty hosts if cluster_series_upgrading
        if not clustered_once() or cluster_series_upgrading:
            hosts = []
        log("Leader unit - bootstrap required={}"
            .format(not leader_bootstrapped),
            DEBUG)
        render_config_restart_on_changed(hosts)
    elif (leader_bootstrapped and
          is_sufficient_peers() and not
          cluster_series_upgrading):
        # Skip if cluster_series_upgrading
        # Speed up cluster process by bootstrapping when the leader has
        # bootstrapped if we have expected number of peers
        # However, in a cold boot scenario do not add the "old" leader
        # when it matches this host.
        if (leader_ip not in hosts and
                leader_ip != get_cluster_host_ip()):
            # Fix Bug #1738896
            hosts = [leader_ip] + hosts
        log("Leader is bootstrapped - configuring mysql on this node",
            DEBUG)
        # Rendering the mysqld.cnf and restarting is bootstrapping for a
        # non-leader node.
        render_config_restart_on_changed(hosts)
        # Assert we are bootstrapped. This will throw an
        # InconsistentUUIDError exception if UUIDs do not match.
        update_bootstrap_uuid()
    else:
        # Until the bootstrap-uuid attribute is set by the leader,
        # cluster_ready() will evaluate to False. So it is necessary to
        # feed this information to the user.
        status_set('waiting', "Waiting for bootstrap-uuid set by leader")
        log('Non-leader waiting on leader bootstrap, skipping render',
            DEBUG)
        return

    # Notify any changes to the access network
    update_client_db_relations()

    for rid in relation_ids('ha'):
        # make sure all the HA resources are (re)created
        ha_relation_joined(relation_id=rid)

    if is_relation_made('nrpe-external-master'):
        update_nrpe_config()

    open_port(DEFAULT_MYSQL_PORT)

    # the password needs to be updated only if the node was already
    # bootstrapped
    if is_bootstrapped():
        if is_leader():
            update_root_password()
        set_ready_on_peers()

    # NOTE(tkurek): re-set 'master' relation data
    if relation_ids('master'):
        master_joined()


@hooks.hook('cluster-relation-joined')
def cluster_joined():
    relation_settings = {}

    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_settings = {'private-address': addr,
                             'hostname': socket.gethostname()}

    relation_settings['cluster-address'] = get_cluster_host_ip()

    log("Setting cluster relation: '{}'".format(relation_settings),
        level=INFO)
    relation_set(relation_settings=relation_settings)


@hooks.hook('cluster-relation-departed')
@hooks.hook('cluster-relation-changed')
def cluster_changed():
    # Need to make sure hostname is excluded to build inclusion list (paying
    # attention to those excluded by default in peer_echo().
    # TODO(dosaboy): extend peer_echo() to support providing exclusion list as
    #                well as inclusion list.
    # NOTE(jamespage): deprecated - leader-election
    rdata = relation_get()
    inc_list = []
    for attr in rdata.keys():
        if attr not in ['hostname', 'private-address', 'cluster-address',
                        'public-address', 'ready']:
            inc_list.append(attr)

    peer_echo(includes=inc_list)
    # NOTE(jamespage): deprecated - leader-election

    maybe_notify_bootstrapped()

    cluster_joined()
    config_changed()

    if is_bootstrapped() and not seeded():
        mark_seeded()


def clear_and_populate_client_db_relations(relation_id, relation_name):
    # NOTE(jamespage): relation level data candidate
    log('Service is peered, clearing {} relation '
        'as this service unit is not the leader'.format(relation_name))
    relation_clear(relation_id)
    # Each unit needs to set the db information otherwise if the unit
    # with the info dies the settings die with it Bug# 1355848
    if is_relation_made('cluster'):
        for rel_id in relation_ids(relation_name):
            client_settings = \
                peer_retrieve_by_prefix(rel_id, exc_list=['hostname'])

            passwords = [key for key in client_settings.keys()
                         if 'password' in key.lower()]
            if len(passwords) > 0:
                relation_set(relation_id=rel_id, **client_settings)


# TODO: This could be a hook common between mysql and percona-cluster
@hooks.hook('db-relation-changed')
@hooks.hook('db-admin-relation-changed')
def db_changed(relation_id=None, unit=None, admin=None):

    # Is this db-admin or db relation
    if admin not in [True, False]:
        admin = relation_type() == 'db-admin'
    if admin:
        relation_name = 'db-admin'
    else:
        relation_name = 'db'

    if not seeded():
        log("Percona cluster not yet bootstrapped - deferring {} relation "
            "until bootstrapped.".format(relation_name), DEBUG)
        return

    if not is_leader() and client_node_is_ready():
        clear_and_populate_client_db_relations(relation_id, relation_name)
        return

    # Bail if leader is not ready
    if not leader_node_is_ready():
        return

    db_name, _ = (unit or remote_unit()).split("/")
    username = db_name
    db_helper = get_db_helper()
    addr = relation_get('private-address', unit=unit, rid=relation_id)
    password = db_helper.configure_db(addr, db_name, username, admin=admin)

    db_host = get_db_host(addr, interface=relation_name)

    peer_store_and_set(relation_id=relation_id,
                       user=username,
                       password=password,
                       host=db_host,
                       database=db_name)


def get_db_host(client_hostname, interface='shared-db'):
    """Get address of local database host for use by db clients

    If an access-network has been configured, expect selected address to be
    on that network. If none can be found, revert to primary address.

    If network spaces are supported (Juju >= 2.0), use network-get to
    retrieve the network binding for the interface.

    If DNSHA is set pass os-access-hostname

    If vip(s) are configured, chooses first available.

    @param client_hostname: hostname of client side relation setting hostname.
                            Only used if access-network is configured
    @param interface: Network space binding to check.
                      Usually the relationship name.
    @returns IP for use with db clients
    """
    vips = config('vip').split() if config('vip') else []
    dns_ha = config('dns-ha')
    access_network = config('access-network')
    if is_clustered() and dns_ha:
        log("Using DNS HA hostname: {}".format(config('os-access-hostname')))
        return config('os-access-hostname')
    elif access_network:
        client_ip = resolve_hostname_to_ip(client_hostname)
        if is_address_in_network(access_network, client_ip):
            if is_clustered():
                for vip in vips:
                    if is_address_in_network(access_network, vip):
                        return vip

                log("Unable to identify a VIP in the access-network '{}'"
                    .format(access_network), level=WARNING)
            else:
                return get_address_in_network(access_network)
        else:
            log("Client address '{}' not in access-network '{}'"
                .format(client_ip, access_network), level=WARNING)
    else:
        try:
            # NOTE(jamespage)
            # Try to use network spaces to resolve binding for
            # interface, and to resolve the VIP associated with
            # the binding if provided.
            interface_binding = network_get_primary_address(interface)
            if is_clustered() and vips:
                interface_cidr = resolve_network_cidr(interface_binding)
                for vip in vips:
                    if is_address_in_network(interface_cidr, vip):
                        return vip
            return interface_binding
        except NotImplementedError:
            # NOTE(jamespage): skip - fallback to previous behaviour
            pass

    if is_clustered() and vips:
        return vips[0]  # NOTE on private network

    if config('prefer-ipv6'):
        return get_ipv6_addr(exc_list=vips)[0]

    # Last resort
    return unit_get('private-address')


def configure_db_for_hosts(hosts, database, username, db_helper):
    """Hosts may be a json-encoded list of hosts or a single hostname."""
    try:
        hosts = json.loads(hosts)
        log("Multiple hostnames provided by relation: {}"
            .format(', '.join(hosts)),
            level=DEBUG)
    except ValueError:
        log("Single hostname provided by relation: {}".format(hosts),
            level=DEBUG)
        hosts = [hosts]

    for host in hosts:
        password = db_helper.configure_db(host, database, username)

    return password


# TODO: This could be a hook common between mysql and percona-cluster
@hooks.hook('shared-db-relation-changed')
def shared_db_changed(relation_id=None, unit=None):
    if not seeded():
        log("Percona cluster not yet bootstrapped - deferring shared-db rel "
            "until bootstrapped", DEBUG)
        return

    if not is_leader() and client_node_is_ready():
        clear_and_populate_client_db_relations(relation_id, 'shared-db')
        return

    # Bail if leader is not ready
    if not leader_node_is_ready():
        return

    settings = relation_get(unit=unit, rid=relation_id)
    access_network = config('access-network')
    db_helper = get_db_helper()

    peer_store_and_set(relation_id=relation_id,
                       relation_settings={'access-network': access_network})

    singleset = {'database', 'username', 'hostname'}
    if singleset.issubset(settings):
        # Process a single database configuration
        hostname = settings['hostname']
        database = settings['database']
        username = settings['username']

        normalized_address = resolve_hostname_to_ip(hostname)
        if access_network and not is_address_in_network(access_network,
                                                        normalized_address):
            # NOTE: for configurations using access-network, only setup
            #       database access if remote unit has presented a
            #       hostname or ip address thats within the configured
            #       network cidr
            log("Host '{}' not in access-network '{}' - ignoring"
                .format(normalized_address, access_network), level=INFO)
            return

        # NOTE: do this before querying access grants
        password = configure_db_for_hosts(hostname, database, username,
                                          db_helper)

        allowed_units = db_helper.get_allowed_units(database, username,
                                                    relation_id=relation_id)
        allowed_units = unit_sorted(allowed_units)
        allowed_units = ' '.join(allowed_units)
        relation_set(relation_id=relation_id, allowed_units=allowed_units)

        db_host = get_db_host(hostname)
        peer_store_and_set(relation_id=relation_id,
                           db_host=db_host,
                           password=password,
                           allowed_units=allowed_units)
    else:
        # Process multiple database setup requests.
        # from incoming relation data:
        #  nova_database=xxx nova_username=xxx nova_hostname=xxx
        #  quantum_database=xxx quantum_username=xxx quantum_hostname=xxx
        # create
        # {
        #   "nova": {
        #        "username": xxx,
        #        "database": xxx,
        #        "hostname": xxx
        #    },
        #    "quantum": {
        #        "username": xxx,
        #        "database": xxx,
        #        "hostname": xxx
        #    }
        # }
        #
        databases = collections.OrderedDict()
        for k, v in settings.items():
            db = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if db not in databases:
                databases[db] = collections.OrderedDict()
            databases[db][x] = v

        allowed_units = collections.OrderedDict()
        return_data = collections.OrderedDict()
        for db in databases:
            if singleset.issubset(databases[db]):
                database = databases[db]['database']
                hostname = databases[db]['hostname']
                username = databases[db]['username']

                normalized_address = resolve_hostname_to_ip(hostname)
                if (access_network and
                        not is_address_in_network(access_network,
                                                  normalized_address)):
                    # NOTE: for configurations using access-network,
                    #       only setup database access if remote unit
                    #       has presented a hostname or ip address
                    #       thats within the configured network cidr
                    return

                # NOTE: do this before querying access grants
                password = configure_db_for_hosts(hostname, database, username,
                                                  db_helper)

                a_units = db_helper.get_allowed_units(database, username,
                                                      relation_id=relation_id)
                a_units = ' '.join(unit_sorted(a_units))
                allowed_units_key = '{}_allowed_units'.format(db)
                allowed_units[allowed_units_key] = a_units

                return_data['{}_password'.format(db)] = password
                return_data[allowed_units_key] = a_units
                db_host = get_db_host(hostname)

        if allowed_units:
            relation_set(relation_id=relation_id, **allowed_units)
        else:
            log("No allowed_units - not setting relation settings",
                level=DEBUG)

        if return_data:
            peer_store_and_set(relation_id=relation_id, db_host=db_host,
                               **return_data)
        else:
            log("No return data - not setting relation settings", level=DEBUG)


@hooks.hook('ha-relation-joined')
def ha_relation_joined(relation_id=None):
    install_mysql_ocf()
    sstpsswd = sst_password()
    _relation_data = {
        'resources': {
            'res_mysql_monitor': 'ocf:percona:mysql_monitor'},
        'resource_params': {
            'res_mysql_monitor': RES_MONITOR_PARAMS % {'sstpass': sstpsswd}},
        'clones': {
            'cl_mysql_monitor': 'res_mysql_monitor meta interleave=true'},
        'delete_resources': ['loc_percona_cluster', 'grp_percona_cluster',
                             'res_mysql_vip']
    }

    if config('dns-ha'):
        update_hacluster_dns_ha('mysql', _relation_data)
        group_name = DNSHA_GROUP_NAME.format(service='mysql')
    else:
        update_hacluster_vip('mysql', _relation_data)
        group_name = VIP_GROUP_NAME.format(service='mysql')

    _relation_data['locations'] = {
        'loc_mysql': '{} rule inf: writable eq 1'.format(group_name)}
    _relation_data['colocations'] = {
        'colo_mysql': 'inf: {} cl_mysql_monitor'.format(group_name)}
    settings = {
        'json_{}'.format(k): json.dumps(v, **JSON_ENCODE_OPTIONS)
        for k, v in _relation_data.items() if v
    }

    for rel_id in relation_ids('ha'):
        relation_set(relation_id=rel_id, **settings)


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    install_mysql_ocf()
    update_client_db_relations()


@hooks.hook('leader-settings-changed')
def leader_settings_changed():
    '''Re-trigger install once leader has seeded passwords into install'''

    maybe_notify_bootstrapped()

    config_changed()
    # NOTE(tkurek): re-set 'master' relation data
    if relation_ids('master'):
        master_joined()
    # NOTE(tkurek): deconfigure old leader
    if relation_ids('slave'):
        deconfigure_slave()
    if not leader_get('cluster_series_upgrading'):
        for r_id in relation_ids('shared-db'):
            relation_set(
                relation_id=r_id,
                relation_settings={DB_SERIES_UPGRADING_KEY: None})


@hooks.hook('leader-elected')
def leader_elected():
    '''Set the leader nodes IP'''
    if is_leader():
        leader_set(**{'leader-ip': get_relation_ip('cluster')})
    else:
        log('leader-elected hook executed, but this unit is not the leader',
            level=INFO)
    # NOTE(tkurek): re-set 'master' relation data
    if relation_ids('master'):
        master_joined()
    # NOTE(tkurek): configure new leader
    if relation_ids('slave'):
        configure_slave()


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    # nagios-plugins-contrib add pmp-check-mysql-status check
    packages = filter_installed_packages(["python-dbus",
                                          "nagios-plugins-contrib"])
    apt_install(packages)

    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, ['mysql'], current_unit)
    nrpe_setup.add_check(
        shortname='mysql_proc',
        description='Check MySQL process {}'.format(current_unit),
        check_cmd='check_procs -c 1:1 -C mysqld'
    )
    try:
        warning_threads, critical_threads = \
            get_nrpe_threads_connected_thresholds()
    except ValueError as error:
        log("failed to get thresholds from nrpe-threads-connected due: "
            "{}".format(error), level=ERROR)
        log("the default thresholds are used")
        warning_threads, critical_threads = 80, 90

    set_nagios_user()
    nrpe_setup.add_check(
        shortname='mysql_threads',
        description='Check MySQL connected threads',
        check_cmd='pmp-check-mysql-status --defaults-file {credential_file} '
                  '-x Threads_connected -o / -y max_connections -T pct '
                  '-w {warning} -c {critical}'.format(
                      credential_file=MYSQL_NAGIOS_CREDENTIAL_FILE,
                      warning=warning_threads,
                      critical=critical_threads)
    )
    nrpe_setup.write()


@hooks.hook('master-relation-joined')
def master_joined(interface='master'):
    cluster_id = get_cluster_id()
    if not is_clustered():
        log("Not clustered yet", level=DEBUG)
        return
    relation_settings = {}
    leader_settings = leader_get()
    if is_leader():
        if not leader_settings.get('async-rep-password'):
            # Replication password cannot be longer than 32 characters
            leader_set({'async-rep-password': pwgen(32)})
            return
        configure_master()
        master_address, master_file, master_position = (
            get_master_status(interface))
        if leader_settings.get('master-address') is not master_address:
            leader_settings['master-address'] = master_address
            leader_settings['master-file'] = master_file
            leader_settings['master-position'] = master_position
        leader_set(leader_settings)
        relation_settings = {'leader': True}
    else:
        relation_settings = {'leader': False}
    relation_settings['cluster_id'] = cluster_id
    relation_settings['master_address'] = leader_settings['master-address']
    relation_settings['master_file'] = leader_settings['master-file']
    relation_settings['master_password'] = \
        leader_settings['async-rep-password']
    relation_settings['master_position'] = leader_settings['master-position']
    log("Setting master relation: '{}'".format(relation_settings), level=INFO)
    for rid in relation_ids(interface):
        relation_set(relation_id=rid, relation_settings=relation_settings)


@hooks.hook('master-relation-changed')
def master_changed(interface='master'):
    if is_leader():
        configure_master()


@hooks.hook('master-relation-departed')
def master_departed(interface='master'):
    if is_leader():
        reset_password = True
        new_slave_addresses = []
        old_slave_addresses = list_replication_users()
        for rid in relation_ids(interface):
            if related_units(rid):
                reset_password = False
            for unit in related_units(rid):
                if not relation_get(attribute='slave_address',
                                    rid=rid, unit=unit):
                    log("No relation data for {}".format(unit), level=DEBUG)
                    return
                new_slave_addresses.append(
                    relation_get(attribute='slave_address',
                                 rid=rid,
                                 unit=unit))
        for old_slave_address in old_slave_addresses:
            if old_slave_address not in new_slave_addresses:
                delete_replication_user(old_slave_address)
        if reset_password:
            leader_set({'async-rep-password': ''})


@hooks.hook('slave-relation-joined')
def slave_joined(interface='slave'):
    relation_settings = {}
    cluster_id = get_cluster_id()
    if not is_clustered():
        log("Not clustered yet", level=DEBUG)
        return
    if is_leader():
        configure_slave()
    relation_settings = {'slave_address':
                         network_get_primary_address(interface)}
    relation_settings['cluster_id'] = cluster_id
    log("Setting slave relation: '{}'".format(relation_settings), level=INFO)
    for rid in relation_ids(interface):
        relation_set(relation_id=rid, relation_settings=relation_settings)


@hooks.hook('slave-relation-changed')
def slave_changed(interface='slave'):
    for rid in relation_ids(interface):
        for unit in related_units(rid):
            rdata = relation_get(unit=unit, rid=rid)
            if rdata.get('leader'):
                if rdata.get('master_address') is not get_slave_status():
                    slave_departed()
                    slave_joined()


@hooks.hook('slave-relation-departed')
def slave_departed():
    if is_leader():
        deconfigure_slave()


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')
    cfg = config()
    # Disable implicit save as update_status will not act on any
    # config changes but a subsequent hook might need to see
    # any changes. Bug #1838125
    cfg.implicit_save = False


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    kvstore = kv()
    if not kvstore.get(INITIAL_CLIENT_UPDATE_KEY, False):
        update_client_db_relations()
    assess_status(register_configs())


if __name__ == '__main__':
    main()
