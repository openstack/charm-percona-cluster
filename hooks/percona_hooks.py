#!/usr/bin/python
# TODO: Support changes to root and sstuser passwords
import sys
import json
import os
import socket

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
    is_leader,
    network_get_primary_address,
    charm_name,
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
    CompareHostReleases,
)
from charmhelpers.core.templating import render
from charmhelpers.fetch import (
    apt_update,
    apt_install,
    add_source,
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
    get_hacluster_config,
)
from charmhelpers.payload.execd import execd_preinstall
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_iface_for_address,
    get_netmask_for_address,
    get_ipv6_addr,
    is_address_in_network,
    resolve_network_cidr,
    get_relation_ip,
)
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden
from charmhelpers.contrib.hardening.mysql.checks import run_mysql_checks
from charmhelpers.contrib.openstack.utils import (
    is_unit_paused_set,
)
from charmhelpers.contrib.openstack.ha.utils import (
    update_dns_ha_resource_params,
)

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
    notify_bootstrapped,
    is_bootstrapped,
    clustered_once,
    INITIAL_CLUSTERED_KEY,
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
)

from charmhelpers.core.unitdata import kv

hooks = Hooks()

RES_MONITOR_PARAMS = ('params user="sstuser" password="%(sstpass)s" '
                      'pid="/var/run/mysqld/mysqld.pid" '
                      'socket="/var/run/mysqld/mysqld.sock" '
                      'max_slave_lag="5" '
                      'cluster_type="pxc" '
                      'op monitor interval="1s" timeout="30s" '
                      'OCF_CHECK_LEVEL="1"')

INITIAL_CLIENT_UPDATE_KEY = 'initial_client_update_done'


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
        'lp1366997_workaround': config('lp1366997-workaround'),
        'binlogs_path': config('binlogs-path'),
        'enable_binlogs': config('enable-binlogs'),
        'binlogs_max_size': config('binlogs-max-size'),
        'binlogs_expire_days': config('binlogs-expire-days'),
        'performance_schema': config('performance-schema'),
        'is_leader': is_leader(),
        'server_id': get_server_id(),
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

    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) < 'bionic':
        # myisam_recover is not valid for PXC 5.7 (introduced in Bionic) so we
        # only set it for PXC 5.6.
        context['myisam_recover'] = 'BACKUP'
        context['wsrep_provider'] = '/usr/lib/libgalera_smm.so'
    elif CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) >= 'bionic':
        context['wsrep_provider'] = '/usr/lib/galera3/libgalera_smm.so'
        context['default_storage_engine'] = 'InnoDB'
        context['wsrep_log_conflicts'] = True
        context['innodb_autoinc_lock_mode'] = '2'
        context['pxc_strict_mode'] = config('pxc-strict-mode')

    context.update(PerconaClusterHelper().parse_config())
    render(os.path.basename(config_file), config_file, context, perms=0o444)


def render_config_restart_on_changed(hosts, bootstrap=False):
    """Render mysql config and restart mysql service if file changes as a
    result.

    If bootstrap is True we do a bootstrap-pxc in order to bootstrap the
    percona cluster. This should only be performed once at cluster creation
    time.

    If percona is already bootstrapped we can get away with just ensuring that
    it is started so long as the new node to be added is guaranteed to have
    been restarted so as to apply the new config.
    """
    config_file = resolve_cnf_file()
    pre_hash = file_hash(config_file)
    render_config(hosts)
    create_binlogs_directory()
    update_db_rels = False
    if file_hash(config_file) != pre_hash or bootstrap:
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
    if leader_node_is_ready() or client_node_is_ready():
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


@hooks.hook('upgrade-charm')
@harden()
def upgrade():

    if is_leader():
        if is_unit_paused_set():
            log('Unit is paused, skiping upgrade', level=INFO)
            return

        # Leader sets on upgrade
        leader_set(**{'leader-ip': get_relation_ip('cluster')})
        configure_sstuser(sst_password())
        if not leader_get('root-password') and leader_get('mysql.passwd'):
            leader_set(**{'root-password': leader_get('mysql.passwd')})

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

    # It is critical that the installation is attempted first before any
    # rendering of the configuration files occurs.
    # install_percona_xtradb_cluster has the code to decide if this is the
    # leader or if the leader is bootstrapped and therefore ready for install.
    install_percona_xtradb_cluster()

    # if we are paused, delay doing any config changed hooks.  It is forced on
    # the resume.
    if is_unit_paused_set():
        return

    if config('prefer-ipv6'):
        assert_charm_supports_ipv6()

    hosts = get_cluster_hosts()
    leader_bootstrapped = is_leader_bootstrapped()
    leader_ip = leader_get('leader-ip')

    if is_leader():
        # If the cluster has not been fully bootstrapped once yet, use an empty
        # hosts list to avoid restarting the leader node's mysqld during
        # cluster buildup.
        # After, the cluster has bootstrapped at least one time, it is much
        # less likely to have restart collisions. It is then safe to use the
        # full hosts list and have the leader node's mysqld restart.
        if not clustered_once():
            hosts = []
        log("Leader unit - bootstrap required=%s" % (not leader_bootstrapped),
            DEBUG)
        render_config_restart_on_changed(hosts,
                                         bootstrap=not leader_bootstrapped)
    elif leader_bootstrapped and is_sufficient_peers():
        # Speed up cluster process by bootstrapping when the leader has
        # bootstrapped if we have expected number of peers
        if leader_ip not in hosts:
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

    # (re)install pcmkr agent
    install_mysql_ocf()

    for rid in relation_ids('ha'):
        # make sure all the HA resources are (re)created
        ha_relation_joined(relation_id=rid)

    if is_relation_made('nrpe-external-master'):
        update_nrpe_config()

    open_port(DEFAULT_MYSQL_PORT)

    # the password needs to be updated only if the node was already
    # bootstrapped
    if is_bootstrapped():
        update_root_password()
        set_ready_on_peers()


@hooks.hook('cluster-relation-joined')
def cluster_joined():
    relation_settings = {}

    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')])[0]
        relation_settings = {'private-address': addr,
                             'hostname': socket.gethostname()}

    relation_settings['cluster-address'] = get_cluster_host_ip()

    log("Setting cluster relation: '%s'" % (relation_settings),
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
    for attr in rdata.iterkeys():
        if attr not in ['hostname', 'private-address', 'cluster-address',
                        'public-address', 'ready']:
            inc_list.append(attr)

    peer_echo(includes=inc_list)
    # NOTE(jamespage): deprecated - leader-election

    cluster_joined()
    config_changed()


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

                log("Unable to identify a VIP in the access-network '%s'" %
                    (access_network), level=WARNING)
            else:
                return get_address_in_network(access_network)
        else:
            log("Client address '%s' not in access-network '%s'" %
                (client_ip, access_network), level=WARNING)
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
        log("Multiple hostnames provided by relation: %s" % (', '.join(hosts)),
            level=DEBUG)
    except ValueError:
        log("Single hostname provided by relation: %s" % (hosts),
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

    singleset = set(['database', 'username', 'hostname'])
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
            log("Host '%s' not in access-network '%s' - ignoring" %
                (normalized_address, access_network), level=INFO)
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
        databases = {}
        for k, v in settings.iteritems():
            db = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if db not in databases:
                databases[db] = {}
            databases[db][x] = v

        allowed_units = {}
        return_data = {}
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
                allowed_units_key = '%s_allowed_units' % (db)
                allowed_units[allowed_units_key] = a_units

                return_data['%s_password' % (db)] = password
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
    cluster_config = get_hacluster_config()
    sstpsswd = sst_password()
    resources = {'res_mysql_monitor': 'ocf:percona:mysql_monitor'}
    resource_params = {'res_mysql_monitor':
                       RES_MONITOR_PARAMS % {'sstpass': sstpsswd}}

    if config('dns-ha'):
        update_dns_ha_resource_params(relation_id=relation_id,
                                      resources=resources,
                                      resource_params=resource_params)
        group_name = 'grp_{}_hostnames'.format(charm_name())
        groups = {group_name: 'res_{}_access_hostname'.format(charm_name())}

    else:
        vip_iface = (get_iface_for_address(cluster_config['vip']) or
                     config('vip_iface'))
        vip_cidr = (get_netmask_for_address(cluster_config['vip']) or
                    config('vip_cidr'))

        if config('prefer-ipv6'):
            res_mysql_vip = 'ocf:heartbeat:IPv6addr'
            vip_params = 'params ipv6addr="%s" cidr_netmask="%s" nic="%s"' % \
                         (cluster_config['vip'], vip_cidr, vip_iface)
        else:
            res_mysql_vip = 'ocf:heartbeat:IPaddr2'
            vip_params = 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                         (cluster_config['vip'], vip_cidr, vip_iface)

        resources['res_mysql_vip'] = res_mysql_vip

        resource_params['res_mysql_vip'] = vip_params

        group_name = 'grp_percona_cluster'
        groups = {group_name: 'res_mysql_vip'}

    clones = {'cl_mysql_monitor': 'res_mysql_monitor meta interleave=true'}

    colocations = {'colo_percona_cluster': 'inf: {} cl_mysql_monitor'
                                           ''.format(group_name)}

    locations = {'loc_percona_cluster':
                 '{} rule inf: writable eq 1'
                 ''.format(group_name)}

    for rel_id in relation_ids('ha'):
        relation_set(relation_id=rel_id,
                     corosync_bindiface=cluster_config['ha-bindiface'],
                     corosync_mcastport=cluster_config['ha-mcastport'],
                     resources=resources,
                     resource_params=resource_params,
                     groups=groups,
                     clones=clones,
                     colocations=colocations,
                     locations=locations)


@hooks.hook('ha-relation-changed')
def ha_relation_changed():
    update_client_db_relations()


@hooks.hook('leader-settings-changed')
def leader_settings_changed():
    '''Re-trigger install once leader has seeded passwords into install'''
    config_changed()


@hooks.hook('leader-elected')
def leader_elected():
    '''Set the leader nodes IP'''
    if is_leader():
        leader_set(**{'leader-ip': get_relation_ip('cluster')})
    else:
        log('leader-elected hook executed, but this unit is not the leader',
            level=INFO)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, ['mysql'], current_unit)
    nrpe_setup.add_check(
        shortname='mysql_proc',
        description='Check MySQL process {%s}' % current_unit,
        check_cmd='check_procs -c 1:1 -C mysqld'
    )
    nrpe_setup.write()


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


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
