''' General utilities for percona '''
import collections
import datetime
import subprocess
from subprocess import Popen, PIPE
import socket
import tempfile
import copy
import os
import re
import shutil
import six
import uuid
from functools import partial
import time
import yaml

from charmhelpers.core.decorators import retry_on_exception
from charmhelpers.core.templating import render
from charmhelpers.core.host import (
    lsb_release,
    mkdir,
    service,
    pwgen,
    CompareHostReleases,
)
from charmhelpers.core.hookenv import (
    charm_dir,
    unit_get,
    relation_ids,
    related_units,
    relation_get,
    relation_set,
    local_unit,
    service_name,
    config,
    log,
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    cached,
    status_set,
    network_get_primary_address,
    application_version_set,
    is_leader,
    leader_get,
    leader_set,
)
from charmhelpers.core.unitdata import kv
from charmhelpers.fetch import (
    add_source,
    apt_install,
    apt_update,
    filter_installed_packages,
    get_upstream_version,
    SourceConfigError,
)
from charmhelpers.contrib.network.ip import (
    get_address_in_network,
    get_ipv6_addr,
    is_ip,
    is_ipv6,
)
from charmhelpers.contrib.database.mysql import (
    MySQLHelper,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_clustered,
    distributed_wait,
)
from charmhelpers.contrib.openstack.utils import (
    make_assess_status_func,
    pause_unit,
    resume_unit,
    is_unit_paused_set,
    is_unit_upgrading_set,
)

# NOTE: python-mysqldb is installed by charmhelpers.contrib.database.mysql so
# hence why we import here
from MySQLdb import (
    OperationalError
)

KEY = "keys/repo.percona.com"
REPO = """deb http://repo.percona.com/apt {release} main
deb-src http://repo.percona.com/apt {release} main"""
SEEDED_MARKER = "{data_dir}/seeded"
BACKUP_INFO = "{data_dir}/xtrabackup_info"
HOSTS_FILE = '/etc/hosts'
DEFAULT_MYSQL_PORT = 3306
INITIAL_CLUSTERED_KEY = 'initial-cluster-complete'
INITIAL_CLIENT_UPDATE_KEY = 'initial_client_update_done'
ADD_APT_REPOSITORY_FAILED = "add-apt-repository-failed"

# NOTE(ajkavanagh) - this is 'required' for the pause/resume code for
# maintenance mode, but is currently not populated as the
# charm_check_function() checks whether the unit is working properly.
REQUIRED_INTERFACES = {}
MYSQL_NAGIOS_CREDENTIAL_FILE = "/etc/nagios/mysql-check.cnf"


class LeaderNoBootstrapUUIDError(Exception):
    """Raised when the leader doesn't have set the bootstrap-uuid attribute"""
    def __init__(self):
        super(LeaderNoBootstrapUUIDError, self).__init__(
            "the leader doesn't have set the bootstrap-uuid attribute")


class InconsistentUUIDError(Exception):
    """Raised when the leader and the unit have different UUIDs set"""
    def __init__(self, leader_uuid, unit_uuid):
        super(InconsistentUUIDError, self).__init__(
            "Leader UUID ('{}') != Unit UUID ('{}')"
            .format(leader_uuid, unit_uuid))


class DesyncedException(Exception):
    '''Raised if PXC unit is not in sync with its peers'''
    pass


class GRAStateFileNotFound(Exception):
    """Raised when the grastate file does not exist"""
    pass


class FakeOSConfigRenderer(object):
    """This class is to provide to register_configs() as a 'fake'
    OSConfigRenderer object that has a complete_contexts method that returns
    an empty list.  This is so that the pause/resume framework can be used
    from charmhelpers that requires configs to be able to run.
    This is a bit of a hack, but via Python's duck-typing enables the function
    to work.
    """
    def complete_contexts(self):
        return []


def determine_packages():
    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) >= 'wily':
        # NOTE(beisner): Use recommended mysql-client package
        # https://launchpad.net/bugs/1476845
        # https://launchpad.net/bugs/1571789
        # NOTE(coreycb): This will install percona-xtradb-cluster-server-5.6
        # for >= wily and percona-xtradb-cluster-server-5.7 for >= bionic.
        return [
            'percona-xtradb-cluster-server',
        ]
    else:
        return [
            'percona-xtradb-cluster-server-5.5',
            'percona-xtradb-cluster-client-5.5',
        ]


def seeded():
    ''' Check whether service unit is already seeded '''
    return os.path.exists(SEEDED_MARKER.format(data_dir=resolve_data_dir()))


def mark_seeded():
    ''' Mark service unit as seeded '''
    with open(SEEDED_MARKER.format(data_dir=resolve_data_dir()),
              'w', encoding="utf-8") as seeded:
        seeded.write('done')


def last_backup_sst():
    """ Check if the last backup was an SST
    The percona xtrabackup_info file (BACKUP_INFO) contains information about
    the last backup/sync to this node, including the type of backup, either
    incremental (IST) or full (SST).

    We return True if we can successfully determine the last backup was SST
    from the BACKUP_INFO file contents, otherwise we assume the last backup
    was an incremental and return False.

    @returns boolean
    """
    result = False
    try:
        with open(BACKUP_INFO.format(data_dir=resolve_data_dir()), 'r') as f:
            lines = f.readlines()
            for line in lines:
                if re.match('^incremental = N($|\n)', line):
                    result = True
    except FileNotFoundError:
        log("""Backup info file not found: %s, assuming last backup was
            incremental""" %
            BACKUP_INFO.format(data_dir=resolve_data_dir()), level=DEBUG)
    except Exception:
        log("""Unable to read backup info file: %s, assuming last backup was
            incremental""" %
            BACKUP_INFO.format(data_dir=resolve_data_dir()), level=DEBUG)
    return result


def setup_percona_repo():
    ''' Configure service unit to use percona repositories '''
    with open('/etc/apt/sources.list.d/percona.list', 'w') as sources:
        sources.write(
            REPO.format(
                release=lsb_release()['DISTRIB_CODENAME']).encode('utf-8'))
    subprocess.check_call(['apt-key', 'add', KEY])


def resolve_hostname_to_ip(hostname):
    """Resolve hostname to IP

    @param hostname: hostname to be resolved
    @returns IP address or None if resolution was not possible via DNS
    """
    try:
        import dns.resolver
    except ImportError:
        apt_install(filter_installed_packages(['python3-dnspython']),
                    fatal=True)
        import dns.resolver

    if config('prefer-ipv6'):
        if is_ipv6(hostname):
            return hostname

        query_type = 'AAAA'
    elif is_ip(hostname):
        return hostname
    else:
        query_type = 'A'

    # This may throw an NXDOMAIN exception; in which case
    # things are badly broken so just let it kill the hook
    answers = dns.resolver.query(hostname, query_type)
    if answers:
        return answers[0].address


def is_sufficient_peers():
    """Sufficient number of expected peers to build a complete cluster

    If min-cluster-size has been provided, check that we have sufficient
    number of peers as expected for a complete cluster.

    If not defined assume a single unit.

    @returns boolean
    """

    min_size = config('min-cluster-size')
    if min_size:
        log("Checking for minimum of {} peer units".format(min_size),
            level=DEBUG)

        # Include this unit
        units = 1
        for rid in relation_ids('cluster'):
            units += len(related_units(rid))

        if units < min_size:
            log("Insufficient number of peer units to form cluster "
                "(expected={}, got={})".format(min_size, units), level=INFO)
            return False
        else:
            log("Sufficient number of peer units to form cluster {}"
                .format(min_size),
                level=DEBUG)
            return True
    else:
        log("min-cluster-size is not defined, race conditions may occur if "
            "this is not a single unit deployment.", level=WARNING)
        return True


def get_cluster_hosts():
    """Get the bootstrapped cluster peers

    Determine the cluster peers that have bootstrapped and return the list
    hosts. Secondarily, update the hosts file with IPv6 address name
    resolution.

    The returned host list is intended to be used in the
    wsrep_cluster_address=gcomm:// setting. Therefore, the hosts must have
    already been bootstrapped. If an un-bootstrapped host happens to be first
    in the list, mysql will fail to start.

    @side_effect update_hosts_file called for IPv6 hostname resolution
    @returns list of hosts
    """
    hosts_map = collections.OrderedDict()

    local_cluster_address = get_cluster_host_ip()

    # We need to add this localhost dns name to /etc/hosts along with peer
    # hosts to ensure percona gets consistently resolved addresses.
    if config('prefer-ipv6'):
        addr = get_ipv6_addr(exc_list=[config('vip')], fatal=True)[0]
        hosts_map = {addr: socket.gethostname()}

    hosts = []
    for relid in relation_ids('cluster'):
        for unit in related_units(relid):
            rdata = relation_get(unit=unit, rid=relid)
            # NOTE(dosaboy): see LP: #1599447
            cluster_address = rdata.get('cluster-address',
                                        rdata.get('private-address'))
            if config('prefer-ipv6'):
                hostname = rdata.get('hostname')
                if not hostname or hostname in hosts:
                    log("(unit=%s) Ignoring hostname '%s' provided by cluster "
                        "relation for addr %s" %
                        (unit, hostname, cluster_address), level=DEBUG)
                    continue
                else:
                    log("(unit={}) hostname '{}' provided by cluster relation "
                        "for addr {}".format(unit, hostname, cluster_address),
                        level=DEBUG)

                hosts_map[cluster_address] = hostname
                host = hostname
            else:
                host = resolve_hostname_to_ip(cluster_address)
            # Add only cluster peers who have set bootstrap-uuid
            # An indiction they themselves are bootstrapped.
            # Un-bootstrapped hosts in gcom lead mysql to fail to start
            # if it happens to be the first address in the list
            # Also fix strange bug when executed from actions where the local
            # unit is returned in related_units. We do not want the local IP
            # in the gcom hosts list.
            if (rdata.get('bootstrap-uuid') and
                    host not in hosts and
                    host != local_cluster_address):
                hosts.append(host)

    if hosts_map:
        update_hosts_file(hosts_map)

    # Return a sorted list to avoid uneccessary restarts
    return sorted(hosts)


SQL_SST_USER_SETUP = ("GRANT {permissions} ON *.* "
                      "TO 'sstuser'@'localhost' IDENTIFIED BY '{password}'")

SQL_SST_USER_SETUP_IPV6 = ("GRANT {permissions} "
                           "ON *.* TO 'sstuser'@'ip6-localhost' IDENTIFIED "
                           "BY '{password}'")


def get_db_helper():
    return MySQLHelper(rpasswdf_template='/var/lib/charm/%s/mysql.passwd' %
                       (service_name()),
                       upasswdf_template='/var/lib/charm/%s/mysql-{}.passwd' %
                       (service_name()))


def configure_sstuser(sst_password):
    # xtrabackup 2.4 (introduced in Bionic) needs PROCESS privilege for backups
    permissions = [
        "RELOAD",
        "LOCK TABLES",
        "REPLICATION CLIENT"
    ]
    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) >= 'bionic':
        permissions.append('PROCESS')

    m_helper = get_db_helper()
    m_helper.connect(password=m_helper.get_mysql_root_password())
    m_helper.execute(SQL_SST_USER_SETUP.format(
        permissions=','.join(permissions),
        password=sst_password)
    )
    m_helper.execute(SQL_SST_USER_SETUP_IPV6.format(
        permissions=','.join(permissions),
        password=sst_password)
    )


# TODO: mysql charmhelper
def configure_mysql_root_password(password):
    ''' Configure debconf with root password '''
    dconf = Popen(['debconf-set-selections'], stdin=PIPE)
    # Set both percona and mysql password options to cover
    # both upstream and distro packages.
    packages = ["percona-server-server", "mysql-server",
                "percona-xtradb-cluster-server"]
    m_helper = get_db_helper()
    root_pass = m_helper.get_mysql_root_password(password)
    for package in packages:
        dconf.stdin.write("{} {}/root_password password {}\n"
                          .format(package, package, root_pass)
                          .encode("utf-8"))
        dconf.stdin.write("{} {}/root_password_again password {}\n"
                          .format(package, package, root_pass)
                          .encode("utf-8"))
    dconf.communicate()
    dconf.wait()


# TODO: Submit for charmhelper
def relation_clear(r_id=None):
    ''' Clears any relation data already set on relation r_id '''
    settings = relation_get(rid=r_id,
                            unit=local_unit())
    for setting in settings:
        if setting not in ['public-address', 'private-address']:
            settings[setting] = None
    relation_set(relation_id=r_id,
                 **settings)


def update_hosts_file(_map):
    """Percona does not currently like ipv6 addresses so we need to use dns
    names instead. In order to make them resolvable we ensure they are  in
    /etc/hosts.

    See https://bugs.launchpad.net/galera/+bug/1130595 for some more info.
    """
    with open(HOSTS_FILE, 'r', encoding="utf-8") as hosts:
        lines = hosts.readlines()

    log("Updating {} with: {} (current: {})".format(HOSTS_FILE, _map, lines),
        level=DEBUG)

    newlines = []
    for ip, hostname in list(_map.items()):
        if not ip or not hostname:
            continue

        keepers = []
        for line in lines:
            _line = line.split()
            if len(line) < 2 or not (_line[0] == ip or hostname in _line[1:]):
                keepers.append(line)
            else:
                log("Marking line '{}' for update or removal"
                    .format(line.strip()),
                    level=DEBUG)

        lines = keepers
        newlines.append("{} {}\n".format(ip, hostname))

    lines += newlines

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        with open(tmpfile.name, 'w', encoding="utf-8") as hosts:
            for line in lines:
                hosts.write(line)

    os.rename(tmpfile.name, HOSTS_FILE)
    os.chmod(HOSTS_FILE, 0o644)


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


def unit_sorted(units):
    """Return a sorted list of unit names."""
    return sorted(
        units, key=lambda a: int(a.split('/')[-1]))


def install_mysql_ocf():
    dest_dir = '/usr/lib/ocf/resource.d/percona/'
    for fname in ['ocf/percona/mysql_monitor']:
        src_file = os.path.join(charm_dir(), fname)
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir)

        dest_file = os.path.join(dest_dir, os.path.basename(src_file))
        if not os.path.exists(dest_file):
            log('Installing %s' % dest_file, level='INFO')
            shutil.copy(src_file, dest_file)
        else:
            log("'{}' already exists, skipping"
                .format(dest_file), level='INFO')
        # Always set to executable
        os.chmod(dest_file, 0o755)


def get_wsrep_value(key):
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", DEBUG)
        return None

    cursor = m_helper.connection.cursor()
    ret = None
    try:
        cursor.execute("show status like '{}'".format(key))
        ret = cursor.fetchall()
    except Exception as e:
        log("Failed to get key={} '{}'".format(key, e), ERROR)
        return None
    finally:
        cursor.close()

    if ret:
        return ret[0][1]

    return None


def is_leader_bootstrapped():
    """ Check that the leader is bootstrapped and has set required settings

    :side_effect: calls leader_get
    :returns: boolean
    """

    check_settings = ['bootstrap-uuid', 'mysql.passwd', 'root-password',
                      'sst-password', 'leader-ip']
    leader_settings = leader_get()

    # Is the leader bootstrapped?
    for setting in check_settings:
        if leader_settings.get(setting) is None:
            log("Leader is NOT bootstrapped {}: {}".format(setting,
                leader_settings.get('bootstrap-uuid')), DEBUG)
            return False

    log("Leader is bootstrapped uuid: {}".format(
        leader_settings.get('bootstrap-uuid')), DEBUG)
    return True


def clustered_once():
    """Determine if the cluster has ever bootstrapped completely

    Check unittest.kv if the cluster has bootstrapped at least once.

    @returns boolean
    """

    # Run is_bootstrapped once to guarantee kvstore is up to date
    is_bootstrapped()
    kvstore = kv()
    return kvstore.get(INITIAL_CLUSTERED_KEY, False)


def is_bootstrapped():
    """Determine if each node in the cluster has been bootstrapped and the
    cluster is complete with the expected number of peers.

    Check that each node in the cluster, including this one, has set
    bootstrap-uuid on the cluster relation.

    Having min-cluster-size set will guarantee is_bootstrapped will not
    return True until the expected number of peers are bootstrapped. If
    min-cluster-size is not set, it will check peer relations to estimate the
    expected cluster size. If min-cluster-size is not set and there are no
    peers it must assume the cluster is bootstrapped in order to allow for
    single unit deployments.

    @returns boolean
    """
    min_size = get_min_cluster_size()
    if not is_sufficient_peers():
        return False
    elif min_size > 1:
        uuids = []
        for relation_id in relation_ids('cluster'):
            units = related_units(relation_id) or []
            units.append(local_unit())
            for unit in units:
                if not relation_get(attribute='bootstrap-uuid',
                                    rid=relation_id,
                                    unit=unit):
                    log("{} is not yet clustered".format(unit),
                        DEBUG)
                    return False
                else:
                    bootstrap_uuid = relation_get(attribute='bootstrap-uuid',
                                                  rid=relation_id,
                                                  unit=unit)
                    if bootstrap_uuid:
                        uuids.append(bootstrap_uuid)

        if len(uuids) < min_size:
            log("Fewer than minimum cluster size: "
                "{} percona units reporting clustered".format(min_size),
                DEBUG)
            return False
        elif len(set(uuids)) > 1:
            log("Found inconsistent bootstrap uuids: "
                "{}".format(uuids), level=WARNING)
            return False
        else:
            log("All {} percona units reporting clustered".format(min_size),
                DEBUG)
    elif not seeded():
        # Single unit deployment but not yet bootstrapped
        return False

    # Set INITIAL_CLUSTERED_KEY as the cluster has fully bootstrapped
    kvstore = kv()
    if not kvstore.get(INITIAL_CLUSTERED_KEY, False):
        kvstore.set(key=INITIAL_CLUSTERED_KEY, value=True)
        kvstore.flush()

    return True


def bootstrap_pxc():
    """Bootstrap PXC
    On systemd systems systemctl bootstrap-pxc mysql does not work.
    Run service mysql bootstrap-pxc to bootstrap."""
    service('stop', 'mysql')
    bootstrapped = service('bootstrap-pxc', 'mysql')
    if not bootstrapped:
        try:
            cmp_os = CompareHostReleases(
                lsb_release()['DISTRIB_CODENAME']
            )
            if cmp_os < 'bionic':
                # NOTE(jamespage): execute under systemd-run to ensure
                #                  that the bootstrap-pxc mysqld does
                #                  not end up in the juju unit daemons
                #                  cgroup scope.
                cmd = ['systemd-run', '--service-type=forking',
                       'service', 'mysql', 'bootstrap-pxc']
                subprocess.check_call(cmd)
            else:
                service('start', 'mysql@bootstrap')
        except subprocess.CalledProcessError as e:
            msg = 'Bootstrap PXC failed'
            error_msg = '{}: {}'.format(msg, e)
            status_set('blocked', msg)
            log(error_msg, ERROR)
            raise Exception(error_msg)
        if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) < 'bionic':
            # To make systemd aware mysql is running after a bootstrap
            service('start', 'mysql')
    log("Bootstrap PXC Succeeded", DEBUG)


def notify_bootstrapped(cluster_rid=None, cluster_uuid=None):
    if cluster_rid:
        rids = [cluster_rid]
    else:
        rids = relation_ids('cluster')
        if not rids:
            log("No relation ids found for 'cluster'", level=INFO)
            return

    if not cluster_uuid:
        cluster_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
        if not cluster_uuid:
            cluster_uuid = str(uuid.uuid4())
            log("Could not determine cluster uuid so using '%s' instead" %
                (cluster_uuid), INFO)

    log("Notifying peers that percona is bootstrapped (uuid=%s)" %
        (cluster_uuid), DEBUG)
    for rid in rids:
        relation_set(relation_id=rid, **{'bootstrap-uuid': cluster_uuid})
    if is_leader():
        leader_set(**{'bootstrap-uuid': cluster_uuid})


def update_bootstrap_uuid():
    """This function verifies if the leader has set the bootstrap-uuid
    attribute to then check it against the running cluster uuid, if the check
    succeeds the bootstrap-uuid field is set in the cluster relation.

    :returns: True if the cluster UUID was updated, False if the local UUID is
              empty.
    """

    lead_cluster_state_uuid = leader_get('bootstrap-uuid')
    if not lead_cluster_state_uuid:
        log('Leader has not set bootstrap-uuid', level=DEBUG)
        raise LeaderNoBootstrapUUIDError()

    wsrep_ready = get_wsrep_value('wsrep_ready') or ""
    log("wsrep_ready: '{}'".format(wsrep_ready), DEBUG)
    if wsrep_ready.lower() in ['on', 'ready']:
        cluster_state_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
    else:
        cluster_state_uuid = None

    if not cluster_state_uuid:
        log("UUID is empty: '{}'".format(cluster_state_uuid), level=DEBUG)
        return False
    elif lead_cluster_state_uuid != cluster_state_uuid:
        # this may mean 2 things:
        # 1) the units have diverged, which it's bad and we do stop.
        # 2) cluster_state_uuid could not be retrieved because it
        # hasn't been bootstrapped, mysqld is stopped, etc.
        log('bootstrap uuid differs: %s != %s' % (lead_cluster_state_uuid,
                                                  cluster_state_uuid),
            level=ERROR)
        raise InconsistentUUIDError(lead_cluster_state_uuid,
                                    cluster_state_uuid)

    for rid in relation_ids('cluster'):
        notify_bootstrapped(cluster_rid=rid,
                            cluster_uuid=cluster_state_uuid)

    return True


def cluster_in_sync():
    '''
    Determines whether the current unit is in sync
    with the rest of the cluster
    '''
    ready = get_wsrep_value('wsrep_ready') or False
    sync_status = get_wsrep_value('wsrep_local_state') or 0
    if ready and int(sync_status) in [2, 4]:
        return True
    return False


def charm_check_func(ensure_seeded=False):
    """Custom function to assess the status of the current unit

    :param ensure_seeded: if set, then ensure that the seeded file exists.
        This is to work around bug: #1868326   where the resume action to
        manage_payload_services causes the seeded file to be removed under
        certain circumstances.  This is one of the only places where we can
        actually re-assert it prior to the resume failing, as this function
        gets a chance to run after management_payload_services() but prior to
        the actual
    :type ensure_seeded: bool
    :returns: (status, message)
    :rtype: Tuple[str, str]
    """
    # Ensure seeded file is replaced if told or after any SST event post
    # bootstrap. resolves bug #2000107
    if (not seeded() and
            (ensure_seeded or (is_bootstrapped() and last_backup_sst()))):
        log("'seeded' file is missing but should exists; putting it back.")
        mark_seeded()
    if is_unit_upgrading_set():
        # Avoid looping through attempting to determine cluster_in_sync
        return ("blocked", "Unit upgrading.")

    kvstore = kv()
    # Using INITIAL_CLIENT_UPDATE_KEY as this is a step beyond merely
    # clustered, but rather clustered and clients were previously notified.
    if (kvstore.get(INITIAL_CLIENT_UPDATE_KEY, False) and
            not check_mysql_connection()):
        return ('blocked',
                'MySQL is down. Sequence Number: {}. Safe To Bootstrap: {}'
                .format(get_grastate_seqno(),
                        get_grastate_safe_to_bootstrap()))

    @retry_on_exception(num_retries=10,
                        base_delay=2,
                        exc_type=DesyncedException)
    def _cluster_in_sync():
        '''Helper func to wait for a while for resync to occur

        @raise DesynedException: raised if local unit is not in sync
                                 with its peers
        '''
        if not cluster_in_sync():
            raise DesyncedException()

    min_size = config('min-cluster-size')
    # Ensure that number of peers > cluster size configuration
    if not is_sufficient_peers():
        return ('blocked', 'Insufficient peers to bootstrap cluster')

    if min_size and int(min_size) > 1:
        # Once running, ensure that cluster is in sync
        # and has the required peers
        if not is_bootstrapped():
            return ('waiting', 'Unit waiting for cluster bootstrap')
        elif not seeded():
            return ('waiting',
                    "Unit waiting to bootstrap ('seeded' file missing)")
        elif cluster_ready():
            try:
                _cluster_in_sync()
                return ('active', 'Unit is ready and clustered')
            except DesyncedException:
                return ('blocked', 'Unit is not in sync')
        else:
            return ('waiting', 'Unit waiting on hacluster relation')
    else:
        if seeded():
            return ('active', 'Unit is ready')
        else:
            return ('waiting', 'Unit waiting to bootstrap')


@cached
def resolve_data_dir():
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < 'vivid':
        return '/var/lib/mysql'
    else:
        return '/var/lib/percona-xtradb-cluster'


@cached
def resolve_cnf_file():
    _release = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(_release) < 'vivid':
        return '/etc/mysql/my.cnf'
    else:
        return '/etc/mysql/percona-xtradb-cluster.conf.d/mysqld.cnf'


def register_configs():
    """Return a OSConfigRenderer object.
    However, ceph-mon wasn't written using OSConfigRenderer objects to do the
    config files, so this just returns an empty OSConfigRenderer object.

    @returns empty FakeOSConfigRenderer object.
    """
    return FakeOSConfigRenderer()


def services():
    """Return a list of services that are managed by this charm.

    @returns [services] - list of strings that are service names.
    """
    # NOTE(jamespage): Native systemd variants of the packagin
    #                  use mysql@bootstrap to seed the cluster
    #                  however this is cleared after a reboot,
    #                  so dynamically check to see if this active
    if service('is-active', 'mysql@bootstrap'):
        return ['mysql@bootstrap']
    return ['mysql']


def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    kvstore = kv()
    if kvstore.get(ADD_APT_REPOSITORY_FAILED, False):
        # NOTE (rgildein): prevent unit status from changing from blocked
        # to "Unit is ready", if adding a new source failed
        log("skip assess_status, because adding new source failed", level=INFO)
        status_set(
            "blocked", "problem adding new source: {}".format(config("source"))
        )
        return

    assess_status_func(configs)()
    if pxc_installed():
        # NOTE(fnordahl) ensure we do not call application_version_set with
        # None argument.  New charm deployments will have the meta-package
        # installed, but upgraded deployments will not.
        def _possible_packages():
            base = determine_packages()[0]
            yield base
            if '.' not in base:
                for i in range(5, 7 + 1):
                    yield base + '-5.' + str(i)
        version = None
        for pkg in _possible_packages():
            version = get_upstream_version(pkg)
            if version is not None:
                break
        else:
            log('Unable to determine installed version for package "{}"'
                .format(determine_packages()[0]), level=WARNING)
            return
        application_version_set(version)


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE(ajkavanagh) ports are not checked due to race hazards with services
    that don't behave sychronously w.r.t their service scripts.  e.g.
    apache2.
    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    # BUG: 1868326 - the resume action on the mysql service can wipe out the
    # seeded file; if it is seeded, then we put it back. This function is
    # called as part of the resume_unit() call and is one of the only places to
    # actually do and fix this check.
    is_seeded = seeded()
    return make_assess_status_func(
        configs, REQUIRED_INTERFACES,
        charm_func=lambda _: charm_check_func(ensure_seeded=is_seeded),
        services=services(), ports=None)


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=None)


def create_binlogs_directory():
    if not pxc_installed():
        log("PXC not yet installed. Not setting up binlogs", DEBUG)
        return
    binlogs_directory = os.path.dirname(config('binlogs-path'))
    data_dir = resolve_data_dir() + '/'
    if binlogs_directory.startswith(data_dir):
        raise Exception("Configured binlogs directory ({}) must not be inside "
                        "mysql data dir".format(binlogs_directory))

    if not os.path.isdir(binlogs_directory):
        mkdir(binlogs_directory, 'mysql', 'mysql', 0o750)


def get_cluster_host_ip():
    """Get the this host's IP address for use with percona cluster peers

    @returns IP to pass to cluster peers
    """

    cluster_network = config('cluster-network')
    if cluster_network:
        cluster_addr = get_address_in_network(cluster_network, fatal=True)
    else:
        try:
            cluster_addr = network_get_primary_address('cluster')
        except NotImplementedError:
            # NOTE(jamespage): fallback to previous behaviour
            cluster_addr = resolve_hostname_to_ip(
                unit_get('private-address')
            )

    return cluster_addr


def get_min_cluster_size():
    """ Get the minimum cluster size

    If the config value is set use that, if not count the number of units on
    the cluster relation.
    """

    min_cluster_size = config('min-cluster-size')
    if not min_cluster_size:
        units = 1
        for relation_id in relation_ids('cluster'):
            units += len(related_units(relation_id))
        min_cluster_size = units
    return min_cluster_size


def cluster_ready():
    """Determine if each node in the cluster is ready to respond to client
    requests.

    Once cluster_ready returns True it is safe to execute client relation
    hooks.

    If a VIP is set do not return ready until hacluster relationship is
    complete.

    @returns boolean
    """
    if config("vip") and not is_clustered():
        log("Waiting on hacluster to complete clustering, not clustered yet.",
            DEBUG)
        return False

    min_cluster_size = get_min_cluster_size()
    # Single unit deployment return state of seeded
    if int(min_cluster_size) == 1:
        return seeded()

    peers = collections.OrderedDict()
    for relation_id in relation_ids('cluster'):
        units = related_units(relation_id) or []
        if local_unit() not in units:
            units.append(local_unit())
        for unit in units:
            peers[unit] = relation_get(attribute='ready',
                                       rid=relation_id,
                                       unit=unit)

    if len(peers) >= min_cluster_size:
        return all(peers.values())

    return False


def client_node_is_ready():
    """Determine if the leader node has set client data

    @returns boolean
    """
    # Bail if this unit is paused
    if is_unit_paused_set():
        return False
    if not cluster_ready():
        return False
    for rid in relation_ids('shared-db'):
        if leader_get(attribute='{}_password'.format(rid)):
            return True
    for rid in relation_ids('db-admin'):
        if leader_get(attribute='{}_password'.format(rid)):
            return True
    for rid in relation_ids('db'):
        if leader_get(attribute='{}_password'.format(rid)):
            return True
    return False


def leader_node_is_ready():
    """Determine if the leader node is ready to handle client relationship
    hooks.

    IFF percona is not paused, is installed, this is the leader node and the
    cluster is complete.

    @returns boolean
    """
    # Paused check must run before other checks
    # Bail if this unit is paused
    if is_unit_paused_set():
        return False
    return (is_leader() and cluster_ready())


def _get_password(key):
    '''Retrieve named password

    This function will ensure that a consistent named password
    is used across all units in the pxc cluster; the lead unit
    will generate or use the root-password configuration option
    to seed this value into the deployment.

    Once set, it cannot be changed.

    @requires: str: named password or None if unable to retrieve
                    at this point in time
    '''
    _password = leader_get(key)
    if not _password and is_leader():
        _password = config(key) or pwgen()
        leader_set({key: _password})
    return _password


root_password = partial(_get_password, 'root-password')

sst_password = partial(_get_password, 'sst-password')


def nagios_password():
    """Get the nagios password using the MySQLdb helper in charmhelpers"""
    m_helper = get_db_helper()
    return m_helper.get_mysql_password('nagios')


def pxc_installed():
    '''Determine whether percona-xtradb-cluster is installed

    @returns: boolean: indicating installation
    '''
    return os.path.exists('/usr/sbin/mysqld')


def update_root_password():
    """Update root password if needed

    :returns: `False` when configured password has not changed
    """

    cfg = config()
    if not cfg.changed('root-password'):
        log("Root password update not required", level=DEBUG)
        return False

    log("Updating root password", level=DEBUG)
    m_helper = get_db_helper()

    current_password = m_helper.get_mysql_password(username=None)
    # password that needs to be set
    new_root_passwd = cfg['root-password'] or root_password()

    # check the password was changed
    try:
        m_helper.connect(user='root', password=current_password)
        m_helper.execute(
            """SET PASSWORD = PASSWORD('{}');""".format(new_root_passwd))
        # Covers root and root@localhost
        m_helper.execute(
            """SET PASSWORD FOR 'root'@'localhost' = PASSWORD('{}');""".format(
                new_root_passwd))

    except OperationalError as ex:
        log("Error connecting using new password: {}"
            .format(str(ex)), level=DEBUG)
        log(('Cannot connect using new password, not updating password in '
             'the relation'), level=WARNING)
        return
    if check_mysql_connection(password=new_root_passwd):
        log("Root password update succeeded", level=DEBUG)
        leader_set({'root-password': new_root_passwd})
        leader_set({'mysql.passwd': new_root_passwd})


def cluster_wait():
    ''' Wait for operations based on modulo distribution

    Use the distributed_wait function to determine how long to wait before
    running an operation like restart or cluster join. By setting modulo to
    the exact number of nodes in the cluster we get serial operations.

    Check for explicit configuration parameters for modulo distribution.
    The config setting modulo-nodes has first priority. If modulo-nodes is not
    set, check min-cluster-size. Finally, if neither value is set, determine
    how many peers there are from the cluster relation.

    @side_effect: distributed_wait is called which calls time.sleep()
    @return: None
    '''
    wait = config('known-wait')
    if config('modulo-nodes') is not None:
        # modulo-nodes has first priority
        num_nodes = config('modulo-nodes')
    elif config('min-cluster-size'):
        # min-cluster-size is consulted next
        num_nodes = config('min-cluster-size')
    else:
        # If nothing explicit is configured, determine cluster size based on
        # peer relations
        num_nodes = 1
        for rid in relation_ids('cluster'):
            num_nodes += len(related_units(rid))
    distributed_wait(modulo=num_nodes, wait=wait)


def get_wsrep_provider_options():

    wsrep_provider_options = []

    if config('prefer-ipv6'):
        wsrep_provider_options.append('gmcast.listen_addr=tcp://:::4567')
    if config('gcs-fc-limit') is not None:
        wsrep_provider_options.append(
            'gcs.fc_limit={}'.format(config('gcs-fc-limit')))

    peer_timeout = config('peer-timeout')
    if peer_timeout and (not peer_timeout.startswith('PT') or
                         not peer_timeout.endswith('S')):
        raise ValueError("Invalid gcast.peer_timeout value: {}"
                         .format(peer_timeout))
    elif peer_timeout:
        wsrep_provider_options.append('gmcast.peer_timeout={}'
                                      .format(config('peer-timeout')))

    return ';'.join(wsrep_provider_options)


class ClusterIDRequired(Exception):
    pass


class ClusterIDIdentical(Exception):
    pass


def get_cluster_id():
    """ Return cluster id (lp1776171)

    Return cluster ID for MySQL asynchronous replication
    :returns: int cluster_id
    """
    if not config('cluster-id'):
        msg = ("Master / Slave relation requires 'cluster-id' option")
        status_set("blocked", msg)
        raise ClusterIDRequired(msg)
    cluster_id = config('cluster-id')
    for rid in relation_ids('master'):
        for unit in related_units(rid):
            if relation_get(attribute='cluster_id',
                            rid=rid,
                            unit=unit) == cluster_id:
                msg = ("'cluster-id' option must be unique within a cluster")
                status_set('blocked', msg)
                raise ClusterIDIdentical(msg)
    for rid in relation_ids('slave'):
        for unit in related_units(rid):
            if relation_get(attribute='cluster_id',
                            rid=rid,
                            unit=unit) == cluster_id:
                msg = ("'cluster-id' option must be unique within a cluster")
                status_set('blocked', msg)
                raise ClusterIDIdentical(msg)
    return cluster_id


def get_server_id():
    """ Return unique server id for bin log replication
    Server ID must be a unique, non-zero, positive number from 1 to 2**32 - 1
    https://dev.mysql.com/doc/refman/8.0/en/replication-options.html
    :returns: int server_id
    """
    MAX_SERVER_ID = 2**32 - 1

    # Get the juju unit number
    server_id = int(local_unit().split('/')[-1])

    # Server ID of 0 indicates disabled replication, use the max instead
    if server_id == 0:
        server_id = MAX_SERVER_ID

    return server_id


def set_ready_on_peers():
    """ Set ready on peers

    Notify peers this unit is clustered and ready to serve clients
    """
    for relid in relation_ids('cluster'):
        relation_set(relation_id=relid, ready=True)


def check_for_socket(file_name, exists=True, sleep=10, attempts=12):
    """Check that a socket file exists or does not exist.

    :file_name: str File name
    :exits: bool Check for file exists or not
    :sleep: int Sleep time between attempts
    :attempts: int Number of attempt before throwing an exception
    :returns: boolean
    :raises: Exception if max attmepts is reached
    """
    for i in range(attempts):
        if os.path.exists(file_name) == exists:
            return
        else:
            log("{} file is not yet ihe correct state retrying. "
                "Check for exists={}".format(file_name, exists),
                DEBUG)
            time.sleep(sleep)
    # If we get here throw an exception
    raise Exception("Socket {} not found after {} attempts."
                    .format(file_name, attempts))


class InvalidDatabasesToReplicate(Exception):
    pass


class InvalidCharacters(Exception):
    pass


def get_databases_to_replicate():
    """ Get databases_to_replicate (lp1776171)

    Returns databases and tables to replicate using MySQL asynchronous
    replication

    :returns: list of dicts of databases and tables to replicate
    :rtype: [{'database': str, 'tables': [str, ...]}, ...]
    :raises: OperationalError
    """
    if not config('cluster-id'):
        msg = ("'cluster-id' option must be set when using "
               "'databases-to-replicate' option")
        status_set('blocked', msg)
        raise ClusterIDRequired(msg)

    databases_to_replicate = []
    entries = config('databases-to-replicate').strip().split(';')
    try:
        for entry in entries:
            databases_and_tables = collections.OrderedDict()
            entry_split = entry.split(':')
            databases_and_tables['database'] = (
                check_invalid_chars(entry_split[0]))
            try:
                # Tables present
                databases_and_tables['tables'] = (
                    check_invalid_chars(entry_split[1].split(',')))
            except IndexError:
                # If there are no tables
                databases_and_tables['tables'] = []
            databases_to_replicate.append(databases_and_tables)
    except InvalidCharacters as e:
        raise InvalidDatabasesToReplicate(
            "The configuration setting databases-to-replicate is malformed. {}"
            .format(e))
    return databases_to_replicate


def check_invalid_chars(data, bad_chars_re=r"[\^\\/?%*:|\"'<>., ]"):
    """ Check for invalid characters

    Run a pattern check on the data and raise an InvalidCharacters exception
    if there is a match. Return the original data untouched if no match is
    found.

    Input can be a list or a string.

    :param data: List or string under test
    :type data: str or list
    :param bad_chars_re: String regex to check against
    :type bad_chars_re: str
    :raises: InvalidCharacters
    :returns: The original data untouched
    :rtype: str or list
    """
    if isinstance(data, six.string_types):
        data_strings = [data]
    else:
        data_strings = copy.copy(data)

    for data_string in data_strings:
        m = re.search(bad_chars_re, data_string)
        if m:
            raise InvalidCharacters(
                "Invalid character '{}' in '{}'"
                .format(m.group(0), data_string))
    return data


def configure_master():
    """ Configure master (lp1776171)

    Calls 'create_replication_user' function for IP addresses of all related
    units.

    """
    new_slave_addresses = []
    old_slave_addresses = list_replication_users()
    for rid in relation_ids('master'):
        for unit in related_units(rid):
            if not relation_get(attribute='slave_address', rid=rid, unit=unit):
                log("No IP address for {} yet".format(unit), level=DEBUG)
                return
            new_slave_addresses.append(
                relation_get(attribute='slave_address', rid=rid, unit=unit))
    # If not yet created
    for new_slave_address in new_slave_addresses:
        if new_slave_address not in old_slave_addresses:
            create_replication_user(new_slave_address,
                                    leader_get('async-rep-password'))


def configure_slave():
    """ Configure slave (lp1776171)

    Configures MySQL asynchronous replication slave.

    :raises: OperationalError
    """
    rel_data = {}
    for rid in relation_ids('slave'):
        for unit in related_units(rid):
            rdata = relation_get(unit=unit, rid=rid)
            is_leader = rdata.get('leader', None)
            if is_leader is None:
                log("No relation data for {} yet".format(unit), level=DEBUG)
                continue
            try:
                if (is_leader and not(all(
                    rdata.get("master_{}".format(k)) for k in ["address",
                                                               "file",
                                                               "password",
                                                               "position"]))):
                    log("No full relation data for {} yet".format(unit),
                        level=DEBUG)
                    continue
                m_helper = get_db_helper()
                try:
                    m_helper.connect(user='replication',
                                     password=rdata.get('master_password'),
                                     host=rdata.get('master_address'))
                    rel_data['master_address'] = rdata.get('master_address')
                    rel_data['master_file'] = rdata.get('master_file')
                    rel_data['master_password'] = rdata.get('master_password')
                    rel_data['master_position'] = rdata.get('master_position')
                except OperationalError:
                    log("Could not connect to {}".format(unit), level=DEBUG)
            except KeyError:
                log("No relation data for {} yet".format(unit), level=DEBUG)
                raise
    if not rel_data:
        log("Unable to find the master", level=DEBUG)
        return
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", level=DEBUG)
        return
    m_helper.execute("STOP SLAVE;")
    m_helper.execute(("CHANGE MASTER TO master_host='{master_address}', "
                      "master_port=3306, master_user='replication', "
                      "master_password='{master_password}', "
                      "master_log_file='{master_file}', "
                      "master_log_pos={master_position};").format(**rel_data))
    m_helper.execute("START SLAVE;")


def deconfigure_slave():
    """ Deconfigure slave (lp1776171)

    Deconfigures MySQL asynchronous replication slave on relation departure.

    :raises: OperationalError
    """
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", level=DEBUG)
        return
    m_helper.execute("STOP SLAVE;")
    m_helper.execute("RESET SLAVE ALL;")


def get_master_status(interface):
    """ Get master status (lp1776171)

    Returns MySQL asynchronous replication master status.

    :param interface: relation name
    :type interface: str
    :returns: tuple of (IP address in space associated with 'master' binding,
                        replication file,
                        replication file position)
    :rtype: (str, str, str)
    :raises: OperationalError
    """
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", level=DEBUG)
        raise
    results = m_helper.select("SHOW MASTER STATUS;")
    return network_get_primary_address(interface), results[0][0], results[0][1]


def get_slave_status():
    """ Get slave status (lp1776171)

    Returns MySQL asynchronous replication slave status.

    returns: currently configured master IP address
    rtype: str
    :raises: OperationalError
    """
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", level=DEBUG)
        raise
    results = m_helper.select("SHOW SLAVE STATUS;")
    return results[0][1]


def create_replication_user(slave_address, master_password):
    """ Create replication user (lp1776171)

    Grants access for MySQL asynchronous replication slave.

    :param slave_address: slave IP address
    :type slave_address: str
    :param master_password: replication password
    :type master_password: str
    :raises: OperationalError
    """
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", level=DEBUG)
        return
    m_helper.execute(("GRANT REPLICATION SLAVE ON *.* TO ""'replication'@'{}' "
                      "IDENTIFIED BY '{}';").format(slave_address,
                                                    master_password))


def delete_replication_user(slave_address):
    """ Delete replication user (lp1776171)

    Revokes access for MySQL asynchronous replication slave.

    :param slave_address: slave IP address
    :type slave_address: str
    :raises: OperationalError
    """
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", DEBUG)
        return
    m_helper.execute(("DELETE FROM mysql.user WHERE Host='{}' AND "
                      "User='replication';").format(slave_address))


def list_replication_users():
    """ List replication users (lp1776171)

    Lists IP addresses of slaves which have been granted with an access for
    MySQL asynchronous replication.

    :returns: IP addresses of slaves
    :rtype replication_users: [str]
    :raises: OperationalError
    """
    replication_users = []
    m_helper = get_db_helper()
    try:
        m_helper.connect(password=m_helper.get_mysql_root_password())
    except OperationalError:
        log("Could not connect to db", DEBUG)
        raise
    for result in m_helper.select("SELECT Host FROM mysql.user WHERE "
                                  "User='replication';"):
        replication_users.append(result[0])
    return replication_users


def check_mysql_connection(password=None):
    """Check if local instance of mysql is accessible.

    Attempt a connection to the local instance of mysql to determine if it is
    running and accessible.

    :param password: Password to use for connection test.
    :type password: str
    :side effect: Uses get_db_helper to execute a connection to the DB.
    :returns: boolean
    """

    m_helper = get_db_helper()
    password = password or m_helper.get_mysql_root_password()
    try:
        m_helper.connect(password=password)
        return True
    except OperationalError:
        log("Could not connect to db", DEBUG)
        return False


def get_grastate():
    """Get GR State.

    Read the grastate yaml file and return dictionary.

    :returns: dict grastate data
    """

    grastate_file = os.path.join(resolve_data_dir(), "grastate.dat")
    if os.path.exists(grastate_file):
        try:
            with open(grastate_file, 'r') as f:
                return yaml.safe_load(f)
        except yaml.reader.ReaderError:
            pass

    # Something is amiss but we should not error out
    # return expected dictionary but zeroed out
    return {"seqno": "0", "safe_to_bootstrap": "0"}


def get_grastate_seqno():
    """Get GR State safe sequence number.

    Read the grastate yaml file to determine the sequence number for this
    instance.

    :returns: str Sequence Number
    """

    return get_grastate().get("seqno")


def get_grastate_safe_to_bootstrap():
    """Get GR State safe to bootstrap.

    Read the grastate yaml file to determine if it is safe to bootstrap from
    this instance.

    :returns: str Safe to bootstrap 0 or 1
    """

    return get_grastate().get("safe_to_bootstrap")


def set_grastate_safe_to_bootstrap():
    """Set GR State safe to bootstrap.

    Update the grastate yaml file to indicate it is safe to bootstrap from
    this instance.

    :side effect: Writes the grastate.dat file.
    :raises GRAStateFileNotFound: If grastate.dat file does not exist.
    :returns: None
    """

    grastate_file = os.path.join(resolve_data_dir(), "grastate.dat")
    if not os.path.exists(grastate_file):
        raise GRAStateFileNotFound("{} file does not exist"
                                   .format(grastate_file))
    with open(grastate_file, 'r') as f:
        grastate = yaml.safe_load(f)

    # Force safe to bootstrap
    grastate["safe_to_bootstrap"] = 1

    with open(grastate_file, 'w') as f:
        f.write(yaml.dump(grastate))


def maybe_notify_bootstrapped():
    """Maybe notify bootstrapped.

    In the event of a subsequent bootstrap after deploy time, as in the case of
    a cold start, it is necessary to re-notify the cluster relation of the new
    bootstrap UUID.

    This function checks that the cluster has been clustered before and
    notified clients, checks for agreement with the leader on the bootstrap
    UUID and calls notify_bootstrapped to inform the cluster peers of the UUID.

    :side effect: calls kv()
    :side effect: may call notify_bootstrapped()
    :returns: None
    """

    if not check_mysql_connection():
        log("MySQL is down: deferring notify bootstrapped", DEBUG)
        return

    kvstore = kv()
    # Using INITIAL_CLIENT_UPDATE_KEY as this is a step beyond merely
    # clustered, but rather clustered and clients were previously notified.
    if kvstore.get(INITIAL_CLIENT_UPDATE_KEY, False):
        # Handle a change of bootstrap UUID after cold start bootstrap
        lead_cluster_state_uuid = leader_get('bootstrap-uuid')
        cluster_state_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
        if lead_cluster_state_uuid == cluster_state_uuid:
            notify_bootstrapped(cluster_uuid=cluster_state_uuid)


def set_pxc_strict_mode(mode):
    """Set PXC Strict Mode.

    :param mode: Strict mode: DISABLED, PERMISSIVE, ENFORCING or MASTER
    :type backup_dir: str
    :raises: Raises ValueError if mode is not a valid parameter
    :raises: Raises MySQLdb.OperationalError if SQL is not successful
    :returns: None
    :rtype: None
    """
    _VALID_PARAMS = ["DISABLED", "PERMISSIVE", "ENFORCING", "MASTER"]
    mode = mode.upper()
    if mode not in _VALID_PARAMS:
        raise ValueError(
            "'{}' is not a valid parameter for pxc_strict_mode. "
            "Valid options are {}.".format(mode, ", ".join(_VALID_PARAMS)))
    m_helper = get_db_helper()
    m_helper.connect(password=m_helper.get_mysql_root_password())
    m_helper.execute("SET GLOBAL pxc_strict_mode='{}'".format(mode))


def write_root_my_cnf():
    """Write root my.cnf

    :side effect: calls render()
    :returns: None
    :rtype: None
    """
    my_cnf_template = "root-my.cnf"
    root_my_cnf = "/root/.my.cnf"
    context = {"mysql_passwd": leader_get("mysql.passwd")}
    render(my_cnf_template, root_my_cnf, context, perms=0o600)


def mysqldump(backup_dir, databases=None):
    """Execute a MySQL dump

    :param backup_dir: Path to the backup directory
    :type backup_dir: str
    :param databases: Comma delimited database names
    :type database: str
    :side effect: Calls subprocess.check_call
    :raises subprocess.CalledProcessError: If the mysqldump fails
    :returns: Path to the mysqldump file
    :rtype: str
    """
    # In order to enable passwordless use of mysqldump
    # write out my.cnf for user root
    write_root_my_cnf()
    # Enable use of my.cnf by setting HOME env variable
    os.environ["HOME"] = "/root"
    _user = "root"
    _delimiter = ","
    if not os.path.exists(backup_dir):
        mkdir(
            backup_dir, owner="mysql", group="mysql", perms=0o750)

    bucmd = ["/usr/bin/mysqldump", "-u", _user,
             "--default-character-set=utf8",
             "--triggers", "--routines", "--events",
             "--ignore-table=mysql.event"]

    # Bionic and Xenial don't support this parameter
    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) >= "eoan":
        bucmd.append("--column-statistics=0")

    if databases is not None:
        _filename = os.path.join(
            backup_dir,
            "mysqldump-{}-{}".format(
                "-".join(databases.split(_delimiter)),
                datetime.datetime.now().strftime("%Y%m%d%H%M")))
        bucmd.extend(["--result-file", _filename, "--databases"])
        bucmd.extend(databases.split(_delimiter))
    else:
        _filename = os.path.join(
            backup_dir,
            "mysqldump-all-databases-{}".format(
                datetime.datetime.now().strftime("%Y%m%d%H%M")))
        bucmd.extend(["--result-file", _filename, "--all-databases"])

    subprocess.check_call(bucmd)
    gzcmd = ["gzip", _filename]
    subprocess.check_call(gzcmd)
    return "{}.gz".format(_filename)


def update_source(source, key=None):
    """Add source and run apt update."""
    try:
        add_source(source=source, key=key, fail_invalid=True)
        log("add new package source: {}".format(source))
    except (subprocess.CalledProcessError, SourceConfigError) as error:
        log(error, level=ERROR)
        raise
    else:
        apt_update()  # run without retries
        log("apt update after adding a new package source")


def get_nrpe_threads_connected_thresholds():
    """This function get and verifies threshold values.

    The function confirms these conditions:
    Thresholds for `nrpe-threads-connected` should be separable by `,` and
    represented by an integer, where the warning threshold should be
    in the range [0, 100) and the critical threshold in the range (0, 100).
    At the same time, the warning threshold should be lower than
    the critical one.

    :returns: warning threshold, critical threshold
    :rtype: Tuple[int, int]
    :raises: ValueError
    """
    values = config("nrpe-threads-connected").split(",")

    if len(values) != 2:
        raise ValueError("the wrong number of values was set for "
                         "the nrpe-threads-connected")

    try:
        warning_threshold, critical_threshold = int(values[0]), int(values[1])
    except ValueError as error:
        raise error

    if not (0 <= warning_threshold < 100 and 0 < critical_threshold <= 100):
        raise ValueError("the warning threshold must be in the range [0,100) "
                         "and the critical threshold must be in the range "
                         "(0,100]")

    if warning_threshold >= critical_threshold:
        raise ValueError("the warning threshold must be less than critical")

    return warning_threshold, critical_threshold


def write_nagios_my_cnf():
    """Create a MySQL configuration file with nagios user credentials."""
    context = {
        "mysql_user": "nagios", "mysql_passwd": nagios_password(),
    }
    render("nagios-my.cnf", MYSQL_NAGIOS_CREDENTIAL_FILE, context,
           owner="nagios", group="nagios", perms=0o640)


def create_nagios_user():
    """Create MySQL user for nagios to check the status of MySQL.

    This user does not have any permissions set, does not have access
    to any database and can only connect from localhost.

    :raises: OperationalError
    """
    m_helper = None
    if is_leader():
        # Only run the CREATE USER on the leader; it does replicate to other
        # instances.
        m_helper = get_db_helper()
        try:
            m_helper.connect(password=m_helper.get_mysql_root_password())
        except OperationalError:
            log("Could not connect to db", level=ERROR)
            raise
        # NOTE (rgildein): This user has access to the SHOW GLOBAL STATUS
        # statement, which does not require any privilege, only the ability to
        # connect to the server.
        nagios_exists = False
        try:
            # NOTE (rgildein): This method of creation nagios user should be
            # replaced by the `MySQLHelper.create_user` method after
            # bug #1905586 has been fixed and merged.
            nagios_exists = m_helper.select(
                "SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = 'nagios')"
            )
            m_helper.execute(
                "CREATE USER 'nagios'@'localhost' IDENTIFIED BY '{}';"
                .format(nagios_password()))
            m_helper.flush_priviledges()
            log("Created user nagios in database.", level="INFO")
            return
        except OperationalError as error:
            if not nagios_exists:
                log("Creating user nagios failed due: {}".format(error),
                    level="ERROR")
                raise error
            else:
                log("User 'nagios'@'localhost' already exists.", level="INFO")

    # NOTE (rgildein): Update the user's password if it has changed.
    # Update the password for username with new_password.

    # BUG: #1925042
    # This is a strategic hotfix to fix nagios password updates.  The
    # charm-helpers library function set_mysql_password() tries to use the
    # username that was passed, rather than root, to update the mysql.user
    # table and this fails.  Instead, this function uses root to update the
    # password and flush privileges.  Note this needs to be run on each node as
    # it uses UPDATE and flush privileges.

    # See https://galeracluster.com/library/kb/user-changes.html

    # copied and adapted from MySQLHelper.set_mysql_password()
    cursor = None
    try:
        # NOTE(freyes): Due to skip-name-resolve root@$HOSTNAME account
        # fails when using SET PASSWORD so using UPDATE against the
        # mysql.user table is needed, but changes to this table are not
        # replicated across the cluster, so this update needs to run in
        # all the nodes. More info at
        # http://galeracluster.com/documentation-webpages/userchanges.html
        release = CompareHostReleases(lsb_release()['DISTRIB_CODENAME'])
        if release < 'bionic':
            SQL_UPDATE_PASSWD = ("UPDATE mysql.user SET password = "
                                 "PASSWORD( %s ) WHERE user = %s;")
        else:
            # PXC 5.7 (introduced in Bionic) uses authentication_string
            SQL_UPDATE_PASSWD = ("UPDATE mysql.user SET "
                                 "authentication_string = "
                                 "PASSWORD( %s ) WHERE user = %s;")

        if m_helper is None:
            m_helper = get_db_helper()
        try:
            m_helper.connect(password=m_helper.get_mysql_root_password())
        except OperationalError:
            log("Could not connect to db", level=WARNING)
            return
        cursor = m_helper.connection.cursor()
        cursor.execute(SQL_UPDATE_PASSWD, (nagios_password(), 'nagios'))
        cursor.execute('FLUSH PRIVILEGES;')
        m_helper.connection.commit()
    except OperationalError as ex:
        log("Could not connect to db: {}".format(str(ex)), level=WARNING)
    finally:
        if cursor:
            cursor.close()


def set_nagios_user():
    """Create MySQL user and configuration file with user credentials."""
    create_nagios_user()

    write_nagios_my_cnf()
