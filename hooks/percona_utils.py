''' General utilities for percona '''
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

from charmhelpers.core.decorators import retry_on_exception
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
    apt_install,
    filter_installed_packages,
    get_upstream_version,
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
HOSTS_FILE = '/etc/hosts'
DEFAULT_MYSQL_PORT = 3306
INITIAL_CLUSTERED_KEY = 'initial-cluster-complete'

# NOTE(ajkavanagh) - this is 'required' for the pause/resume code for
# maintenance mode, but is currently not populated as the
# charm_check_function() checks whether the unit is working properly.
REQUIRED_INTERFACES = {}


class LeaderNoBootstrapUUIDError(Exception):
    """Raised when the leader doesn't have set the bootstrap-uuid attribute"""
    def __init__(self):
        super(LeaderNoBootstrapUUIDError, self).__init__(
            "the leader doesn't have set the bootstrap-uuid attribute")


class InconsistentUUIDError(Exception):
    """Raised when the leader and the unit have different UUIDs set"""
    def __init__(self, leader_uuid, unit_uuid):
        super(InconsistentUUIDError, self).__init__(
            "Leader UUID ('%s') != Unit UUID ('%s')" % (leader_uuid,
                                                        unit_uuid))


class DesyncedException(Exception):
    '''Raised if PXC unit is not in sync with its peers'''
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
              'w') as seeded:
        seeded.write('done')


def setup_percona_repo():
    ''' Configure service unit to use percona repositories '''
    with open('/etc/apt/sources.list.d/percona.list', 'w') as sources:
        sources.write(REPO.format(release=lsb_release()['DISTRIB_CODENAME']))
    subprocess.check_call(['apt-key', 'add', KEY])


def resolve_hostname_to_ip(hostname):
    """Resolve hostname to IP

    @param hostname: hostname to be resolved
    @returns IP address or None if resolution was not possible via DNS
    """
    try:
        import dns.resolver
    except ImportError:
        apt_install(filter_installed_packages(['python-dnspython']),
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
                "(expected=%s, got=%s)" % (min_size, units), level=INFO)
            return False
        else:
            log("Sufficient number of peer units to form cluster {}"
                "".format(min_size, level=DEBUG))
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
    hosts_map = {}

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
                    log("(unit=%s) hostname '%s' provided by cluster relation "
                        "for addr %s" % (unit, hostname, cluster_address),
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
    hosts.sort()
    return hosts


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
        dconf.stdin.write("%s %s/root_password password %s\n" %
                          (package, package, root_pass))
        dconf.stdin.write("%s %s/root_password_again password %s\n" %
                          (package, package, root_pass))
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


def update_hosts_file(map):
    """Percona does not currently like ipv6 addresses so we need to use dns
    names instead. In order to make them resolvable we ensure they are  in
    /etc/hosts.

    See https://bugs.launchpad.net/galera/+bug/1130595 for some more info.
    """
    with open(HOSTS_FILE, 'r') as hosts:
        lines = hosts.readlines()

    log("Updating %s with: %s (current: %s)" % (HOSTS_FILE, map, lines),
        level=DEBUG)

    newlines = []
    for ip, hostname in map.items():
        if not ip or not hostname:
            continue

        keepers = []
        for line in lines:
            _line = line.split()
            if len(line) < 2 or not (_line[0] == ip or hostname in _line[1:]):
                keepers.append(line)
            else:
                log("Marking line '%s' for update or removal" % (line.strip()),
                    level=DEBUG)

        lines = keepers
        newlines.append("%s %s\n" % (ip, hostname))

    lines += newlines

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        with open(tmpfile.name, 'w') as hosts:
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


def _cmp(x, y):
    """Shim for py2 py3 compat."""
    return (x > y) - (x < y)


def unit_sorted(units):
    """Return a sorted list of unit names."""
    return sorted(
        units, lambda a, b: _cmp(int(a.split('/')[-1]), int(b.split('/')[-1])))


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
            log("'%s' already exists, skipping" % dest_file, level='INFO')


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
        cursor.execute("show status like '%s'" % (key))
        ret = cursor.fetchall()
    except:
        log("Failed to get '%s'", ERROR)
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
            raise Exception("Found inconsistent bootstrap uuids: "
                            "{}".format((uuids)))
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
    log("wsrep_ready: '%s'" % wsrep_ready, DEBUG)
    if wsrep_ready.lower() in ['on', 'ready']:
        cluster_state_uuid = get_wsrep_value('wsrep_cluster_state_uuid')
    else:
        cluster_state_uuid = None

    if not cluster_state_uuid:
        log("UUID is empty: '%s'" % cluster_state_uuid, level=DEBUG)
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


def charm_check_func():
    """Custom function to assess the status of the current unit

    @returns (status, message) - tuple of strings if an issue
    """
    if is_unit_upgrading_set():
        # Avoid looping through attempting to determine cluster_in_sync
        return ("blocked", "Unit upgrading.")

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
    assess_status_func(configs)()
    if pxc_installed():
        # NOTE(fnordahl) ensure we do not call application_version_set with
        # None argument.  New charm deployments will have the meta-package
        # installed, but upgraded deployments will not.
        def _possible_packages():
            base = determine_packages()[0]
            yield base
            if '.' not in base:
                for i in range(5, 7+1):
                    yield base+'-5.'+str(i)
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
    return make_assess_status_func(
        configs, REQUIRED_INTERFACES,
        charm_func=lambda _: charm_check_func(),
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
        raise Exception("Configured binlogs directory (%s) must not be inside "
                        "mysql data dir" % (binlogs_directory))

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

    peers = {}
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
        return False

    m_helper = get_db_helper()

    # password that needs to be set
    new_root_passwd = cfg['root-password'] or root_password()
    m_helper.set_mysql_root_password(new_root_passwd)

    # check the password was changed
    try:
        m_helper.connect(user='root', password=new_root_passwd)
        m_helper.execute('select 1;')
    except OperationalError as ex:
        log("Error connecting using new password: %s" % str(ex), level=DEBUG)
        log(('Cannot connect using new password, not updating password in '
             'the relation'), level=WARNING)
        return


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
    if config('autoevict') is not None:
        wsrep_provider_options.append(
            'evs.auto_evict={}'.format(config('autoevict')))
        wsrep_provider_options.append(
            'evs.version=1')

    peer_timeout = config('peer-timeout')
    if peer_timeout and(not peer_timeout.startswith('PT') or
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
            databases_and_tables = {}
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
            .format(e.message))
    return databases_to_replicate


def check_invalid_chars(data, bad_chars_re="[\^\\/?%*:|\"'<>., ]"):
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
            raise(InvalidCharacters(
                "Invalid character '{}' in '{}'"
                .format(m.group(0), data_string)))
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
