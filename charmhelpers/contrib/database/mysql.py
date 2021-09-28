# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Helper for working with a MySQL database"""
import collections
import copy
import json
import re
import sys
import platform
import os
import glob
import six

# from string import upper

from charmhelpers.core.host import (
    CompareHostReleases,
    lsb_release,
    mkdir,
    pwgen,
    write_file
)
from charmhelpers.core.hookenv import (
    config as config_get,
    relation_get,
    related_units,
    unit_get,
    log,
    DEBUG,
    ERROR,
    INFO,
    WARNING,
    leader_get,
    leader_set,
    is_leader,
)
from charmhelpers.fetch import (
    apt_install,
    apt_update,
    filter_installed_packages,
)
from charmhelpers.contrib.network.ip import get_host_ip

try:
    import MySQLdb
except ImportError:
    apt_update(fatal=True)
    if six.PY2:
        apt_install(filter_installed_packages(['python-mysqldb']), fatal=True)
    else:
        apt_install(filter_installed_packages(['python3-mysqldb']), fatal=True)
    import MySQLdb


class MySQLSetPasswordError(Exception):
    pass


class MySQLHelper(object):

    def __init__(self, rpasswdf_template, upasswdf_template, host='localhost',
                 migrate_passwd_to_leader_storage=True,
                 delete_ondisk_passwd_file=True, user="root", password=None,
                 port=None, connect_timeout=None):
        self.user = user
        self.host = host
        self.password = password
        self.port = port
        # default timeout of 30 seconds.
        self.connect_timeout = connect_timeout or 30

        # Password file path templates
        self.root_passwd_file_template = rpasswdf_template
        self.user_passwd_file_template = upasswdf_template

        self.migrate_passwd_to_leader_storage = migrate_passwd_to_leader_storage
        # If we migrate we have the option to delete local copy of root passwd
        self.delete_ondisk_passwd_file = delete_ondisk_passwd_file
        self.connection = None

    def connect(self, user='root', password=None, host=None, port=None,
                connect_timeout=None):
        _connection_info = {
            "user": user or self.user,
            "passwd": password or self.password,
            "host": host or self.host
        }
        # set the connection timeout; for mysql8 it can hang forever, so some
        # timeout is required.
        timeout = connect_timeout or self.connect_timeout
        if timeout:
            _connection_info["connect_timeout"] = timeout
        # port cannot be None but we also do not want to specify it unless it
        # has been explicit set.
        port = port or self.port
        if port is not None:
            _connection_info["port"] = port

        log("Opening db connection for %s@%s" % (user, host), level=DEBUG)
        try:
            self.connection = MySQLdb.connect(**_connection_info)
        except Exception as e:
            log("Failed to connect to database due to '{}'".format(str(e)),
                level=ERROR)
            raise

    def database_exists(self, db_name):
        cursor = self.connection.cursor()
        try:
            cursor.execute("SHOW DATABASES")
            databases = [i[0] for i in cursor.fetchall()]
        finally:
            cursor.close()

        return db_name in databases

    def create_database(self, db_name):
        cursor = self.connection.cursor()
        try:
            cursor.execute("CREATE DATABASE `{}` CHARACTER SET UTF8"
                           .format(db_name))
        finally:
            cursor.close()

    def grant_exists(self, db_name, db_user, remote_ip):
        cursor = self.connection.cursor()
        priv_string = "GRANT ALL PRIVILEGES ON `{}`.* " \
                      "TO '{}'@'{}'".format(db_name, db_user, remote_ip)
        try:
            cursor.execute("SHOW GRANTS for '{}'@'{}'".format(db_user,
                                                              remote_ip))
            grants = [i[0] for i in cursor.fetchall()]
        except MySQLdb.OperationalError:
            return False
        finally:
            cursor.close()

        # TODO: review for different grants
        return priv_string in grants

    def create_grant(self, db_name, db_user, remote_ip, password):
        cursor = self.connection.cursor()
        try:
            # TODO: review for different grants
            cursor.execute("GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}' "
                           "IDENTIFIED BY '{}'".format(db_name,
                                                       db_user,
                                                       remote_ip,
                                                       password))
        finally:
            cursor.close()

    def create_admin_grant(self, db_user, remote_ip, password):
        cursor = self.connection.cursor()
        try:
            cursor.execute("GRANT ALL PRIVILEGES ON *.* TO '{}'@'{}' "
                           "IDENTIFIED BY '{}'".format(db_user,
                                                       remote_ip,
                                                       password))
        finally:
            cursor.close()

    def cleanup_grant(self, db_user, remote_ip):
        cursor = self.connection.cursor()
        try:
            cursor.execute("DROP FROM mysql.user WHERE user='{}' "
                           "AND HOST='{}'".format(db_user,
                                                  remote_ip))
        finally:
            cursor.close()

    def flush_priviledges(self):
        cursor = self.connection.cursor()
        try:
            cursor.execute("FLUSH PRIVILEGES")
        finally:
            cursor.close()

    def execute(self, sql):
        """Execute arbitrary SQL against the database."""
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql)
        finally:
            cursor.close()

    def select(self, sql):
        """
        Execute arbitrary SQL select query against the database
        and return the results.

        :param sql: SQL select query to execute
        :type sql: string
        :returns: SQL select query result
        :rtype: list of lists
        :raises: MySQLdb.Error
        """
        cursor = self.connection.cursor()
        try:
            cursor.execute(sql)
            results = [list(i) for i in cursor.fetchall()]
        finally:
            cursor.close()
        return results

    def migrate_passwords_to_leader_storage(self, excludes=None):
        """Migrate any passwords storage on disk to leader storage."""
        if not is_leader():
            log("Skipping password migration as not the lead unit",
                level=DEBUG)
            return
        dirname = os.path.dirname(self.root_passwd_file_template)
        path = os.path.join(dirname, '*.passwd')
        for f in glob.glob(path):
            if excludes and f in excludes:
                log("Excluding %s from leader storage migration" % (f),
                    level=DEBUG)
                continue

            key = os.path.basename(f)
            with open(f, 'r') as passwd:
                _value = passwd.read().strip()

            try:
                leader_set(settings={key: _value})

                if self.delete_ondisk_passwd_file:
                    os.unlink(f)
            except ValueError:
                # NOTE cluster relation not yet ready - skip for now
                pass

    def get_mysql_password_on_disk(self, username=None, password=None):
        """Retrieve, generate or store a mysql password for the provided
        username on disk."""
        if username:
            template = self.user_passwd_file_template
            passwd_file = template.format(username)
        else:
            passwd_file = self.root_passwd_file_template

        _password = None
        if os.path.exists(passwd_file):
            log("Using existing password file '%s'" % passwd_file, level=DEBUG)
            with open(passwd_file, 'r') as passwd:
                _password = passwd.read().strip()
        else:
            log("Generating new password file '%s'" % passwd_file, level=DEBUG)
            if not os.path.isdir(os.path.dirname(passwd_file)):
                # NOTE: need to ensure this is not mysql root dir (which needs
                # to be mysql readable)
                mkdir(os.path.dirname(passwd_file), owner='root', group='root',
                      perms=0o770)
                # Force permissions - for some reason the chmod in makedirs
                # fails
                os.chmod(os.path.dirname(passwd_file), 0o770)

            _password = password or pwgen(length=32)
            write_file(passwd_file, _password, owner='root', group='root',
                       perms=0o660)

        return _password

    def passwd_keys(self, username):
        """Generator to return keys used to store passwords in peer store.

        NOTE: we support both legacy and new format to support mysql
        charm prior to refactor. This is necessary to avoid LP 1451890.
        """
        keys = []
        if username == 'mysql':
            log("Bad username '%s'" % (username), level=WARNING)

        if username:
            # IMPORTANT: *newer* format must be returned first
            keys.append('mysql-%s.passwd' % (username))
            keys.append('%s.passwd' % (username))
        else:
            keys.append('mysql.passwd')

        for key in keys:
            yield key

    def get_mysql_password(self, username=None, password=None):
        """Retrieve, generate or store a mysql password for the provided
        username using peer relation cluster."""
        excludes = []

        # First check peer relation.
        try:
            for key in self.passwd_keys(username):
                _password = leader_get(key)
                if _password:
                    break

            # If root password available don't update peer relation from local
            if _password and not username:
                excludes.append(self.root_passwd_file_template)

        except ValueError:
            # cluster relation is not yet started; use on-disk
            _password = None

        # If none available, generate new one
        if not _password:
            _password = self.get_mysql_password_on_disk(username, password)

        # Put on wire if required
        if self.migrate_passwd_to_leader_storage:
            self.migrate_passwords_to_leader_storage(excludes=excludes)

        return _password

    def get_mysql_root_password(self, password=None):
        """Retrieve or generate mysql root password for service units."""
        return self.get_mysql_password(username=None, password=password)

    def set_mysql_password(self, username, password, current_password=None):
        """Update a mysql password for the provided username changing the
        leader settings

        To update root's password pass `None` in the username

        :param username: Username to change password of
        :type username: str
        :param password: New password for user.
        :type password: str
        :param current_password: Existing password for user.
        :type current_password: str
        """

        if username is None:
            username = 'root'

        # get root password via leader-get, it may be that in the past (when
        # changes to root-password were not supported) the user changed the
        # password, so leader-get is more reliable source than
        # config.previous('root-password').
        rel_username = None if username == 'root' else username
        if not current_password:
            current_password = self.get_mysql_password(rel_username)

        # password that needs to be set
        new_passwd = password

        # update password for all users (e.g. root@localhost, root@::1, etc)
        try:
            self.connect(user=username, password=current_password)
            cursor = self.connection.cursor()
        except MySQLdb.OperationalError as ex:
            raise MySQLSetPasswordError(('Cannot connect using password in '
                                         'leader settings (%s)') % ex, ex)

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
            cursor.execute(SQL_UPDATE_PASSWD, (new_passwd, username))
            cursor.execute('FLUSH PRIVILEGES;')
            self.connection.commit()
        except MySQLdb.OperationalError as ex:
            raise MySQLSetPasswordError('Cannot update password: %s' % str(ex),
                                        ex)
        finally:
            cursor.close()

        # check the password was changed
        try:
            self.connect(user=username, password=new_passwd)
            self.execute('select 1;')
        except MySQLdb.OperationalError as ex:
            raise MySQLSetPasswordError(('Cannot connect using new password: '
                                         '%s') % str(ex), ex)

        if not is_leader():
            log('Only the leader can set a new password in the relation',
                level=DEBUG)
            return

        for key in self.passwd_keys(rel_username):
            _password = leader_get(key)
            if _password:
                log('Updating password for %s (%s)' % (key, rel_username),
                    level=DEBUG)
                leader_set(settings={key: new_passwd})

    def set_mysql_root_password(self, password, current_password=None):
        """Update mysql root password changing the leader settings

        :param password: New password for user.
        :type password: str
        :param current_password: Existing password for user.
        :type current_password: str
        """
        self.set_mysql_password(
            'root',
            password,
            current_password=current_password)

    def normalize_address(self, hostname):
        """Ensure that address returned is an IP address (i.e. not fqdn)"""
        if config_get('prefer-ipv6'):
            # TODO: add support for ipv6 dns
            return hostname

        if hostname != unit_get('private-address'):
            return get_host_ip(hostname, fallback=hostname)

        # Otherwise assume localhost
        return '127.0.0.1'

    def get_allowed_units(self, database, username, relation_id=None, prefix=None):
        """Get list of units with access grants for database with username.

        This is typically used to provide shared-db relations with a list of
        which units have been granted access to the given database.
        """
        if not self.connection:
            self.connect(password=self.get_mysql_root_password())
        allowed_units = set()
        if not prefix:
            prefix = database
        for unit in related_units(relation_id):
            settings = relation_get(rid=relation_id, unit=unit)
            # First check for setting with prefix, then without
            for attr in ["%s_hostname" % (prefix), 'hostname']:
                hosts = settings.get(attr, None)
                if hosts:
                    break

            if hosts:
                # hostname can be json-encoded list of hostnames
                try:
                    hosts = json.loads(hosts)
                except ValueError:
                    hosts = [hosts]
            else:
                hosts = [settings['private-address']]

            if hosts:
                for host in hosts:
                    host = self.normalize_address(host)
                    if self.grant_exists(database, username, host):
                        log("Grant exists for host '%s' on db '%s'" %
                            (host, database), level=DEBUG)
                        if unit not in allowed_units:
                            allowed_units.add(unit)
                    else:
                        log("Grant does NOT exist for host '%s' on db '%s'" %
                            (host, database), level=DEBUG)
            else:
                log("No hosts found for grant check", level=INFO)

        return allowed_units

    def configure_db(self, hostname, database, username, admin=False):
        """Configure access to database for username from hostname."""
        if not self.connection:
            self.connect(password=self.get_mysql_root_password())
        if not self.database_exists(database):
            self.create_database(database)

        remote_ip = self.normalize_address(hostname)
        password = self.get_mysql_password(username)
        if not self.grant_exists(database, username, remote_ip):
            if not admin:
                self.create_grant(database, username, remote_ip, password)
            else:
                self.create_admin_grant(username, remote_ip, password)
            self.flush_priviledges()

        return password


# `_singleton_config_helper` stores the instance of the helper class that is
# being used during a hook invocation.
_singleton_config_helper = None


def get_mysql_config_helper():
    global _singleton_config_helper
    if _singleton_config_helper is None:
        _singleton_config_helper = MySQLConfigHelper()
    return _singleton_config_helper


class MySQLConfigHelper(object):
    """Base configuration helper for MySQL."""

    # Going for the biggest page size to avoid wasted bytes.
    # InnoDB page size is 16MB

    DEFAULT_PAGE_SIZE = 16 * 1024 * 1024
    DEFAULT_INNODB_BUFFER_FACTOR = 0.50
    DEFAULT_INNODB_BUFFER_SIZE_MAX = 512 * 1024 * 1024

    # Validation and lookups for InnoDB configuration
    INNODB_VALID_BUFFERING_VALUES = [
        'none',
        'inserts',
        'deletes',
        'changes',
        'purges',
        'all'
    ]
    INNODB_FLUSH_CONFIG_VALUES = {
        'fast': 2,
        'safest': 1,
        'unsafe': 0,
    }

    def human_to_bytes(self, human):
        """Convert human readable configuration options to bytes."""
        num_re = re.compile('^[0-9]+$')
        if num_re.match(human):
            return human

        factors = {
            'K': 1024,
            'M': 1048576,
            'G': 1073741824,
            'T': 1099511627776
        }
        modifier = human[-1]
        if modifier in factors:
            return int(human[:-1]) * factors[modifier]

        if modifier == '%':
            total_ram = self.human_to_bytes(self.get_mem_total())
            if self.is_32bit_system() and total_ram > self.sys_mem_limit():
                total_ram = self.sys_mem_limit()
            factor = int(human[:-1]) * 0.01
            pctram = total_ram * factor
            return int(pctram - (pctram % self.DEFAULT_PAGE_SIZE))

        raise ValueError("Can only convert K,M,G, or T")

    def is_32bit_system(self):
        """Determine whether system is 32 or 64 bit."""
        try:
            return sys.maxsize < 2 ** 32
        except OverflowError:
            return False

    def sys_mem_limit(self):
        """Determine the default memory limit for the current service unit."""
        if platform.machine() in ['armv7l']:
            _mem_limit = self.human_to_bytes('2700M')  # experimentally determined
        else:
            # Limit for x86 based 32bit systems
            _mem_limit = self.human_to_bytes('4G')

        return _mem_limit

    def get_mem_total(self):
        """Calculate the total memory in the current service unit."""
        with open('/proc/meminfo') as meminfo_file:
            for line in meminfo_file:
                key, mem = line.split(':', 2)
                if key == 'MemTotal':
                    mtot, modifier = mem.strip().split(' ')
                    return '%s%s' % (mtot, modifier[0].upper())

    def get_innodb_flush_log_at_trx_commit(self):
        """Get value for innodb_flush_log_at_trx_commit.

        Use the innodb-flush-log-at-trx-commit or the tunning-level setting
        translated by INNODB_FLUSH_CONFIG_VALUES to get the
        innodb_flush_log_at_trx_commit value.

        :returns: Numeric value for innodb_flush_log_at_trx_commit
        :rtype: Union[None, int]
        """
        _iflatc = config_get('innodb-flush-log-at-trx-commit')
        _tuning_level = config_get('tuning-level')
        if _iflatc:
            return _iflatc
        elif _tuning_level:
            return self.INNODB_FLUSH_CONFIG_VALUES.get(_tuning_level, 1)

    def get_innodb_change_buffering(self):
        """Get value for innodb_change_buffering.

        Use the innodb-change-buffering validated against
        INNODB_VALID_BUFFERING_VALUES to get the innodb_change_buffering value.

        :returns: String value for innodb_change_buffering.
        :rtype: Union[None, str]
        """
        _icb = config_get('innodb-change-buffering')
        if _icb and _icb in self.INNODB_VALID_BUFFERING_VALUES:
            return _icb

    def get_innodb_buffer_pool_size(self):
        """Get value for innodb_buffer_pool_size.

        Return the number value of innodb-buffer-pool-size or dataset-size. If
        neither is set, calculate a sane default based on total memory.

        :returns: Numeric value for innodb_buffer_pool_size.
        :rtype: int
        """
        total_memory = self.human_to_bytes(self.get_mem_total())

        dataset_bytes = config_get('dataset-size')
        innodb_buffer_pool_size = config_get('innodb-buffer-pool-size')

        if innodb_buffer_pool_size:
            innodb_buffer_pool_size = self.human_to_bytes(
                innodb_buffer_pool_size)
        elif dataset_bytes:
            log("Option 'dataset-size' has been deprecated, please use"
                "innodb_buffer_pool_size option instead", level="WARN")
            innodb_buffer_pool_size = self.human_to_bytes(
                dataset_bytes)
        else:
            # NOTE(jamespage): pick the smallest of 50% of RAM or 512MB
            #                  to ensure that deployments in containers
            #                  without constraints don't try to consume
            #                  silly amounts of memory.
            innodb_buffer_pool_size = min(
                int(total_memory * self.DEFAULT_INNODB_BUFFER_FACTOR),
                self.DEFAULT_INNODB_BUFFER_SIZE_MAX
            )

        if innodb_buffer_pool_size > total_memory:
            log("innodb_buffer_pool_size; {} is greater than system available memory:{}".format(
                innodb_buffer_pool_size,
                total_memory), level='WARN')

        return innodb_buffer_pool_size


class PerconaClusterHelper(MySQLConfigHelper):
    """Percona-cluster specific configuration helper."""

    def parse_config(self):
        """Parse charm configuration and calculate values for config files."""
        config = config_get()
        mysql_config = {}
        if 'max-connections' in config:
            mysql_config['max_connections'] = config['max-connections']

        if 'wait-timeout' in config:
            mysql_config['wait_timeout'] = config['wait-timeout']

        if self.get_innodb_flush_log_at_trx_commit() is not None:
            mysql_config['innodb_flush_log_at_trx_commit'] = \
                self.get_innodb_flush_log_at_trx_commit()

        if self.get_innodb_change_buffering() is not None:
            mysql_config['innodb_change_buffering'] = config['innodb-change-buffering']

        if 'innodb-io-capacity' in config:
            mysql_config['innodb_io_capacity'] = config['innodb-io-capacity']

        # Set a sane default key_buffer size
        mysql_config['key_buffer'] = self.human_to_bytes('32M')
        mysql_config['innodb_buffer_pool_size'] = self.get_innodb_buffer_pool_size()
        return mysql_config


class MySQL8Helper(MySQLHelper):

    def grant_exists(self, db_name, db_user, remote_ip):
        cursor = self.connection.cursor()
        priv_string = ("GRANT ALL PRIVILEGES ON {}.* "
                       "TO {}@{}".format(db_name, db_user, remote_ip))
        try:
            cursor.execute("SHOW GRANTS FOR '{}'@'{}'".format(db_user,
                                                              remote_ip))
            grants = [i[0] for i in cursor.fetchall()]
        except MySQLdb.OperationalError:
            return False
        finally:
            cursor.close()

        # Different versions of MySQL use ' or `. Ignore these in the check.
        return priv_string in [
            i.replace("'", "").replace("`", "") for i in grants]

    def create_grant(self, db_name, db_user, remote_ip, password):
        if self.grant_exists(db_name, db_user, remote_ip):
            return

        # Make sure the user exists
        # MySQL8 must create the user before the grant
        self.create_user(db_user, remote_ip, password)

        cursor = self.connection.cursor()
        try:
            cursor.execute("GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{}'"
                           .format(db_name, db_user, remote_ip))
        finally:
            cursor.close()

    def create_user(self, db_user, remote_ip, password):

        SQL_USER_CREATE = (
            "CREATE USER '{db_user}'@'{remote_ip}' "
            "IDENTIFIED BY '{password}'")

        cursor = self.connection.cursor()
        try:
            cursor.execute(SQL_USER_CREATE.format(
                db_user=db_user,
                remote_ip=remote_ip,
                password=password)
            )
        except MySQLdb._exceptions.OperationalError:
            log("DB user {} already exists.".format(db_user),
                "WARNING")
        finally:
            cursor.close()

    def create_router_grant(self, db_user, remote_ip, password):

        # Make sure the user exists
        # MySQL8 must create the user before the grant
        self.create_user(db_user, remote_ip, password)

        # Mysql-Router specific grants
        cursor = self.connection.cursor()
        try:
            cursor.execute("GRANT CREATE USER ON *.* TO '{}'@'{}' WITH GRANT "
                           "OPTION".format(db_user, remote_ip))
            cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON "
                           "mysql_innodb_cluster_metadata.* TO '{}'@'{}'"
                           .format(db_user, remote_ip))
            cursor.execute("GRANT SELECT ON mysql.user TO '{}'@'{}'"
                           .format(db_user, remote_ip))
            cursor.execute("GRANT SELECT ON "
                           "performance_schema.replication_group_members "
                           "TO '{}'@'{}'".format(db_user, remote_ip))
            cursor.execute("GRANT SELECT ON "
                           "performance_schema.replication_group_member_stats "
                           "TO '{}'@'{}'".format(db_user, remote_ip))
            cursor.execute("GRANT SELECT ON "
                           "performance_schema.global_variables "
                           "TO '{}'@'{}'".format(db_user, remote_ip))
        finally:
            cursor.close()

    def configure_router(self, hostname, username):

        if self.connection is None:
            self.connect(password=self.get_mysql_root_password())

        remote_ip = self.normalize_address(hostname)
        password = self.get_mysql_password(username)
        self.create_user(username, remote_ip, password)
        self.create_router_grant(username, remote_ip, password)

        return password


def get_prefix(requested, keys=None):
    """Return existing prefix or None.

    :param requested: Request string. i.e. novacell0_username
    :type requested: str
    :param keys: Keys to determine prefix. Defaults set in function.
    :type keys: List of str keys
    :returns: String prefix i.e. novacell0
    :rtype: Union[None, str]
    """
    if keys is None:
        # Shared-DB default keys
        keys = ["_database", "_username", "_hostname"]
    for key in keys:
        if requested.endswith(key):
            return requested[:-len(key)]


def get_db_data(relation_data, unprefixed):
    """Organize database requests into a collections.OrderedDict

    :param relation_data: shared-db relation data
    :type relation_data: dict
    :param unprefixed: Prefix to use for requests without a prefix. This should
                       be unique for each side of the relation to avoid
                       conflicts.
    :type unprefixed: str
    :returns: Order dict of databases and users
    :rtype: collections.OrderedDict
    """
    # Deep copy to avoid unintentionally changing relation data
    settings = copy.deepcopy(relation_data)
    databases = collections.OrderedDict()

    # Clear non-db related elements
    if "egress-subnets" in settings.keys():
        settings.pop("egress-subnets")
    if "ingress-address" in settings.keys():
        settings.pop("ingress-address")
    if "private-address" in settings.keys():
        settings.pop("private-address")

    singleset = {"database", "username", "hostname"}
    if singleset.issubset(settings):
        settings["{}_{}".format(unprefixed, "hostname")] = (
            settings["hostname"])
        settings.pop("hostname")
        settings["{}_{}".format(unprefixed, "database")] = (
            settings["database"])
        settings.pop("database")
        settings["{}_{}".format(unprefixed, "username")] = (
            settings["username"])
        settings.pop("username")

    for k, v in settings.items():
        db = k.split("_")[0]
        x = "_".join(k.split("_")[1:])
        if db not in databases:
            databases[db] = collections.OrderedDict()
        databases[db][x] = v

    return databases
