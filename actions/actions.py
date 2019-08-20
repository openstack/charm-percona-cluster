#!/usr/bin/env python3

import os
import sys
import subprocess
import traceback
import MySQLdb
from contextlib import contextmanager
from time import gmtime, strftime

_path = os.path.dirname(os.path.realpath(__file__))
_hooks = os.path.abspath(os.path.join(_path, '../hooks'))
_root = os.path.abspath(os.path.join(_path, '..'))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_hooks)
_add_path(_root)


from charmhelpers.core.hookenv import (
    action_get,
    action_set,
    action_fail,
    leader_set,
    is_leader,
)

from charmhelpers.core.host import (
    CompareHostReleases,
    lsb_release,
)
from charmhelpers.contrib.database.mysql import MySQLHelper

import percona_utils
import percona_hooks

@contextmanager
def open_mysql_cursor(connection):
    """ Opens up a new MySQL cursor """

    cur = connection.cursor()
    yield cur
    cur.close()

@contextmanager
def open_mysql():
    """ Opens up a new MySQL connection """

    db_helper = MySQLHelper(
        rpasswdf_template='/var/lib/mysql/mysql.passwd',
        upasswdf_template='/var/lib/mysql/mysql-{}.passwd',
        delete_ondisk_passwd_file=False
    )
    password = db_helper.get_mysql_root_password()

    con = MySQLdb.connect(
        host="localhost",
        user="root",
        passwd=password,
    )
    yield con
    con.close()

def validate_parameters(params, required_keys):
    for key in required_keys:
        if not params.get(key):
            raise Exception("Missing required parameter: {}".format(key))

def user_exists(connection, username):
    with open_mysql_cursor(connection) as cursor:
        cursor.execute(
            "SELECT count(1) FROM mysql.user WHERE user = %s ;",
            (username, )
        )
        if cursor.fetchone()[0] == 1:
            return True
    return False


def create_user(params):
    validate_parameters(params, ["username", "password"])
    username = params["username"]
    password = params["password"]

    with open_mysql() as con:
        if user_exists(con, username):
            raise Exception("User already exists: {}".format(username))

        with open_mysql_cursor(con) as cursor:
            cursor.execute(
                "CREATE USER %s@'%%' IDENTIFIED BY %s ;",
                (username, password)
            )
            cursor.execute(
                "GRANT ALL PRIVILEGES ON *.* TO %s@'%%' ;",
                (username, )
            )
    action_set(dict(result="Created user: {}".format(username)))

def set_user_password(params):
    validate_parameters(params, ["username", "password"])

    username = params["username"]
    password = params["password"]
    with open_mysql() as con:
        if not user_exists(con, username):
            raise Exception("User does not exist: {}".format(username))

        with open_mysql_cursor(con) as cursor:
            cursor.execute(
                "ALTER USER %s@'%%' IDENTIFIED BY %s ;",
                (username, password)
            )
    action_set(dict(result="Password updated for user: {}".format(username))) 


def delete_user(params):
    validate_parameters(params, ["username", ])

    username = params["username"]
    with open_mysql() as con:
        if not user_exists(con, username):
            action_set(dict(result="User does not exist: {}".format(username)))
            return

        with open_mysql_cursor(con) as cursor:
            cursor.execute(
                "DELETE FROM mysql.user WHERE User = %s ;",
                (username, )
            )
    action_set(dict(result="Deleted user: {}".format(username))) 


def create_database(params):
    validate_parameters(params, ["database", ])

    database_name = params["database"]
    with open_mysql() as con:
        with open_mysql_cursor(con) as cursor:
            cursor.execute(
                "SELECT count(1) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = %s ;",
                (database_name, )
            )
            if cursor.fetchone()[0] != 0:
                action_set(dict(
                    result="Database already exists: {}".format(database_name)
                ))
                return
            cursor.execute("CREATE DATABASE `{}` ;".format(database_name))
    action_set(dict(result="Database created: {}".format(database_name))) 

def pause(args):
    """Pause the MySQL service.

    @raises Exception should the service fail to stop.
    """
    percona_utils.pause_unit_helper(percona_utils.register_configs())


def resume(args):
    """Resume the MySQL service.

    @raises Exception should the service fail to start.
    """
    percona_utils.resume_unit_helper(percona_utils.register_configs())
    # NOTE(ajkavanagh) - we force a config_changed pseudo-hook to see if the
    # unit needs to bootstrap or restart it's services here.
    percona_hooks.config_changed()


def complete_cluster_series_upgrade(args):
    """ Complete the series upgrade process

    After all nodes have been upgraded, this action is run to inform the whole
    cluster the upgrade is done. Config files will be re-rendered with each
    peer in the wsrep_cluster_address config.
    """
    if is_leader():
        # Unset cluster_series_upgrading
        leader_set(cluster_series_upgrading="")
        leader_set(cluster_series_upgrade_leader="")
    percona_hooks.config_changed()


def backup(args):
    basedir = (action_get("basedir")).lower()
    compress = action_get("compress")
    incremental = action_get("incremental")
    sstpw = percona_utils._get_password("sst-password")
    optionlist = []

    # innobackupex will not create recursive dirs that do not already exist,
    # so help it along
    if not os.path.exists(basedir):
        os.makedirs(basedir)

    # Build a list of options to pass to innobackupex
    if compress:
        optionlist.append("--compress")

    if incremental:
        optionlist.append("--incremental")

    # xtrabackup 2.4 (introduced in Bionic) doesn't support compact backups
    if CompareHostReleases(lsb_release()['DISTRIB_CODENAME']) < 'bionic':
        optionlist.append("--compact")

    try:
        subprocess.check_call(
            ['innobackupex', '--galera-info', '--rsync', basedir,
             '--user=sstuser', '--password={}'.format(sstpw)] + optionlist)
        action_set({
            'time-completed': (strftime("%Y-%m-%d %H:%M:%S", gmtime())),
            'outcome': 'Success'}
        )
    except subprocess.CalledProcessError as e:
        action_set({
            'time-completed': (strftime("%Y-%m-%d %H:%M:%S", gmtime())),
            'output': e.output,
            'return-code': e.returncode,
            'traceback': traceback.format_exc()})
        action_fail("innobackupex failed, you should log on to the unit"
                    "and check the status of the database")


def bootstrap_pxc(args):
    """ Force a bootstrap on this node

    This action will run bootstrap-pxc on this node bootstrapping the cluster.
    This action should only be run after a cold start requiring a bootstrap.
    This action should only be run on the node with the highest sequence number
    as displayed in workgoup status and found in grastate.dat.
    If this unit has the highest sequence number and is not the juju leader
    node, a subsequent action run of notify-bootstrapped is required.
    """

    try:
        # Force safe to bootstrap
        percona_utils.set_grastate_safe_to_bootstrap()
        # Boostrap this node
        percona_utils.bootstrap_pxc()
        percona_utils.notify_bootstrapped()
    except (percona_utils.GRAStateFileNotFound, OSError) as e:
        action_set({
            'output': e.output,
            'return-code': e.returncode})
        action_fail("The GRAState file does not exist or cannot "
                    "be written to.")
    except (subprocess.CalledProcessError, Exception) as e:
        action_set({
            'output': e.output,
            'return-code': e.returncode,
            'traceback': traceback.format_exc()})
        action_fail("The bootstrap-pxc failed. "
                    "See traceback in show-action-output")
    action_set({
        'output': "Bootstrap succeeded. "
                  "Wait for the other units to run update-status"})
    percona_utils.assess_status(percona_utils.register_configs())


def notify_bootstrapped(args):
    """Notify the cluster of the new bootstrap cluster UUID.

    As a consequence of timing, this action will often need to be executed
    after the bootstrap-pxc action. It will need to be run on a different unit
    than was bootstrap-pxc was executed on.
    """
    percona_utils.notify_bootstrapped()


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume, "backup": backup,
           "complete-cluster-series-upgrade": complete_cluster_series_upgrade,
           "bootstrap-pxc": bootstrap_pxc,
           "notify-bootstrapped": notify_bootstrapped,
           "create-user": create_user, "delete-user": delete_user, "set-user-password": set_user_password, "create-database": create_database,}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        s = "Action {} undefined".format(action_name)
        action_fail(s)
        return s
    else:
        try:
            params = action_get()
            action(params)
        except Exception as e:
            action_fail("Action {} failed: {}".format(action_name, str(e)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
