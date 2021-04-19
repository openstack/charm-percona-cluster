#!/usr/bin/env python3

import os
import sys
import subprocess
import traceback
from time import gmtime, strftime

import MySQLdb


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
    relation_ids,
    relation_set,
    leader_set,
    is_leader,
)

from charmhelpers.core.host import (
    CompareHostReleases,
    lsb_release,
    pwgen,
)

from charmhelpers.contrib.openstack.utils import (
    DB_SERIES_UPGRADING_KEY,
)

import percona_utils
import percona_hooks


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
        for r_id in relation_ids('shared-db'):
            relation_set(
                relation_id=r_id,
                relation_settings={DB_SERIES_UPGRADING_KEY: None})
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


def set_pxc_strict_mode(args):
    """Set PXC Strict Mode.
    """
    mode = action_get("mode")
    try:
        percona_utils.set_pxc_strict_mode(mode)
        action_set({"outcome": "Success"})
    except (MySQLdb.OperationalError, ValueError) as e:
        action_set({
            "output": ", ".join(e.args),
            "traceback": traceback.format_exc()})
        action_fail("Setting PXC strict mode {} failed"
                    .format(mode))


def mysqldump(args):
    """Execute a mysqldump backup.

    Execute mysqldump of the database(s).  The mysqldump action will take
    in the databases action parameter. If the databases parameter is unset all
    databases will be dumped, otherwise only the named databases will be
    dumped. The action will use the basedir action parameter to dump the
    database into the base directory.

    A successful mysqldump backup will set the action results key,
    mysqldump-file, with the full path to the dump file.

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.mysqldump
    :returns: This function is called for its side effect
    :rtype: None
    :action param basedir: Base directory to dump the db(s)
    :action param databases: Comma separated string of databases
    :action return:
    """
    basedir = action_get("basedir")
    databases = action_get("databases")

    try:
        filename = percona_utils.mysqldump(basedir, databases=databases)
        action_set({
            "mysqldump-file": filename,
            "outcome": "Success"}
        )
    except subprocess.CalledProcessError as e:
        action_set({
            "output": e.output,
            "return-code": e.returncode,
            "traceback": traceback.format_exc()})
        action_fail("mysqldump failed")


def generate_nagios_password(args):
    """Regenerate nagios password."""
    if is_leader():
        leader_set({"mysql-nagios.passwd": pwgen()})
        percona_utils.set_nagios_user()
        action_set({"output": "New password for nagios created successfully."})
    else:
        action_fail("This action should only take place on the leader unit.")


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume, "backup": backup,
           "complete-cluster-series-upgrade": complete_cluster_series_upgrade,
           "bootstrap-pxc": bootstrap_pxc,
           "notify-bootstrapped": notify_bootstrapped,
           "set-pxc-strict-mode": set_pxc_strict_mode,
           "mysqldump": mysqldump,
           "generate-nagios-password": generate_nagios_password}


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
            action(args)
        except Exception as e:
            action_fail("Action {} failed: {}".format(action_name, str(e)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
