#!/usr/bin/env python3

import os
import sys
import subprocess
import traceback
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
    try:
        # Force safe to bootstrap
        percona_utils.set_grstate_safe_to_bootstrap()
        # Boostrap this node
        percona_utils.bootstrap_pxc()
    except (percona_utils.GRStateFileNotFound, OSError) as e:
        action_set({
            'output': e.output,
            'return-code': e.returncode})
        action_fail("The GRState file does not exist or cannot be written to.")
    except (subprocess.CalledProcessError, Exception) as e:
        action_set({
            'output': e.output,
            'return-code': e.returncode,
            'traceback': traceback.format_exc()})
        action_fail("The bootstrap-pxc failed. "
                    "See traceback in show-action-output")
    action_set({
        'output': "Bootstrap succeded. "
                  "Wait for the other units to run update-status"})
    percona_utils.assess_status(percona_utils.register_configs())


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume, "backup": backup,
           "complete-cluster-series-upgrade": complete_cluster_series_upgrade,
           "bootstrap-pxc": bootstrap_pxc}


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
