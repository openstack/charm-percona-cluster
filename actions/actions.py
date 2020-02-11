#!/usr/bin/python

import os
import sys
import subprocess
import traceback
from time import gmtime, strftime

sys.path.append('hooks')

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
)

from charmhelpers.contrib.openstack.utils import (
    DB_SERIES_UPGRADING_KEY,
)

from percona_utils import (
    pause_unit_helper,
    resume_unit_helper,
    register_configs,
    _get_password,
)
from percona_hooks import config_changed


def pause(args):
    """Pause the MySQL service.

    @raises Exception should the service fail to stop.
    """
    pause_unit_helper(register_configs())


def resume(args):
    """Resume the MySQL service.

    @raises Exception should the service fail to start.
    """
    resume_unit_helper(register_configs())
    # NOTE(ajkavanagh) - we force a config_changed pseudo-hook to see if the
    # unit needs to bootstrap or restart it's services here.
    config_changed()


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
    config_changed()


def backup(args):
    basedir = (action_get("basedir")).lower()
    compress = action_get("compress")
    incremental = action_get("incremental")
    sstpw = _get_password("sst-password")
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


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"pause": pause, "resume": resume, "backup": backup,
           "complete-cluster-series-upgrade": complete_cluster_series_upgrade}


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
