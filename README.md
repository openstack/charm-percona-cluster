# Overview

Percona XtraDB Cluster is a high availability and high scalability solution for
MySQL clustering. Percona XtraDB Cluster integrates Percona Server with the
Galera library of MySQL high availability solutions in a single product package
which enables you to create a cost-effective MySQL cluster.

The percona-cluster charm deploys Percona XtraDB Cluster and provides DB
services to those charms that support the 'mysql-shared' interface. The current
list of such charms can be obtained from the [Charm
Store][charms-requires-mysql-shared] (the charms officially supported by the
OpenStack Charms project are published by 'openstack-charmers').

> **Important**: The eoan series is the last series supported by the
  percona-cluster charm. It is replaced by the
  [mysql-innodb-cluster][mysql-innodb-cluster-charm] and
  [mysql-router][mysql-router-charm] charms in the focal series. See
  [percona-cluster charm: series upgrade to
  Focal][cdg-percona-migration-to-mysql8] for migration steps.

# Usage

## Configuration

This section covers common configuration options. See file `config.yaml` for
the full list of options, along with their descriptions and default values.

#### `max-connections`

The `max-connections` option set the maximum number of allowed connections.
The default is 600. This is an important option and is discussed in the Memory
section below.

#### `min-cluster-size`

The `min-cluster-size` option sets the number of percona-cluster units required
to form its cluster. It is best practice to use this option as doing so ensures
that the charm will wait until the cluster is up before accepting relations
from other client applications.

## Deployment

To deploy a single percona-cluster unit:

    juju deploy percona-cluster

To make use of DB services, simply add a relation between percona-cluster and
an application that supports the 'mysql-shared' interface. For instance:

    juju add-relation percona-cluster:shared-db keystone:shared-db

Passwords required for the correct operation of the deployment are
automatically generated and stored by the application leader. The root password
for mysql can be retrieved using the following command:

    juju run --unit percona-cluster/0 leader-get root-password

Root user DB access is only usable from within one of the deployed units
(access to root is restricted to localhost only).

## High availability

When more than one unit is deployed with the hacluster application the charm
will bring up an HA active/active cluster. The `min-cluster-size` option
should be used (see description above).

To deploy a three-node cluster:

    juju deploy -n 3 --config min-cluster-size=3 percona-cluster

There are two mutually exclusive high availability options: using virtual IP(s)
or DNS. In both cases the hacluster subordinate charm is used to provide the
Corosync and Pacemaker backend HA functionality.

See the [OpenStack high availability][cdg-app-ha-apps] appendix in the
[OpenStack Charms Deployment Guide][cdg] for details.

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions percona-cluster`. If the charm is
not deployed then see file `actions.yaml`.

* `backup`
* `bootstrap-pxc`
* `complete-cluster-series-upgrade`
* `mysqldump`
* `notify-bootstrapped`
* `pause`
* `resume`
* `set-pxc-strict-mode`

## Memory

Percona Cluster is extremely memory sensitive. Setting memory values too low
will give poor performance. Setting them too high will create problems that are
very difficult to diagnose. Please take time to evaluate these settings for
each deployment environment rather than copying and pasting bundle
configurations.

The Percona Cluster charm needs to be able to be deployed in small low memory
development environments as well as high performance production environments.
The charm configuration opinionated defaults favour the developer environment
in order to ease initial testing. Production environments need to consider
carefully the memory requirements for the hardware or cloud in use. Consult a
[MySQL memory calculator][mysql-memory-calculator] to understand the
implications of the values.

Between the 5.5 and 5.6 releases a significant default was changed. The
[performance schema][upstream-performance-schema] defaulted to on for 5.6 and
later. This allocates all the memory that would be required to handle
`max-connections` plus several other memory settings. With 5.5 memory was
allocated during run-time as needed.

The charm now makes performance schema configurable and defaults to off
(False). With the performance schema turned off memory is allocated when needed
during run-time. It is important to understand this can lead to run-time memory
exhaustion if the configuration values are set too high. Consult a [MySQL
memory calculator][mysql-memory-calculator] to understand the implications of
the values.

The value of `max-connections` should strike a balance between connection
exhaustion and memory exhaustion. Occasionally connection exhaustion occurs in
large production HA clouds with a value of less than 2000. The common practice
became to set it unrealistically high (near 10k or 20k). In the move to 5.6 on
Xenial this became a problem as Percona would fail to start up or behave
erratically as memory exhaustion occurred on the host due to performance schema
being turned on. Even with the default now turned off this value should be
carefully considered against the production requirements and resources
available.

## MySQL asynchronous replication

This charm supports MySQL asynchronous replication feature which can be used
to replicate databases between multiple Percona XtraDB Clusters. In order to
setup master-slave replication of "example1" and "example2" databases between
"pxc1" and "pxc2" applications, first configure mandatory options:

    juju config pxc1 databases-to-replicate="database1:table1,table2;database2"
    juju config pxc2 databases-to-replicate="database1:table1,table2;database2"
    juju config pxc1 cluster-id=1
    juju config pxc2 cluster-id=2

and then relate them:

    juju add-relation pxc1:master pxc2:slave

In order to setup master-master replication, add another relation:

    juju add-relation pxc2:master pxc1:slave

In the same way circular replication can be setup between multiple clusters.

## Network Space support

This charm supports the use of Juju Network Spaces, allowing the charm to be
bound to network space configurations managed directly by Juju. This is only
supported with Juju 2.0 and above.

You can ensure that database connections and cluster peer communication are
bound to specific network spaces by binding the appropriate interfaces:

    juju deploy percona-cluster --bind "shared-db=internal-space cluster=internal-space"

Alternatively, configuration can be provided as part of a bundle:

    percona-cluster:
      charm: cs:xenial/percona-cluster
      num_units: 1
      bindings:
        shared-db: internal-space
        cluster: internal-space

The 'cluster' endpoint binding is used to determine which network space units
within the percona-cluster deployment should use for communication with each
other; the 'shared-db' endpoint binding is used to determine which network
space should be used for access to MySQL databases services from other charms.

> **Note**: Spaces must be configured in the underlying provider prior to
  attempting to use them.

> **Note**: Existing deployments using the access-network configuration option
  will continue to function; this option is preferred over any network space
  binding provided for the 'shared-db' relation if set.

# Limitations

Note that Percona XtraDB Cluster is not a 'scale-out' MySQL solution; reads
and writes are channelled through a single service unit and synchronously
replicated to other nodes in the cluster; reads/writes are as slow as the
slowest node you have in your deployment.

# Series Upgrade

## Procedure

1. Take a backup of all the databases

    juju run-action mysql/N backup

 * Get that backup off the mysql/N unit and somewhere safe.

    juju scp -- -r mysql/N:/opt/backups/mysql /path/to/local/backup/dir

2. Pause all non-leader units and corresponding hacluster units.
The leader node will remain up for the time being. This is to ensure the leader
has the latest sequence number and will be considered the most up to date by
the cluster.

    juju run-action hacluster/N pause
    juju run-action percona-cluster/N pause

3. Prepare the leader node

    juju upgrade-series $MACHINE_NUMBER prepare $SERIES

4. Administratively perform the upgrade.
* do-release-upgrade plus any further steps administratively required steps for an upgrade.

5. Reboot

6. Complete the series upgrade on the leader:

    juju upgrade-series $MACHINE_NUMBER complete

7. Administratively validate the leader node database is up and running
* Connect to the database and check for expected data
* Review "SHOW GLOBAL STATUS;"

8. Upgrade the non-leader nodes one at a time following the same pattern summarized bellow:

* juju upgrade-series $MACHINE_NUMBER prepare $SERIES
* Administratively Upgrade
* Reboot
* juju upgrade-series $MACHINE_NUMBER complete
* Validate

9. Finalize the upgrade
Run action on leader node.
This action informs each node of the cluster the upgrade process is complete cluster wide.
This also updates mysql configuration with all peers in the cluster.

    juju run-action mysql/N complete-cluster-series-upgrade

10. Set future instance to the new series and set the source origin

    juju set-series percona-cluster xenial
    juju config mysql source=distro

## Upstream documentation

* [Upgrading Percona XtraDB Cluster][upstream-upgrading-percona]
* [Percona XtraDB Cluster In-Place Upgrading Guide: From 5.5 to 5.6][upstream-upgrading-55-to-56]
* [Galera replication - how to recover a PXC cluster][upstream-recovering]

# Cold Boot

In the event of an unexpected power outage and cold boot, the cluster will be
unable to reestablish itself without manual intervention.

The cluster will be in scenario 3 or 6 from the upstream [Percona Cluster
documentation](https://www.percona.com/blog/2014/09/01/galera-replication-how-to-recover-a-pxc-cluster/)
Please read the upstream documentation as it provides context to the steps
outlined here. In either scenario, it is necessary to choose a unit to become
the bootstrap node.

## Determine the node with the highest sequence number

This information can be found in the
`/var/lib/percona-xtradb-cluster/grastate.dat` file. The charm will also display
this information in the juju status.

Example `juju status` after a cold boot of `percona-cluster`

    Unit                Workload  Agent  Machine  Public address  Ports     Message
    keystone/0*         active    idle   0        10.5.0.32       5000/tcp  Unit is ready
    percona-cluster/0   blocked   idle   1        10.5.0.20       3306/tcp  MySQL is down. Sequence Number: 355. Safe To Bootstrap: 0
      hacluster/0       active    idle            10.5.0.20                 Unit is ready and clustered
    percona-cluster/1   blocked   idle   2        10.5.0.17       3306/tcp  MySQL is down. Sequence Number: 355. Safe To Bootstrap: 0
      hacluster/1       active    idle            10.5.0.17                 Unit is ready and clustered
    percona-cluster/2*  blocked   idle   3        10.5.0.27       3306/tcp  MySQL is down. Sequence Number: 355. Safe To Bootstrap: 0
      hacluster/2*      active    idle            10.5.0.27                 Unit is ready and clustered

*Note*: An application leader is denoted by any asterisk in the Unit column.

In the above example all the sequence numbers match. This means we can
bootstrap from any unit we choose.

In the next example the percona-cluster/2 node has the highest sequence number
so we must choose that node to avoid data loss.

    Unit                Workload  Agent  Machine  Public address  Ports     Message
    keystone/0*         active    idle   0        10.5.0.32       5000/tcp  Unit is ready
    percona-cluster/0*  blocked   idle   1        10.5.0.20       3306/tcp  MySQL is down. Sequence Number: 1318. Safe To Bootstrap: 0
      hacluster/0*      active    idle            10.5.0.20                 Unit is ready and clustered
    percona-cluster/1   blocked   idle   2        10.5.0.17       3306/tcp  MySQL is down. Sequence Number: 1318. Safe To Bootstrap: 0
      hacluster/1       active    idle            10.5.0.17                 Unit is ready and clustered
    percona-cluster/2   blocked   idle   3        10.5.0.27       3306/tcp  MySQL is down. Sequence Number: 1325. Safe To Bootstrap: 0
      hacluster/2       active    idle            10.5.0.27                 Unit is ready and clustered

## Bootstrap the node with the highest sequence number

Run the `bootstrap-pxc` action on the node with the highest sequence number. In
this example, it is unit percona-cluster/2, which happens to be a non-leader.

    juju run-action --wait percona-cluster/2 bootstrap-pxc

## Notify the cluster of the new bootstrap UUID

In the vast majority of cases, once the `bootstrap-pxc` action has been run and
the model has settled the output to the `juju status` command will now look
like this:

    Unit                Workload  Agent  Machine  Public address  Ports     Message
    keystone/0*         active    idle   0        10.5.0.32       5000/tcp  Unit is ready
    percona-cluster/0*  waiting   idle   1        10.5.0.20       3306/tcp  Unit waiting for cluster bootstrap
      hacluster/0*      active    idle            10.5.0.20                 Unit is ready and clustered
    percona-cluster/1   waiting   idle   2        10.5.0.17       3306/tcp  Unit waiting for cluster bootstrap
      hacluster/1       active    idle            10.5.0.17                 Unit is ready and clustered
    percona-cluster/2   waiting   idle   3        10.5.0.27       3306/tcp  Unit waiting for cluster bootstrap
      hacluster/2       active    idle            10.5.0.27                 Unit is ready and clustered

If you observe the above output ("Unit waiting for cluster bootstrap") then the
`notify-bootstrapped` action needs to be run on a unit. There are two
possibilities:

1. If the `bootstrap-pxc` action was run on a leader then run
   `notify-bootstrapped` on a non-leader.
2. If the `bootstrap-pxc` action was run on a non-leader then run
   `notify-bootstrapped` on the leader.

In the current example, the first action was run on a non-leader so we'll run
the second action on the leader, percona-cluster/0:

    juju run-action percona-cluster/0 notify-bootstrapped --wait

After the model settles, the output should show all nodes in active and ready
state:

    Unit                Workload  Agent  Machine  Public address  Ports     Message
    keystone/0*         active    idle   0        10.5.0.32       5000/tcp  Unit is ready
    percona-cluster/0*  active    idle   1        10.5.0.20       3306/tcp  Unit is ready
      hacluster/0*      active    idle            10.5.0.20                 Unit is ready and clustered
    percona-cluster/1   active    idle   2        10.5.0.17       3306/tcp  Unit is ready
      hacluster/1       active    idle            10.5.0.17                 Unit is ready and clustered
    percona-cluster/2   active    idle   3        10.5.0.27       3306/tcp  Unit is ready
      hacluster/2       active    idle            10.5.0.27                 Unit is ready and clustered

The percona-cluster application is now back to a clustered and healthy state.

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-percona-cluster].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[cdg-app-ha-apps]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#ha-applications
[charms-requires-mysql-shared]: https://jaas.ai/search?requires=mysql-shared
[mysql-memory-calculator]: http://www.mysqlcalculator.com/
[lp-bugs-charm-percona-cluster]: https://bugs.launchpad.net/charm-percona-cluster/+filebug
[upstream-performance-schema]: http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-6.html#mysqld-5-6-6-performance-schema
[upstream-upgrading-percona]: https://www.percona.com/doc/percona-xtradb-cluster/LATEST/howtos/upgrade_guide.html
[upstream-upgrading-55-to-56]: https://www.percona.com/doc/percona-xtradb-cluster/5.6/upgrading_guide_55_56.html
[upstream-recovering]: https://www.percona.com/blog/2014/09/01/galera-replication-how-to-recover-a-pxc-cluster/
[juju-docs-actions]: https://jaas.ai/docs/actions
[cdg-percona-migration-to-mysql8]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-series-upgrade-specific-procedures.html#percona-cluster-charm-series-upgrade-to-focal
[mysql-router-charm]: https://jaas.ai/mysql-router
[mysql-innodb-cluster-charm]: https://jaas.ai/mysql-innodb-cluster
