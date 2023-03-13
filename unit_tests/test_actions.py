from unittest import mock
from unittest.mock import patch

from test_utils import CharmTestCase

# we have to patch out harden decorator because hooks/percona_hooks.py gets
# imported via actions.py and will freak out if it trys to run in the context
# of a test.
with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    from actions import actions


class PauseTestCase(CharmTestCase):

    def setUp(self):
        super(PauseTestCase, self).setUp(
            actions.percona_utils, ["pause_unit_helper", "register_configs"])

    def test_pauses_services(self):
        self.register_configs.return_value = "test-config"
        actions.pause([])
        self.pause_unit_helper.assert_called_once_with('test-config')


class ResumeTestCase(CharmTestCase):

    def setUp(self):
        super(ResumeTestCase, self).setUp(
            actions.percona_utils, ["resume_unit_helper", "register_configs"])

    def test_pauses_services(self):
        self.register_configs.return_value = "test-config"
        with patch('actions.actions.percona_hooks.config_changed'
                   ) as config_changed:
            actions.resume([])
            self.resume_unit_helper.assert_called_once_with('test-config')
            config_changed.assert_called_once_with()


class CompleteClusterSeriesUpgrade(CharmTestCase):

    def setUp(self):
        to_patch = [
            "is_leader",
            "leader_set",
            "relation_ids",
            "relation_set"]
        super(CompleteClusterSeriesUpgrade, self).setUp(
            actions, to_patch)

    def test_leader_complete_series_upgrade(self):
        self.is_leader.return_value = True
        self.relation_ids.return_value = ['relid:1']
        calls = [mock.call(cluster_series_upgrading=""),
                 mock.call(cluster_series_upgrade_leader="")]
        with patch('actions.actions.percona_hooks.config_changed'
                   ) as config_changed:
            actions.complete_cluster_series_upgrade([])
            self.leader_set.assert_has_calls(calls)
            config_changed.assert_called_once_with()
            self.relation_set.assert_called_once_with(
                relation_id='relid:1',
                relation_settings={'cluster-series-upgrading': None})

    def test_non_leader_complete_series_upgrade(self):
        self.is_leader.return_value = False
        with patch('actions.actions.percona_hooks.config_changed'
                   ) as config_changed:
            actions.complete_cluster_series_upgrade([])
            self.leader_set.assert_not_called()
            config_changed.assert_called_once_with()


class MainTestCase(CharmTestCase):

    def setUp(self):
        super(MainTestCase, self).setUp(actions, ["action_fail"])

    def test_invokes_action(self):
        dummy_calls = []

        def dummy_action(args):
            dummy_calls.append(True)

        with mock.patch.dict(actions.ACTIONS, {"foo": dummy_action}):
            actions.main(["foo"])
        self.assertEqual(dummy_calls, [True])

    def test_unknown_action(self):
        """Unknown actions aren't a traceback."""
        exit_string = actions.main(["foo"])
        self.assertEqual("Action foo undefined", exit_string)

    def test_failing_action(self):
        """Actions which traceback trigger action_fail() calls."""
        dummy_calls = []

        self.action_fail.side_effect = dummy_calls.append

        def dummy_action(args):
            raise ValueError("uh oh")

        with mock.patch.dict(actions.ACTIONS, {"foo": dummy_action}):
            actions.main(["foo"])
        self.assertEqual(dummy_calls, ["Action foo failed: uh oh"])


class NagiosTestCase(CharmTestCase):

    def setUp(self):
        super(NagiosTestCase, self).setUp(actions,
                                          ["action_set",
                                           "action_fail",
                                           "is_leader",
                                           "leader_set",
                                           "pwgen",
                                           ])

    @patch.object(actions.percona_utils, "set_nagios_user")
    def test_generate_nagios_password(self, mock_set_nagios_user):
        """Test regenerate new password for nagios user."""
        self.is_leader.return_value = True
        self.pwgen.return_value = "1234"
        actions.generate_nagios_password([])
        self.leader_set.assert_called_once_with(
            {"mysql-nagios.passwd": "1234"})
        mock_set_nagios_user.assert_called_once_with()
        self.action_set.assert_called_once_with(
            {"output": "New password for nagios created successfully."}
        )

    def test_generate_nagios_password_no_leader(self):
        """Test regenerate new password for nagios user at no leader unit."""
        self.is_leader.return_value = False
        actions.generate_nagios_password([])
        self.action_fail.assert_called_once_with(
            "This action should only take place on the leader unit."
        )
