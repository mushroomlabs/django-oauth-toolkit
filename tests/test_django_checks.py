from copy import deepcopy

import pytest
from django.core import checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings

from oauth2_provider.core.checks import (
    validate_backchannel_logout,
    validate_swapped_model_consistency,
    validate_token_configuration,
)

from .common_testing import OAuth2ProviderTestCase as TestCase
from .presets import OIDC_SETTINGS_BACKCHANNEL_LOGOUT


BAD_HANDLER_SETTINGS = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
BAD_HANDLER_SETTINGS["OIDC_BACKCHANNEL_LOGOUT_HANDLER"] = "sys.api_version"

MISSING_ISS_OIDC_ENDPOINT = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
MISSING_ISS_OIDC_ENDPOINT["OIDC_ISS_ENDPOINT"] = None

OIDC_DISABLED_SETTINGS = deepcopy(OIDC_SETTINGS_BACKCHANNEL_LOGOUT)
OIDC_DISABLED_SETTINGS["OIDC_ENABLED"] = False


class DjangoChecksTestCase(TestCase):
    def test_checks_pass(self):
        call_command("check")

    # CrossDatabaseRouter claims AccessToken is in beta while everything else is in alpha.
    # This will cause the database checks to fail.
    @override_settings(
        DATABASE_ROUTERS=["tests.db_router.CrossDatabaseRouter", "tests.db_router.AlphaRouter"]
    )
    def test_checks_fail_when_router_crosses_databases(self):
        message = "The token models are expected to be stored in the same database."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")

    def test_token_configuration_check_runs_without_a_database_alias(self):
        # Django 6.1 skips `database`-tagged checks unless an alias is passed explicitly
        # (`manage.py check --database default`). This check only asks the routers where the
        # token models would be written -- it never opens a connection -- so it must not carry
        # that tag, or a plain `manage.py check` would silently stop running it.
        self.assertNotIn(checks.Tags.database, validate_token_configuration.tags)
        self.assertIn(checks.Tags.models, validate_token_configuration.tags)

    @override_settings(OAUTH2_PROVIDER=OIDC_DISABLED_SETTINGS)
    def test_checks_fail_when_backchannel_is_enabled_and_oidc_is_disabled(self):
        message = "OIDC_ENABLED must be True to enable OIDC backchannel logout."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")

    @override_settings(OAUTH2_PROVIDER=BAD_HANDLER_SETTINGS)
    def test_checks_fail_when_backchannel_logout_handler_is_not_callable(self):
        message = "OIDC_BACKCHANNEL_LOGOUT_HANDLER must be a callable."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")

    @override_settings(OAUTH2_PROVIDER=MISSING_ISS_OIDC_ENDPOINT)
    def test_checks_fail_when_iss_oidc_endpoint_is_missing(self):
        message = "OIDC_ISS_ENDPOINT must be set to enable OIDC backchannel logout."
        with self.assertRaisesMessage(SystemCheckError, message):
            call_command("check")


@pytest.mark.usefixtures("oauth2_settings")
class BackchannelLogoutCheckTestCase(TestCase):
    def test_check_is_registered(self):
        # Guard against the @checks.register decorator being dropped: the direct-call
        # tests below would still pass, but Django would never run the check.
        from django.core.checks.registry import registry as checks_registry

        self.assertIn(
            validate_backchannel_logout,
            checks_registry.get_checks(include_deployment_checks=True),
        )

    def test_passes_when_backchannel_disabled(self):
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = False
        self.assertEqual(validate_backchannel_logout(None), [])

    def test_passes_when_backchannel_enabled_and_all_settings_valid(self):
        from oauth2_provider.handlers import send_backchannel_logout_request

        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_ENABLED = True
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER = send_backchannel_logout_request
        self.oauth2_settings.OIDC_ISS_ENDPOINT = "http://localhost/o"
        self.assertEqual(validate_backchannel_logout(None), [])

    def test_reports_all_three_errors_when_everything_is_wrong(self):
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED = True
        self.oauth2_settings.OIDC_ENABLED = False
        self.oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER = "not-a-callable"
        self.oauth2_settings.OIDC_ISS_ENDPOINT = None

        messages = validate_backchannel_logout(None)
        self.assertEqual(len(messages), 3)
        self.assertCountEqual(
            [m.msg for m in messages],
            [
                "OIDC_ENABLED must be True to enable OIDC backchannel logout.",
                "OIDC_BACKCHANNEL_LOGOUT_HANDLER must be a callable.",
                "OIDC_ISS_ENDPOINT must be set to enable OIDC backchannel logout.",
            ],
        )


@pytest.mark.usefixtures("oauth2_settings")
class SwappedModelConsistencyCheckTestCase(TestCase):
    def _ids(self):
        return {m.id for m in validate_swapped_model_consistency(None)}

    def test_check_is_registered(self):
        # Guard against the @checks.register decorator being dropped: the direct-call
        # tests below would still pass, but Django would never run the check.
        from django.core.checks.registry import registry as checks_registry

        self.assertIn(
            validate_swapped_model_consistency,
            checks_registry.get_checks(include_deployment_checks=True),
        )

    def test_default_models_pass(self):
        # Both models default to the oauth2_provider app.
        self.assertNotIn("oauth2_provider.W011", self._ids())

    def test_token_pair_swapped_together_pass(self):
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "myapp.AccessToken"
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "myapp.RefreshToken"
        self.assertNotIn("oauth2_provider.W011", self._ids())

    def test_only_access_token_swapped_warns(self):
        # Regression for #634: swapping AccessToken but leaving RefreshToken on the
        # default app creates a cross-app circular FK that cannot be migrated.
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "myapp.AccessToken"
        messages = validate_swapped_model_consistency(None)
        self.assertEqual([m.id for m in messages], ["oauth2_provider.W011"])
        self.assertIsInstance(messages[0], checks.Warning)

    def test_token_models_in_different_apps_warns(self):
        self.oauth2_settings.ACCESS_TOKEN_MODEL = "app_a.AccessToken"
        self.oauth2_settings.REFRESH_TOKEN_MODEL = "app_b.RefreshToken"
        self.assertIn("oauth2_provider.W011", self._ids())
