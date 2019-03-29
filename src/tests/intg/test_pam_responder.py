#
# Test for the PAM responder
#
# Copyright (c) 2018 Red Hat, Inc.
# Author: Sumit Bose <sbose@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Tests for the PAM responder
"""
import os
import stat
import signal
import errno
import subprocess
import time
import pytest

import config
import shutil
from util import unindent

import intg.ds_openldap

import pytest

from intg.util import unindent
from intg.files_ops import passwd_ops_setup

LDAP_BASE_DN = "dc=example,dc=com"


@pytest.fixture(scope="module")
def ad_inst(request):
    """Fake AD server instance fixture"""
    instance = intg.ds_openldap.FakeAD(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123"
    )

    try:
        instance.setup()
    except:
        instance.teardown()
        raise
    request.addfinalizer(instance.teardown)
    return instance


@pytest.fixture(scope="module")
def ldap_conn(request, ad_inst):
    """LDAP server connection fixture"""
    ldap_conn = ad_inst.bind()
    ldap_conn.ad_inst = ad_inst
    request.addfinalizer(ldap_conn.unbind_s)
    return ldap_conn


def format_basic_conf(ldap_conn):
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        domains = FakeAD
        services = pam, nss

        [nss]

        [pam]
        debug_level = 10

        [domain/FakeAD]
        debug_level = 10
        ldap_search_base = {ldap_conn.ad_inst.base_dn}
        ldap_referrals = false

        id_provider = ldap
        auth_provider = ldap
        chpass_provider = ldap
        access_provider = ldap

        ldap_uri = {ldap_conn.ad_inst.ldap_url}
        ldap_default_bind_dn = {ldap_conn.ad_inst.admin_dn}
        ldap_default_authtok_type = password
        ldap_default_authtok = {ldap_conn.ad_inst.admin_pw}

        ldap_schema = ad
        ldap_id_mapping = true
        ldap_idmap_default_domain_sid = S-1-5-21-1305200397-2901131868-73388776
        case_sensitive = False

        [prompting/password]
        password_prompt = My global prompt

        [prompting/password/pam_sss_alt_service]
        password_prompt = My alt service prompt
    """).format(**locals())


def format_pam_cert_auth_conf():
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        domains = auth_only
        services = pam

        [nss]

        [pam]
        pam_cert_auth = True
        debug_level = 10

        [domain/auth_only]
        id_provider = ldap
        auth_provider = ldap
        chpass_provider = ldap
        access_provider = ldap
    """).format(**locals())


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)

    def cleanup_conf_file():
        """Remove sssd.conf, if it exists"""
        if os.path.lexists(config.CONF_PATH):
            os.unlink(config.CONF_PATH)

    request.addfinalizer(cleanup_conf_file)


def create_sssd_process():
    """Start the SSSD process"""
    os.environ["SSS_FILES_PASSWD"] = os.environ["NSS_WRAPPER_PASSWD"]
    os.environ["SSS_FILES_GROUP"] = os.environ["NSS_WRAPPER_GROUP"]
    if subprocess.call(["sssd", "-D", "-f"]) != 0:
        raise Exception("sssd start failed")


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        with open(config.PIDFILE_PATH, "r") as pid_file:
            pid = int(pid_file.read())
        os.kill(pid, signal.SIGTERM)
        while True:
            try:
                os.kill(pid, signal.SIGCONT)
            except OSError as ex:
                break
            time.sleep(1)
    except OSError as ex:
        pass
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)

    # make sure that the indicator file is removed during shutdown
    try:
        assert not os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    except OSError as ex:
        if ex.errno != errno.ENOENT:
            raise ex


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    request.addfinalizer(cleanup_sssd_process)


@pytest.fixture
def simple_pam_cert_auth(request):
    """Setup SSSD with pam_cert_auth=True"""
    conf = format_pam_cert_auth_conf()
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_preauth_indicator(simple_pam_cert_auth):
    """Check if preauth indicator file is created"""
    statinfo = os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    assert stat.S_ISREG(statinfo.st_mode)


@pytest.fixture
def pam_prompting_config(request, ldap_conn):
    """Setup SSSD with PAM prompting config"""
    conf = format_basic_conf(ldap_conn)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_password_prompting_config_global(ldap_conn, pam_prompting_config,
                                          env_for_sssctl):
    """Check global change of the password prompt"""

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1_dom1-19661",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="111")
    except:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("My global prompt") != -1


def test_password_prompting_config_srv(ldap_conn, pam_prompting_config,
                                       env_for_sssctl):
    """Check change of the password prompt for dedicated service"""

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1_dom1-19661",
                               "--action=auth",
                               "--service=pam_sss_alt_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="111")
    except:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("My alt service prompt") != -1


@pytest.fixture
def env_for_sssctl(request):
    pwrap_runtimedir = os.getenv("PAM_WRAPPER_SERVICE_DIR")
    if pwrap_runtimedir is None:
        raise ValueError("The PAM_WRAPPER_SERVICE_DIR variable is unset\n")

    env_for_sssctl = os.environ.copy()
    env_for_sssctl['PAM_WRAPPER'] = "1"
    env_for_sssctl['SSSD_INTG_PEER_UID'] = "0"
    env_for_sssctl['SSSD_INTG_PEER_GID'] = "0"
    env_for_sssctl['LD_PRELOAD'] += ':' + os.environ['PAM_WRAPPER_PATH']

    return env_for_sssctl
