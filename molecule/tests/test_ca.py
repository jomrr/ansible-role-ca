import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_verify(host):
    output = host.check_output('openssl verify /etc/ssl/home/certs/my-mobile.crt')
    assert 'OK' in output
