import copy
import os
import pathlib
from urllib.parse import urljoin

from .plugin import CredentialPlugin

import requests
from django.utils.translation import ugettext_lazy as _

# AWX
from awx.main.utils import (
    create_temporary_fifo,
)

base_inputs = {
    'fields': [{
        'id': 'url',
        'label': _('Server URL'),
        'type': 'string',
        'format': 'url',
        'help_text': _('The URL to the HashiCorp Vault'),
    }, {
        'id': 'token',
        'label': _('Token'),
        'type': 'string',
        'secret': True,
        'help_text': _('The access token used to authenticate to the Vault server'),
    }, {
        'id': 'cacert',
        'label': _('CA Certificate'),
        'type': 'string',
        'multiline': True,
        'help_text': _('The CA certificate used to verify the SSL certificate of the Vault server')
    }],
    'metadata': [{
        'id': 'secret_path',
        'label': _('Path to Secret'),
        'type': 'string',
        'help_text': _('The path to the secret stored in the secret backend e.g, /some/secret/')
    }],
    'required': ['url', 'token', 'secret_path'],
}

hashi_ssh_inputs = copy.deepcopy(base_inputs)
hashi_ssh_inputs['metadata'] = [{
    'id': 'public_key',
    'label': _('Unsigned Public Key'),
    'type': 'string',
    'multiline': True,
}] + hashi_ssh_inputs['metadata'] + [{
    'id': 'role',
    'label': _('Role Name'),
    'type': 'string',
    'help_text': _('The name of the role used to sign.')
}, {
    'id': 'valid_principals',
    'label': _('Valid Principals'),
    'type': 'string',
    'help_text': _('Valid principals (either usernames or hostnames) that the certificate should be signed for.'),
}]
hashi_ssh_inputs['required'].extend(['role'])




def ssh_backend(**kwargs):
    token = kwargs['token']
    url = urljoin(kwargs['url'], 'v1')
    secret_path = kwargs['secret_path']
    role = kwargs['role']
    cacert = kwargs.get('cacert', None)

    request_kwargs = {'timeout': 30}
    if cacert:
        request_kwargs['verify'] = create_temporary_fifo(cacert.encode())

    request_kwargs['json'] = {'public_key': kwargs['public_key']}
    if kwargs.get('valid_principals'):
        request_kwargs['json']['valid_principals'] = kwargs['valid_principals']

    sess = requests.Session()
    sess.headers['Authorization'] = 'Bearer {}'.format(token)
    # Compatability header for older installs of Hashicorp Vault
    sess.headers['X-Vault-Token'] = token
    # https://www.vaultproject.io/api/secret/ssh/index.html#sign-ssh-key
    request_url = '/'.join([url, secret_path, 'issue', role]).rstrip('/')
    resp = sess.post(request_url, **request_kwargs)

    resp.raise_for_status()
    return resp.json()['data']['private_key']

hashivault_custom_ssh_plugin = CredentialPlugin(
    'HashiCorp Vault SSH Custom',
    inputs=hashi_ssh_inputs,
    backend=ssh_backend
)