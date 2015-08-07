# filter_plugins/passwdhash.py
#
# Generate password hashes that can be used in /etc/shadow.
#
# Example usage:
#
# Assume you have the following variable defined in Yaml:
#
# users:
#   - name: alice
#     password: secret
#   - name: bob
#     password: letmein
#
# You can use this filter in your playbook like this:
#
# - name: Create system users
#   user: name={{ item.name }} password={{ item.password|sha512crypt }}
#   with_items: users
#
# Three algorithms are supported: MD5, SHA-256 and SHA-512. To check which one
# your system uses, execute
#
#   authconfig --test | grep hashing
#
# WARNING: this should be considered UNSAFE for use in production systems. Use
# at your own risk!

import crypt
import string
import random

# Helper functions


def salt(length):
    chars = string.letters + string.digits + './'
    return ''.join(random.choice(chars) for _ in range(length))


def encrypt(clearpassword, algo, salt_length):
    return crypt.crypt(clearpassword, algo + salt(salt_length) + '$')


# Hash functions


def md5crypt(clearpassword):
    return encrypt(clearpassword, '$1$', 8)


def sha256crypt(clearpassword):
    return encrypt(clearpassword, '$5$', 16)


def sha512crypt(clearpassword):
    return encrypt(clearpassword, '$6$', 16)


class FilterModule(object):
    ''' Ansible core jinja2 filters '''

    def filters(self):
        return {
            'md5crypt': md5crypt,
            'sha256crypt': sha256crypt,
            'sha512crypt': sha512crypt,
        }
