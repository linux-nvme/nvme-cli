#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
#
# Authors: Martin Belanger <martin.belanger@dell.com>
#
# Test KMS for the nvme-keysd wringer, built on PyKMIP. "serve" runs a
# PyKMIP server. The other commands manage the keys on it, as a KMIP
# client with the certificates in DIR: ca.pem, client.pem, client.key.

import argparse
import logging
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from kmip.core import enums
from kmip.pie import objects
from kmip.pie.client import ProxyKmipClient


def serve(args):
    from kmip.services.server import server

    sys.argv = [sys.argv[0], '-f', args.config, '-l', args.log]
    server.main()


def client(args):
    return ProxyKmipClient(
        hostname='127.0.0.1', port=args.port,
        cert=f'{args.dir}/client.pem', key=f'{args.dir}/client.key',
        ca=f'{args.dir}/ca.pem',
        kmip_version=enums.KMIPVersion.KMIP_1_4)


def register(args, obj):
    with client(args) as c:
        uid = c.register(obj)
        if args.activate:
            c.activate(uid)
    print(uid)


def register_secret(args):
    register(args, objects.SecretData(
        args.value.encode(), enums.SecretDataType.PASSWORD,
        name=args.name))


def register_symmetric(args):
    key = bytes.fromhex(args.hex)
    register(args, objects.SymmetricKey(
        enums.CryptographicAlgorithm.AES, len(key) * 8, key,
        name=args.name))


def register_certificate(args):
    with open(args.pem, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    register(args, objects.X509Certificate(
        cert.public_bytes(serialization.Encoding.DER), name=args.name))


def activate(args):
    with client(args) as c:
        c.activate(args.uid)


def revoke(args):
    with client(args) as c:
        c.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION,
                 args.uid)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dir', help='directory of the client certificates')
    p.add_argument('--port', type=int, default=5696)
    sub = p.add_subparsers(required=True)

    s = sub.add_parser('serve', help='run a PyKMIP server')
    s.add_argument('config', help='PyKMIP server configuration file')
    s.add_argument('log', help='PyKMIP server log file')
    s.set_defaults(func=serve)

    for name, func, value in (
            ('register-secret', register_secret, 'value'),
            ('register-symmetric', register_symmetric, 'hex'),
            ('register-certificate', register_certificate, 'pem')):
        s = sub.add_parser(name, help='register a key, print its ID')
        s.add_argument('--activate', action='store_true')
        s.add_argument('name', help='KMIP Name of the key')
        s.add_argument(value)
        s.set_defaults(func=func)

    for name, func in (('activate', activate), ('revoke', revoke)):
        s = sub.add_parser(name)
        s.add_argument('uid', help='Unique Identifier of the key')
        s.set_defaults(func=func)

    args = p.parse_args()
    # PyKMIP warns about its missing default configuration files.
    logging.getLogger('kmip').setLevel(logging.ERROR)
    args.func(args)


if __name__ == '__main__':
    main()
