#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Route """

import json
import uuid
import base64
import textwrap
import datetime

import flask  # pylint: disable=E0611,E0401
import signxml  # pylint: disable=E0611,E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import auth_core  # pylint: disable=E0401


class Route:  # pylint: disable=E1101,R0903
    """
        Route Resource

        self is pointing to current Module instance

        By default routes are prefixed with module name
        Example:
        - pylon is at "https://example.com/"
        - module name is "demo"
        - route is "/"
        Route URL: https://example.com/demo/

        web.route decorator takes the same arguments as Flask route
        Note: web.route decorator must be the last decorator (at top)
    """

    @web.route("/logout")
    def logout(self):
        """ Logout """
        target_token = flask.request.args.get("target_to", "")
        #
        logout_mode = self.descriptor.config.get("logout_mode", "post")
        #
        if logout_mode == "local":
            return auth_core.logout_success_redirect(target_token)
        #
        auth_ctx = auth_core.get_auth_context()
        #
        logout_request = {
            "tag": "samlp:LogoutRequest",
            "attr": {
                "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                "ID": f"EliteA_SAML_{uuid.uuid4()}",
                "Version": "2.0",
                "IssueInstant": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                #
                "Destination": self.descriptor.config["logout_destination"],
            },
            "children": [
                {
                    "tag": "saml:Issuer",
                    "text": self.descriptor.config["saml_issuer"],
                },
                {
                    "tag": "saml:NameID",
                    "attr": {
                        "Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                    },
                    "text": auth_ctx["provider_attr"].get("nameid", ""),
                },
            ],
        }
        #
        if self.descriptor.config.get("logout_sign", True):
            logout_request["children"].insert(1, {
                "tag": "ds:Signature",
                "attr": {
                    "xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
                    "Id": "placeholder",
                },
            })
            #
            raw_cert = self.descriptor.config["sp_cert"]
            raw_key = self.descriptor.config["sp_key"]
            #
            sign_cert = \
                "-----BEGIN CERTIFICATE-----" + "\n" + \
                raw_cert + \
                "-----END CERTIFICATE-----"
            # cert = \
            #     "-----BEGIN CERTIFICATE-----" + "\n" + \
            #     textwrap.fill(raw_cert, 64) + \
            #     "\n" + "-----END CERTIFICATE-----"
            key = \
                "-----BEGIN RSA PRIVATE KEY-----" + "\n" + \
                textwrap.fill(raw_key, 64) + \
                "\n" + "-----END RSA PRIVATE KEY-----"
            #
            tree = self.json_to_xml_tree(logout_request)
            # log.debug("[Create]: %s", self.xml_tree_to_string(tree))
            #
            signed_tree = signxml.XMLSigner().sign(tree, key=key, cert=sign_cert)
            signed = self.xml_tree_to_bytes(signed_tree, backend="lxml")
            signed_base64_str = base64.b64encode(signed).decode()
            # log.debug("[Sign]: %s", self.xml_tree_to_string(signed_tree, backend="lxml"))
            #
            saml_request = signed_base64_str
        else:
            tree = self.json_to_xml_tree(logout_request)
            unsigned = self.xml_tree_to_bytes(tree)
            saml_request = base64.b64encode(unsigned).decode()
        #
        return self.descriptor.render_template(
            "redirect.html",
            action=self.descriptor.config["logout_destination"],
            parameters=[
                {
                    "name": "SAMLRequest",
                    "value": saml_request,
                },
                {
                    "name": "RelayState",
                    "value": target_token,
                },
            ],
        )

    @web.route("/sls", methods=["GET", "POST"])
    def sls(self):  # pylint: disable=R0912,R0914,R0915
        """ SLS """
        if flask.request.method == "GET":
            log.debug("GET response: %s", flask.request.args)
            #
            target_token = flask.request.args.get("RelayState", "")
            saml_response = flask.request.args["SAMLResponse"]
        else:
            log.debug("POST response: %s", flask.request.form)
            #
            target_token = flask.request.form.get("RelayState", "")
            saml_response = flask.request.form["SAMLResponse"]
        #
        saml_response_data = base64.b64decode(saml_response)
        #
        if self.descriptor.config.get("logout_verify", True):
            raw_cert = self.descriptor.config["idp_cert"]
            #
            cert = \
                "-----BEGIN CERTIFICATE-----" + "\n" + \
                textwrap.fill(raw_cert, 64) + \
                "\n" + "-----END CERTIFICATE-----"
            #
            verify_result = signxml.XMLVerifier().verify(saml_response_data, x509_cert=cert)
            decoded = self.xml_tree_to_json(verify_result.signed_xml)
            # log.debug("[Verify]: %s", decoded)
        else:
            unsigned_xml = self.data_to_xml_tree(saml_response_data, backend="lxml")
            decoded = self.xml_tree_to_json(unsigned_xml)
        #
        log.debug("SAML response: %s", json.dumps(decoded))
        #
        return auth_core.logout_success_redirect(target_token)
