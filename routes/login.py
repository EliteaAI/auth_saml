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

    @web.route("/login")
    def login(self):
        """ Login """
        target_token = flask.request.args.get("target_to", "")
        #
        authn_request = {
            "tag": "samlp:AuthnRequest",
            "attr": {
                "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                "ID": f"Centry_SAML_{uuid.uuid4()}",
                "Version": "2.0",
                "IssueInstant": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                #
                "Destination": self.descriptor.config["authn_destination"],
                # "Consent": "urn:oasis:names:tc:SAML:2.0:consent:current-implicit",
                #
                # "ForceAuthn": "false",
                # "IsPassive": "false",
                # "AssertionConsumerServiceURL": "...",  # added below
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "children": [
                {
                    "tag": "saml:Issuer",
                    "text": self.descriptor.config["saml_issuer"],
                },
                {
                    "tag": "samlp:NameIDPolicy",
                    "attr": {
                        "Format": self.descriptor.config.get(
                            "authn_nameid_format",
                            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                        ),
                        "AllowCreate": "true",
                    },
                },
            ],
        }
        #
        if self.descriptor.config.get("authn_acs_url_add", True):
            authn_request["attr"]["AssertionConsumerServiceURL"] = self.descriptor.config.get(
                "authn_acs_url",
                f'{flask.request.host_url.rstrip("/")}{flask.url_for("auth_saml.acs")}'
            )
        #
        if self.descriptor.config.get("authn_sign", True):
            authn_request["children"].insert(1, {
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
            tree = self.json_to_xml_tree(authn_request)
            # log.debug("[Create]: %s", self.xml_tree_to_string(tree))
            #
            signed_tree = signxml.XMLSigner().sign(tree, key=key, cert=sign_cert)
            # log.debug("[Sign]: %s", self.xml_tree_to_string(signed_tree, backend="lxml"))
            #
            signed = self.xml_tree_to_bytes(signed_tree, backend="lxml")
            signed_base64_str = base64.b64encode(signed).decode()
            #
            saml_request = signed_base64_str
        else:
            tree = self.json_to_xml_tree(authn_request)
            unsigned = self.xml_tree_to_bytes(tree)
            saml_request = base64.b64encode(unsigned).decode()
        #
        return self.descriptor.render_template(
            "redirect.html",
            action=self.descriptor.config["authn_destination"],
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

    @web.route("/acs", methods=["GET", "POST"])
    def acs(self):  # pylint: disable=R0912,R0914,R0915
        """ ACS """
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
        if self.descriptor.config.get("authn_verify", True):
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
        samlp_status_code = self.json_tree_find_element_by_tag(
            decoded, self.response_remap.get("StatusCode", "samlp:StatusCode")
        )
        if samlp_status_code is None:
            log.error("No status code in SAML response")
            return auth_core.access_denied_reply()
        #
        if samlp_status_code["attr"].get("Value", None) != \
                "urn:oasis:names:tc:SAML:2.0:status:Success":
            log.error("SAML auth is not successfull")
            return auth_core.access_denied_reply()
        #
        auth_ok = True
        #
        saml_nameid = self.json_tree_find_element_by_tag(
            decoded, self.response_remap.get("NameID", "saml:NameID")
        )
        if saml_nameid is None or saml_nameid["text"] is None:
            log.error("No NameID in SAML response")
            return auth_core.access_denied_reply()
        #
        auth_name = saml_nameid["text"]
        #
        auth_attributes = {}
        #
        saml_attributes = self.json_tree_find_elements_by_tag(
            decoded, self.response_remap.get("Attribute", "saml:Attribute")
        )
        for saml_attribute in saml_attributes:
            attribute_name = saml_attribute["attr"].get("Name", None)
            if attribute_name is None:
                continue
            #
            attribute_values = self.json_tree_find_elements_by_tag(
                saml_attribute, self.response_remap.get("AttributeValue", "saml:AttributeValue")
            )
            #
            for attribute_value_obj in attribute_values:
                attribute_value = None
                #
                attribute_type = attribute_value_obj["attr"].get("xsi:type", None)
                if attribute_type == "xs:string":
                    attribute_value = attribute_value_obj["text"]
                #
                if attribute_value is None and "text" in attribute_value_obj:
                    attribute_value = attribute_value_obj["text"]
                #
                if attribute_value is None:
                    continue
                #
                if attribute_name in self.attributes_map:
                    attribute_name = self.attributes_map[attribute_name]
                #
                if attribute_name not in auth_attributes:
                    auth_attributes[attribute_name] = attribute_value
                elif not isinstance(auth_attributes[attribute_name], list):
                    attribute_data = []
                    attribute_data.append(auth_attributes[attribute_name])
                    attribute_data.append(attribute_value)
                    auth_attributes[attribute_name] = attribute_data
                else:
                    auth_attributes[attribute_name].append(attribute_value)
        #
        if "email" not in auth_attributes and \
                self.descriptor.config.get("fallback_to_nameid_for_email", True):
            auth_attributes["email"] = auth_name
        #
        authn_statement = self.json_tree_find_element_by_tag(
            decoded, self.response_remap.get("AuthnStatement", "saml:AuthnStatement")
        )
        if authn_statement is None or "SessionIndex" not in authn_statement["attr"]:
            auth_sessionindex = ""
        else:
            auth_sessionindex = authn_statement["attr"]["SessionIndex"]
        #
        exp_override = self.descriptor.config.get("expiration_override", None)
        #
        if exp_override is not None:
            auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=int(exp_override))
        elif authn_statement is None or "SessionNotOnOrAfter" not in authn_statement["attr"]:
            auth_exp = datetime.datetime.now()+datetime.timedelta(seconds=86400)  # 24h
        else:
            auth_exp = datetime.datetime.strptime(
                authn_statement["attr"]["SessionNotOnOrAfter"], "%Y-%m-%dT%H:%M:%S.%fZ"
            )
        #
        try:
            auth_user_id = auth_core.get_user_from_provider(auth_name)["id"]
        except:  # pylint: disable=W0702
            auth_user_id = None
        #
        auth_ctx = auth_core.get_auth_context()
        auth_ctx["done"] = auth_ok
        auth_ctx["error"] = ""
        auth_ctx["expiration"] = auth_exp
        auth_ctx["provider"] = "saml"
        auth_ctx["provider_attr"]["nameid"] = auth_name
        auth_ctx["provider_attr"]["attributes"] = auth_attributes
        auth_ctx["provider_attr"]["sessionindex"] = auth_sessionindex
        auth_ctx["user_id"] = auth_user_id
        auth_core.set_auth_context(auth_ctx)
        #
        log.debug("Context: %s", auth_ctx)
        #
        return auth_core.access_success_redirect(target_token)
