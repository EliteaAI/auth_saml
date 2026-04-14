#!/usr/bin/python3
# coding=utf-8
# pylint: disable=C0116,W0201

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

""" Method """

import importlib

from pylon.core.tools import web, log  # pylint: disable=E0401,E0611,W0611


class Method:  # pylint: disable=E1101,R0903
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.method()
    def json_tree_find_element_by_tag(self, obj, tag):
        """ Find element by tag """
        elements = []
        #
        if isinstance(obj, list):
            elements.extend(obj)
        else:
            elements.append(obj)
        #
        while elements:
            element = elements.pop(0)
            #
            if element["tag"] == tag:
                return element
            #
            elements.extend(element["children"])
        #
        return None

    @web.method()
    def json_tree_find_elements_by_tag(self, obj, tag):
        """ Find elements by tag """
        result = []
        #
        elements = []
        #
        if isinstance(obj, list):
            elements.extend(obj)
        else:
            elements.append(obj)
        #
        while elements:
            element = elements.pop(0)
            #
            if element["tag"] == tag:
                result.append(element)
            #
            elements.extend(element["children"])
        #
        return result

    @web.method()
    def xml_tree_to_string(self, obj, backend="python", backend_etree=None):
        """ Make string from XML tree """
        return self.xml_tree_to_bytes(obj, backend, backend_etree).decode()

    @web.method()
    def xml_tree_to_bytes(self, obj, backend="python", backend_etree=None):
        """ Make bytes from XML tree """
        if backend_etree is None:
            if backend == "lxml":
                backend_etree = importlib.import_module("lxml.etree")
            else:  # python
                backend_etree = importlib.import_module("xml.etree.ElementTree")
        #
        return backend_etree.tostring(obj)

    @web.method()
    def data_to_xml_tree(self, obj, backend="python", backend_etree=None):
        """ Make XML tree from data """
        if backend_etree is None:
            if backend == "lxml":
                backend_etree = importlib.import_module("lxml.etree")
            elif backend == "defusedxml":
                backend_etree = importlib.import_module("defusedxml.ElementTree")
            else:  # python
                backend_etree = importlib.import_module("xml.etree.ElementTree")
        #
        return backend_etree.fromstring(obj)

    @web.method()
    def json_to_xml_tree(self, obj, backend="python", backend_etree=None):
        """ Make XML tree from JSON struct """
        if backend_etree is None:
            if backend == "lxml":
                backend_etree = importlib.import_module("lxml.etree")
            else:  # python
                backend_etree = importlib.import_module("xml.etree.ElementTree")
        #
        element = backend_etree.Element(obj["tag"])
        #
        for key, value in obj.get("attr", {}).items():
            element.set(key, value)
        #
        element.text = obj.get("text", None)
        #
        for child in obj.get("children", []):
            element.append(self.json_to_xml_tree(child, backend, backend_etree))
        #
        return element

    @web.method()
    def xml_tree_to_json(self, obj, collapse_ns=True, ns_map=None, known_ns=None):  # pylint: disable=R0912,R0914
        """ Make JSON struct from XML tree """
        result = {}
        #
        result["tag"] = obj.tag
        result["attr"] = dict(obj.attrib)
        result["text"] = obj.text.strip() if obj.text is not None else None
        result["children"] = []
        #
        if collapse_ns:
            if ns_map is None and not hasattr(obj, "nsmap"):
                raise ValueError("collapse_ns set with ns_map not provided and lxml not used")
            #
            if ns_map is None:
                ns_map = {}
            if hasattr(obj, "nsmap"):
                ns_map.update(obj.nsmap)
            if known_ns is None:
                known_ns = set()
            #
            for ns_item in ns_map.items():
                ns_key, ns_value = ns_item
                #
                if ns_item not in known_ns:
                    xmlns_attr = f"xmlns:{ns_key}"
                    if xmlns_attr not in result["attr"]:
                        mod_attr = {}
                        mod_attr[xmlns_attr] = ns_value
                        mod_attr.update(result["attr"])
                        result["attr"] = mod_attr
                    known_ns.add(ns_item)
                #
                ns_tag = "{" + ns_value + "}"
                if result["tag"].startswith(ns_tag):
                    result["tag"] = result["tag"].replace(ns_tag, f"{ns_key}:")
                #
                mod_ns_attr = {}
                for attr_key in result["attr"]:
                    if attr_key.startswith(ns_tag):
                        mod_attr_key = attr_key.replace(ns_tag, f"{ns_key}:")
                        mod_ns_attr[mod_attr_key] = result["attr"][attr_key]
                    else:
                        mod_ns_attr[attr_key] = result["attr"][attr_key]
                result["attr"] = mod_ns_attr
        #
        for inner_obj in list(obj):
            result["children"].append(
                self.xml_tree_to_json(inner_obj, collapse_ns, ns_map, known_ns)
            )
        #
        return result
