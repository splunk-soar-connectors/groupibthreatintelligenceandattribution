# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/python
"""Group-IB Threat Intelligence Connector for Splunk SOAR."""

import json
from datetime import datetime, timedelta

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from cyberintegrations import TIPoller
from dateparser import parse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from groupibthreatintelligenceandattribution_actions import handle_ip_scoring, handle_whois_domain, handle_whois_ip
from groupibthreatintelligenceandattribution_consts import *
from groupibthreatintelligenceandattribution_parser import parse_artifacts
from groupibthreatintelligenceandattribution_utils import config_to_int_flag


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class GroupIbThreatIntelligenceAndAttributionConnector(BaseConnector):
    def __init__(self):
        super().__init__()
        self._state = None
        self._base_url = None
        self._gib_tia_connector = TIPoller("", "", "")
        self._collections = {}

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"
        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Unable to parse JSON response. Error: {e}"), None)

        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {} Data from server: {}".format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if not r.text:
            return self._process_empty_response(r, action_result)

        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        config = self.get_config()
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"), resp_json)

        url = self._base_url + endpoint

        try:
            r = request_func(url, verify=config.get("verify_server_cert", False), **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Error Connecting to server. Details: {e}"), resp_json)

        return self._process_response(r, action_result)

    def _setup_generator(
        self, collection_name, date_start, date_end=None, last_fetch=None, probable_corporate_access=None, unique=None, combolist=None
    ):
        """Set up the data generator for a collection."""
        collection_info = INCIDENT_COLLECTIONS_INFO.get(collection_name, {})
        keys = {**BASE_MAPPING_CONTAINER, **collection_info.get("container", {})}
        self._gib_tia_connector.set_keys(collection_name, keys)

        # Determine seq_update from last_fetch or date_start
        if last_fetch:
            if isinstance(last_fetch, dict):
                seq_update = last_fetch.get(collection_name, 0)
            elif isinstance(last_fetch, int | float | str):
                try:
                    seq_update = int(last_fetch) if last_fetch else 0
                except (ValueError, TypeError):
                    seq_update = 0
            else:
                seq_update = 0
                self.debug_print(f"Warning: Unexpected last_fetch type for {collection_name}")
        elif date_start:
            seq_update_dict = self._gib_tia_connector.get_seq_update_dict(date_start, collection_name)
            if isinstance(seq_update_dict, dict):
                seq_update = seq_update_dict.get(collection_name, 0)
            elif isinstance(seq_update_dict, int | float | str):
                try:
                    seq_update = int(seq_update_dict) if seq_update_dict else 0
                except (ValueError, TypeError):
                    seq_update = 0
            else:
                seq_update = 0
        else:
            seq_update = 0

        if collection_name == "compromised/breached":
            if not last_fetch:
                last_fetch = date_start
            generator = self._gib_tia_connector.create_search_generator(collection_name=collection_name, date_from=last_fetch, date_to=date_end)
        else:
            generator_kwargs = {"collection_name": collection_name, "sequpdate": seq_update}

            # Add filters for compromised/account_group (only when enabled)
            if collection_name == "compromised/account_group":
                if probable_corporate_access == 1:
                    generator_kwargs["probable_corporate_access"] = probable_corporate_access
                if unique == 1:
                    generator_kwargs["unique"] = unique
                if combolist == 1:
                    generator_kwargs["combolist"] = combolist

            generator = self._gib_tia_connector.create_update_generator(**generator_kwargs)

        return generator, collection_info

    def _transform_severity(self, feed):
        """Transform Group-IB severity to SOAR severity."""
        severity_map = {"green": "low", "orange": "medium", "red": "high"}
        return severity_map.get(feed["severity"])

    def _parse_artifacts(self, chunk, collection_info, collection_name, filters=None):
        """Delegate to the parser module."""
        return parse_artifacts(chunk, collection_info, collection_name, debug_print=self.debug_print, filters=filters)

    def _log_filter_status(self, filter_name, filter_value):
        """Log filter status for debugging."""
        status = "enabled" if filter_value == 1 else "disabled"
        msg = f"{filter_name} filter for compromised/account_group is {status}"
        self.debug_print(msg)
        self.save_progress(msg)

    def _build_filters_dict(self, probable_corporate_access, unique, combolist):
        """Build filters dictionary for parser."""
        if probable_corporate_access is None and unique is None and combolist is None:
            return None
        return {
            "combolist": combolist == 1 if combolist is not None else False,
            "unique": unique == 1 if unique is not None else False,
            "probable_corporate_access": probable_corporate_access == 1 if probable_corporate_access is not None else False,
        }

    def _get_error_message_from_exception(self, e):
        """Extract error message from exception."""
        error_code = ERROR_CODE_MESSAGE
        error_message = ERROR_MESSAGE_UNAVAILABLE
        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception:  # nosec B110
            pass
        return f"Error Code: {error_code}. Error Message: {error_message}"

    def _handle_test_connectivity(self, param):
        """Test connectivity to Group-IB API."""
        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.set_status(phantom.APP_SUCCESS)
        self.save_progress("Connecting to endpoint")

        try:
            self._gib_tia_connector.get_available_collections()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            action_result.set_status(phantom.APP_ERROR, error_message)

        if phantom.is_fail(action_result.get_status()):
            self.save_progress("Test Connectivity Failed.")
            self.debug_print("Test Connectivity Failed: ", action_result.get_status())
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _on_poll(self, param):
        """Poll Group-IB API for threat intelligence data."""
        is_manual_poll = self.is_poll_now()
        action_result = self.add_action_result(ActionResult(dict(param)))
        action_result.set_status(phantom.APP_SUCCESS)
        container_count = 0
        artifacts_count = 0
        limit_reached = False
        config = self.get_config()

        self.debug_print("Starting polling")
        self.debug_print(self._collections.items())

        for collection_name, date_start in self._collections.items():
            self.debug_print(f"Starting polling for {collection_name}")
            self.save_progress(f"Starting polling for {collection_name}")

            # Get filter settings for compromised/account_group
            probable_corporate_access = None
            unique = None
            combolist = None

            if collection_name == "compromised/account_group":
                unique = config_to_int_flag(config.get("compromised_account_group_unique", False))
                combolist = config_to_int_flag(config.get("compromised_account_group_combolist", False))
                probable_corporate_access = config_to_int_flag(config.get("compromised_account_group_probable_corporate_access", False))
                self._log_filter_status("Probable corporate access", probable_corporate_access)
                self._log_filter_status("Unique", unique)
                self._log_filter_status("Combolist", combolist)

            last_fetch = self._state.get(collection_name)

            try:
                if is_manual_poll:
                    start_time = parse(str(param.get("start_time"))).strftime(GIB_DATE_FORMAT) if param.get("start_time") else date_start
                    end_time = parse(str(param.get("end_time"))).strftime(GIB_DATE_FORMAT) if param.get("end_time") else None
                    generator, collection_info = self._setup_generator(
                        collection_name,
                        start_time,
                        end_time,
                        probable_corporate_access=probable_corporate_access,
                        unique=unique,
                        combolist=combolist,
                    )
                else:
                    generator, collection_info = self._setup_generator(
                        collection_name=collection_name,
                        date_start=date_start,
                        date_end=None,
                        last_fetch=last_fetch,
                        probable_corporate_access=probable_corporate_access,
                        unique=unique,
                        combolist=combolist,
                    )

                for chunk in generator:
                    portion = chunk.parse_portion()
                    filters = self._build_filters_dict(probable_corporate_access, unique, combolist)
                    artifacts_list = self._parse_artifacts(chunk, collection_info, collection_name, filters=filters)

                    for i, feed in enumerate(portion):
                        feed["name"] = f"{collection_info.get('prefix', '')}: {feed.get('name')}"
                        severity = self._transform_severity(feed)

                        # Set high severity for hash-only IOC containers
                        current_artifacts = artifacts_list[i] if i < len(artifacts_list) and artifacts_list[i] else []
                        if collection_name == "ioc/common" and current_artifacts:
                            if all(a.get("name", "").startswith("Hash (") for a in current_artifacts):
                                severity = "high"

                        feed["severity"] = severity
                        last_fetch = feed.pop("last_fetch")

                        if feed.get("start_time"):
                            feed["start_time"] = parse(feed.get("start_time")).strftime(SPLUNK_DATE_FORMAT)
                        if feed.get("end_time"):
                            feed["end_time"] = parse(feed.get("end_time")).strftime(SPLUNK_DATE_FORMAT)

                        container = {**feed, **BASE_CONTAINER}
                        ret_val, message, container_id = self.save_container(container)

                        # Select appropriate artifact base
                        if collection_name in INDICATOR_COLLECTIONS:
                            base_artifact = BASE_ARTIFACT_INDICATOR
                        elif collection_name in INFO_COLLECTIONS:
                            base_artifact = BASE_ARTIFACT_INFO
                        else:
                            base_artifact = BASE_ARTIFACT

                        if message == "Duplicate container found":
                            duplication_container_info = self.get_container_info(container_id)
                            status = duplication_container_info[1].get("status")
                            if status in ["resolved", "closed"]:
                                self.debug_print(f"Skipping artifacts for {status} container")
                                continue
                            base_artifact["label"] = "gib update indicator"
                            self.debug_print(f"Container {container.get('source_data_identifier')} exists, updating")
                        elif phantom.is_fail(ret_val):
                            # Check if this is a session timeout error - log and continue rather than abort
                            if "session token" in message.lower() or "authentication failed" in message.lower():
                                self.debug_print(f"Session error for container {container.get('source_data_identifier')}: {message}")
                                self.save_progress(f"Warning: Session error encountered, skipping container. Consider reducing poll scope.")
                                continue
                            action_result.set_status(phantom.APP_ERROR, f"Error ingesting feed: {message}")
                            return action_result.get_status()
                        else:
                            if is_manual_poll:
                                container_count += 1
                                if container_count >= param.get("container_count", BASE_MAX_CONTAINERS_COUNT):
                                    limit_reached = True

                        self.debug_print(f"Container saved: {container_id}")

                        if not is_manual_poll:
                            self._state[collection_name] = last_fetch

                        # Process artifacts
                        artifacts = []
                        for artifact in current_artifacts:
                            if artifact.get("start_time"):
                                artifact["start_time"] = parse(artifact.get("start_time")).strftime(SPLUNK_DATE_FORMAT)
                            if artifact.get("end_time"):
                                artifact["end_time"] = parse(artifact.get("end_time")).strftime(SPLUNK_DATE_FORMAT)

                            artifact_severity = artifact.get("severity") or severity
                            artifacts.append({**artifact, **base_artifact, "container_id": container_id, "severity": artifact_severity})

                            if is_manual_poll:
                                artifacts_count += 1
                                if artifacts_count >= param.get("artifact_count", BASE_MAX_ARTIFACTS_COUNT):
                                    limit_reached = True
                                    break

                        if artifacts:
                            ret_val, message, _ = self.save_artifacts(artifacts)
                            self.debug_print(f"Artifacts saved for container {container_id}: {message}")

                        if limit_reached:
                            break

                    if limit_reached:
                        break

                self.save_progress(f"Polling for {collection_name} finished")
                if limit_reached:
                    break

            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, error_message)
        else:
            self.save_progress("No collections configured for polling")
            return action_result.set_status(phantom.APP_SUCCESS)

        self.save_progress("Polling complete")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_whois_ip(self, param):
        return handle_whois_ip(param, self)

    def _handle_whois_domain(self, param):
        return handle_whois_domain(param, self)

    def _handle_ip_scoring(self, param):
        return handle_ip_scoring(param, self)

    def handle_action(self, param):
        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        action_handlers = {
            "test_connectivity": self._handle_test_connectivity,
            "on_poll": self._on_poll,
            "whois_ip": self._handle_whois_ip,
            "whois_domain": self._handle_whois_domain,
            "ip_scoring": self._handle_ip_scoring,
        }

        handler = action_handlers.get(action_id)
        if handler:
            return handler(param)
        return phantom.APP_SUCCESS

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()

        self._gib_tia_connector = TIPoller(username=config.get("username"), api_key=config.get("api_key"), api_url=config.get("base_url"))
        self._gib_tia_connector.set_verify(verify=not config.get("insecure", False))

        # Load enabled collections with their start dates
        for collection in INCIDENT_COLLECTIONS_INFO.keys():
            modified_collection = collection.replace("/", "_")
            if config.get(modified_collection):
                start_date_key = modified_collection + "_start"
                start_date_value = config.get(start_date_key)

                if not start_date_value:
                    # Default to 3 days ago
                    default_start = datetime.now() - timedelta(days=3)
                    parsed_date = default_start.strftime(GIB_DATE_FORMAT)
                    self._collections[collection] = parsed_date
                    self.debug_print(f"No start date for {collection}, using 3 days ago")
                    continue

                try:
                    parsed_date = parse(start_date_value).strftime(GIB_DATE_FORMAT)
                    self._collections[collection] = parsed_date
                except Exception as e:
                    message = "Invalid date format. Use: 2020-01-01, January 1 2020, or 3 days"
                    error_message = self._get_error_message_from_exception(e)
                    self.set_status(phantom.APP_ERROR, f"{message}. {error_message}")
                    return phantom.APP_ERROR

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def handle_exception(self, e):
        self._gib_tia_connector.close_session()
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()
    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None
    username = args.username
    password = args.password

    if username is not None and password is None:
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = GroupIbThreatIntelligenceAndAttributionConnector._get_phantom_base_url() + "/login"
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False, timeout=30)  # nosec B501
            csrftoken = r.cookies["csrftoken"]

            data = {"username": username, "password": password, "csrfmiddlewaretoken": csrftoken}
            headers = {"Cookie": "csrftoken=" + csrftoken, "Referer": login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers, timeout=30)  # nosec B501
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = GroupIbThreatIntelligenceAndAttributionConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
