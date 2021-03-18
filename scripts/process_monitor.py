import argparse
import copy
import datetime
import json
import logging
import logging.handlers
import os
import sys

import requests

from time_sync import timesync


class logGenerator:
    def __init__(self, logIP, mode, hostname):

        self.logger = logging.getLogger(hostname)
        self.logger.setLevel(logging.INFO)

        if mode == "syslog":
            handler = logging.handlers.SysLogHandler(address=(logIP, 514), facility=19)

        elif mode == "stdout":
            handler = logging.StreamHandler(sys.stdout)

        formatter = logging.Formatter(
            "%(asctime)s %(name)s " + "state_monitor[%(process)d]: %(message)s"
        )

        handler.formatter = formatter

        self.logger.addHandler(handler)

    def log(self, dataset):

        for param, severity, change in dataset["changes"]:

            device_meta = {
                "service_mon": {
                    "service": dataset["service"],
                    "parameter": param,
                    "description": change,
                }
            }

            method_call = "self.logger.{}('device_meta=({})')".format(
                severity, json.dumps(device_meta)
            )
            eval(method_call)


class service_state:

    # perform comparison using the (-) method between two state objects. results dictionary
    # contains all the changes detected with the name of the services. passed into the self.log() method.
    def __sub__(self, previous):

        currentDef = self.__dict__
        previousDef = previous.__dict__

        results = {"service": self.name, "changes": []}

        for key, cur_value in currentDef.items():

            prev_value = previousDef[key]

            if "status_descr" in key:

                if prev_value != cur_value:

                    severity = "critical" if cur_value == "Not Running" else "info"
                    results["changes"].append(
                        (
                            "state",
                            severity,
                            "Service state changed from {} to {}".format(prev_value, cur_value),
                        )
                    )

            if "num_processes" in key:

                if prev_value != cur_value:

                    severity = "critical" if cur_value < 1 else "info"
                    results["changes"].append(
                        (
                            "num_processes",
                            severity,
                            "Number of processes changed from {} to {}".format(
                                prev_value, cur_value
                            ),
                        )
                    )

            if "pid" in key or "subs" in key:

                current_list = cur_value.split(", ") if cur_value != "" else []
                previous_list = prev_value.split(", ") if prev_value != "" else []

                # get the list items which are not in both current and previous using the ^ set special operator.
                list_outliars = list(set(current_list) ^ set(previous_list))

                for item in list_outliars:

                    if item not in current_list and item in previous_list:
                        results["changes"].append(
                            (key, "warning", "{} {} is missing".format(key, item))
                        )

                    if item in current_list and item not in previous_list:
                        results["changes"].append(
                            (key, "info", "New {} {} discovered".format(key, item))
                        )

            if "duration" in key:

                if cur_value and prev_value:

                    # drop micro seconds from the time_deltas
                    cur_value = cur_value - datetime.timedelta(microseconds=cur_value.microseconds)
                    prev_value = prev_value - datetime.timedelta(
                        microseconds=prev_value.microseconds
                    )

                    diff = prev_value - cur_value

                    if (cur_value < prev_value) and diff > datetime.timedelta(seconds=10):

                        results["changes"].append((key, "warning", "Service uptime has been reset"))

        return results

    def __iter__(self):
        return self

    def __next__(self):

        if self.itercount == len(self):
            self.itercount = 0
            raise StopIteration

        sub = service_state(**self.sub_services_list[self.itercount])
        self.itercount += 1

        return sub

    def __len__(self):
        return len(self.sub_services_list)

    def __str__(self):
        def sizeof_fmt(num, suffix="B"):
            for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
                if abs(num) < 1024.0:
                    return "%3.1f%s%s" % (num, unit, suffix)
                num /= 1024.0
            return "%.1f%s%s" % (num, "Yi", suffix)

        message = []

        message.append("{} ".format(self.name))

        if self.status == 1:
            message.append("Status: {}, ".format(self.status_descr))

        else:
            message.append("Status: {} ({}), ".format(self.status_descr, self.failed))

        message.append("CPU: {}%, ".format(round(self.cpu_pct * 100, 2)))
        message.append(
            "Memory: {}, {}%, ".format(
                sizeof_fmt(self.memory_bytes), (round(self.memory_pct * 100, 2))
            )
        )

        pids = []
        if self.pid:
            (*pids,) = self.pid.split(", ")[:2]
            if len(self.pid.split(", ")) > 2:
                pids.append("...")

        message.append("PIDs: {} ({}), ".format(", ".join(pids), self.num_processes))
        message.append("Subs: {}, ".format(len(self)))
        message.append("Duration: {}".format(self.duration))

        return "".join(message)

    def __init__(self, **kwargs):

        self.itercount = 0
        self.sub_services_list = []

        for serv, item in kwargs.items():
            self.name = serv

            for key, value in item.items():

                if "sub_services" in key:

                    # load in the sub process dict objects only if the object name
                    # is not the same as the service name
                    self.sub_services_list.extend(
                        [
                            list_item
                            for list_item in value
                            for sub, parts in list_item.items()
                            if sub != self.name
                        ]
                    )
                else:
                    # create object parameters based on the kwargs keys:
                    # - nane, status_descr, status, cpu_pct, memory_pct,
                    # - memory_bytes, pid, num_processes, state
                    setattr(self, key, value)

            # sub list name stirng
            self.subs = ", ".join(
                [sub for item in self.sub_services_list for sub, parts in item.items()]
            )


class state_mon(timesync, logGenerator):
    def summarize_state(
        self, state_db
    ):  # modify state_db dictionary reference with state information

        for service in state_db.keys():

            # list up all the status bools and if all is true and there's length, then the process is running
            state = [
                parts["status"]
                for sub in state_db[service]["sub_services"]
                for key, parts in sub.items()
            ]

            if all(state) and len(state) > 0:

                state_db[service]["status_descr"] = "Running"
                state_db[service]["status"] = 1
                state_db[service]["failed"] = 0

            elif len(state) > 0:

                state_db[service]["failed"] = len([fail for fail in state if fail == 0])

            # set the process summary for key that are just sum'd up
            for param in ["num_processes", "cpu_pct", "memory_pct", "memory_bytes"]:

                state_db[service][param] = round(
                    sum(
                        [
                            parts[param]
                            for sub in state_db[service]["sub_services"]
                            for key, parts in sub.items()
                        ]
                    ),
                    3,
                )

            # join all the pid strings together from each sub pid strings as a summary
            state_db[service]["pid"] = ", ".join(
                filter(
                    None,
                    [
                        parts["pid"]
                        for sub in state_db[service]["sub_services"]
                        for key, parts in sub.items()
                    ],
                )
            )

            # split up each of the strings, then join everything together by using a set to remove duplicates
            state, start_time, duration = [], [], []

            for sub in state_db[service]["sub_services"]:
                for _, parts in sub.items():

                    if parts["state"] is not None:
                        state.extend(filter(None, parts["state"].split(", ")))

                    if parts["start_time"] is not None:
                        start_time.extend(filter(None, parts["start_time"].split(", ")))

                    if parts["duration"] is not None:
                        duration.append(parts["duration"])

            state_db[service]["state"] = ", ".join(list(set(state)))
            state_db[service]["start_time"] = ", ".join(list(set(start_time)))

            if len(duration) > 0:
                state_db[service]["duration"] = max(duration)

        return state_db

    def get_state(self, service, *args):

        # offset used to get the last or second last based on recursion.
        bucket_offset = -1 + args[0] if args else -1

        # dictionary is copied from template. setup for failure until proven otherwise,
        service_state_db = {service: copy.deepcopy(self.state_def)}

        if service in self.services.keys():

            service_db = self.services[service]
            dt_last_poll = datetime.datetime.strptime(
                service_db["last_poll"], "%Y-%m-%dT%H:%M:%S.%f"
            )

            if len(service_db["bucket_list"]) >= abs(bucket_offset):

                # get the last bucket using the offset (either last or second last)
                last_time_bucket_id = service_db["bucket_list"][bucket_offset]

                # get last bucket dictionary by the object name matching the id from above list
                last_time_bucket = next(
                    (
                        item[last_time_bucket_id]
                        for item in service_db["buckets"]
                        if last_time_bucket_id in item.keys()
                    ),
                    None,
                )

                dt_last_bucket = datetime.datetime.strptime(
                    last_time_bucket_id, "%Y-%m-%dT%H:%M:%S"
                )
                dt_delta = dt_last_poll - dt_last_bucket

                # use either the service process list if processing the current active state
                # or use the in stored bucket process list state to produce a previous state
                proc_list = (
                    service_db["procs"]
                    if bucket_offset == -1
                    else last_time_bucket["proc_list_state"]
                )

                for sub_service in proc_list:

                    # copy of main service dictionary is setup for failure until proven otherwise,

                    sub_service_db = {sub_service: copy.deepcopy(service_state_db[service])}
                    sub_service_db[sub_service].pop("sub_services")  # no subs in the subway

                    # time from last poll and date of last bucket is not more than 5x query windows long - (60 seconds / window)
                    # only if processing the active state. Otherwise if processing previous state then enter in, regardless
                    # fixes when timesync makes adjustment on startup
                    if (
                        dt_delta.total_seconds() < (self.query_window * 5) and bucket_offset == -1
                    ) or bucket_offset < -1:

                        # checks to see if proc is even in the bucket first
                        if sub_service in last_time_bucket["proc_list"]:

                            # gets proc dictionary from last bucket catalog matching proc name (sub_service)
                            proc_db = next(
                                (
                                    item[sub_service]
                                    for item in last_time_bucket["proc_collection"]
                                    if sub_service in item.keys()
                                ),
                                None,
                            )

                            if proc_db["proc_count"] > 0:

                                sub_service_db[sub_service]["status_descr"] = "Running"
                                sub_service_db[sub_service]["status"] = 1
                                sub_service_db[sub_service]["failed"] = 0

                                sub_service_db[sub_service]["num_processes"] = proc_db["proc_count"]

                                sub_service_db[sub_service]["cpu_pct"] = sum(proc_db["cpu_pct"])
                                sub_service_db[sub_service]["memory_pct"] = sum(
                                    proc_db["memory_pct"]
                                )
                                sub_service_db[sub_service]["memory_bytes"] = sum(
                                    proc_db["memory_bytes"]
                                )

                                sub_service_db[sub_service]["pid"] = ", ".join(
                                    filter(None, proc_db["pid"])
                                )
                                sub_service_db[sub_service]["state"] = ", ".join(
                                    filter(None, list(set(proc_db["state"])))
                                )

                                sub_service_db[sub_service]["start_time"] = ", ".join(
                                    filter(None, list(set(proc_db["start_time"])))
                                )

                                # error handling if start_time is none
                                if sub_service_db[sub_service]["start_time"] is not None:

                                    start_time_delta = max(
                                        [
                                            datetime.datetime.strptime(
                                                start_time, "%Y-%m-%dT%H:%M:%S.%fZ"
                                            )
                                            for start_time in sub_service_db[sub_service][
                                                "start_time"
                                            ].split(", ")
                                        ]
                                    )

                                    # get time difference from either the time_delta sync or just the current time
                                    # then make the duration and store as object
                                    timeoffset = (
                                        datetime.datetime.utcnow() + self.time_delta
                                        if self.timesync_enable
                                        else datetime.datetime.utcnow()
                                    )
                                    sub_service_db[sub_service]["duration"] = (
                                        timeoffset - start_time_delta
                                    )

                        # update the bucket stored process state list in the bucket def if processing the active state
                        # and if the process is not already in the list. the building will help produce previous state
                        if (
                            bucket_offset == -1
                            and sub_service not in last_time_bucket["proc_list_state"]
                        ):
                            last_time_bucket["proc_list_state"].append(sub_service)

                    service_state_db[service]["sub_services"].append(sub_service_db)

        if not args:

            previous_state_db = self.get_state(service, bucket_offset)

            self.summarize_state(previous_state_db)
            self.summarize_state(service_state_db)

            return service_state_db, previous_state_db

        return service_state_db

    def generate_state(self):

        summary_state_db = {"_summary_": copy.deepcopy(self.state_def)}

        for service in self.services:

            # generate query and receive query relative time
            query, cur_time = self.create_query(service)
            # print (json.dumps(query))

            # fetch data from elasticsearch server
            doc_result = self.fetch_proc(query)
            # print (doc_result)

            # catalog results if the results are a proper response
            if isinstance(doc_result, dict):

                (*_,) = self.catalog_service(service, doc_result, cur_time)
                # *results contains newly discovered procs

            # generate a state dictionary definitions for last bucket and previous bucket
            current_def, previous_def = self.get_state(service)

            summary_state_db["_summary_"]["sub_services"].append(current_def)

            # create new state object as class attribute by service name
            setattr(self, service, service_state(**current_def))

            # compare previous state to new state if there's two buckets
            if len(self.services[service]["bucket_list"]) > 1:

                previous = service_state(**previous_def)

                diff = getattr(self, service) - previous

                diff["changes"].sort()
                self.services[service]["changes"].sort()

                # report comparison  if there's changes
                if diff["changes"] != self.services[service]["changes"]:

                    if len(diff["changes"]) > 0:
                        self.log(diff)

                    self.services[service]["changes"] = diff["changes"]

            # generator returns service class attribute (state object)
            yield getattr(self, service)

        # summarize object is made into class atrribute
        self.summarize_state(summary_state_db)
        self.summary = service_state(**summary_state_db)

    def catalog_service(self, *args):

        # setup the last poll stamp right away
        service = args[0]
        doc_result = args[1]
        self.services[service]["last_poll"] = args[2]

        proc_return = []

        # loop from oldest to newest time buckets in the result query
        for last_time_bucket in doc_result["aggregations"]["date_bucket"]["buckets"]:

            bucket_time = last_time_bucket["key"]

            # bucket definition object name off bucket time / time aggregation key
            bucket_collection = {
                bucket_time: {
                    "proc_count": 0,
                    "proc_collection": [],
                    "proc_list": [],  # used to check what processes are in the collection
                    "proc_list_state": [],  # this is used to produce a previous state w/ global proc list snapshot
                }
            }

            # discovery automatically processes from the terms aggregation
            for proc in last_time_bucket[service]["buckets"]:

                # process term name is used as the object name
                service_bucket = {
                    proc["key"]: {
                        "proc_count": 0,
                        "cpu_pct": [],
                        "memory_pct": [],
                        "memory_bytes": [],
                        "start_time": [],
                        "state": [],
                        "pid": [],
                    }
                }

                # append all pid document metrics together for a process term bucket
                for pid in proc["pid"]["buckets"]:

                    service_bucket[proc["key"]]["proc_count"] += 1
                    bucket_collection[bucket_time]["proc_count"] += 1

                    service_bucket[proc["key"]]["cpu_pct"].append(round(pid["cpu_pct"]["value"], 3))
                    service_bucket[proc["key"]]["memory_pct"].append(
                        round(pid["memory_pct"]["value"], 3)
                    )
                    service_bucket[proc["key"]]["memory_bytes"].append(pid["memory_bytes"]["value"])

                    for hits in pid["state"]["hits"]["hits"]:

                        if "system.process.state" in hits["fields"].keys():
                            service_bucket[proc["key"]]["state"].extend(
                                hits["fields"]["system.process.state"]
                            )

                        if "system.process.cpu.start_time" in hits["fields"].keys():

                            # service pack 12 uses the date field format (epoch)
                            # convert to dt object in the utc time, then save in string format time
                            if any(
                                isinstance(start_time, int)
                                for start_time in hits["fields"]["system.process.cpu.start_time"]
                            ):

                                for epoch in hits["fields"]["system.process.cpu.start_time"]:

                                    try:

                                        dt_epoch = datetime.datetime.fromtimestamp(
                                            epoch / 1000.0, tz=datetime.timezone.utc
                                        )

                                        service_bucket[proc["key"]]["start_time"].append(
                                            dt_epoch.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                                        )

                                    except Exception:
                                        continue

                            # pre 10.3 service pack 12 used a keyword field format
                            else:

                                service_bucket[proc["key"]]["start_time"].extend(
                                    hits["fields"]["system.process.cpu.start_time"]
                                )

                    service_bucket[proc["key"]]["pid"].append(str(pid["key"]))

                # add the process bucket to the process list in the time bucket catalog
                bucket_collection[bucket_time]["proc_collection"].append(service_bucket)
                bucket_collection[bucket_time]["proc_list"].append(proc["key"])

            # find if the process is newly discovered. add it to the main process list and return list
            for _proc in bucket_collection[bucket_time]["proc_list"]:
                if _proc not in self.services[service]["procs"]:

                    self.services[service]["procs"].append(_proc)
                    proc_return.append(_proc)

            # enter if bucket list isn't fresh from startup
            if len(self.services[service]["bucket_list"]) > 0:

                bucket_store_dt = datetime.datetime.strptime(
                    self.services[service]["bucket_list"][-1], "%Y-%m-%dT%H:%M:%S"
                )
                bucket_dt = datetime.datetime.strptime(bucket_time, "%Y-%m-%dT%H:%M:%S")

                _delta = bucket_dt - bucket_store_dt

                # if the stored bucket is older than the query window, then add it to the list as a new bucket
                # else modify existing bucket with only updated proc information
                if _delta.total_seconds() > self.query_window:

                    self.services[service]["bucket_list"].append(bucket_time)
                    self.services[service]["buckets"].append(bucket_collection)

                else:

                    # copy last bucket dictionary into a reference
                    stored_bucket = next(iter(self.services[service]["buckets"][-1].values()))

                    # iterate through each proc in current running bucket. update proc in stored bucket with new dictionary information
                    # otherwise, add new proc to bucket proc collection
                    for proc in bucket_collection[bucket_time]["proc_collection"]:
                        for _key, _values in proc.items():

                            if _key in stored_bucket["proc_list"]:

                                stored_proc = next(
                                    (
                                        proc
                                        for proc in stored_bucket["proc_collection"]
                                        if _key in proc.keys()
                                    ),
                                    None,
                                )

                                stored_proc[_key].update(_values)

                            else:

                                stored_bucket["proc_collection"].append(proc)
                                stored_bucket["proc_list"].append(_key)
                                stored_bucket["proc_count"] += _values["proc_count"]

            else:

                # add the new time bucket to the catalog and memory list
                self.services[service]["bucket_list"].append(bucket_time)
                self.services[service]["buckets"].append(bucket_collection)

            # discharge oldest time bucket if there's already 4 time buckets in the catalog
            if len(self.services[service]["bucket_list"]) > 4:
                self.services[service]["bucket_list"].pop(0)
                self.services[service]["buckets"].pop(0)

        # print(self.services[service]['bucket_list'], json.dumps(self.services[service]['buckets'], indent = 1))

        return proc_return

    def create_query(self, service):

        # copy dictionary templates
        query = copy.deepcopy(self.proc_query)
        _range = copy.deepcopy(self.proc_range_time)
        _time_agg = copy.deepcopy(self.date_range_agg)
        _term_procname_agg = copy.deepcopy(self.term_procname_agg)
        _term_pid = copy.deepcopy(self.pid_agg)

        # populate the service name into the process aggregation name
        _term_procname_agg["aggs"][service] = _term_procname_agg["aggs"].pop("procname")

        # search the cmdline text field with the cmdline information and match the process name exactly
        # cmdline field is analyzed so it's being tested as such.
        if self.services[service]["cmdline"]:

            _proc_name = copy.deepcopy(self.proc_name_match_phrase)
            _cmdline = copy.deepcopy(self.proc_cmdline_query)

            _proc_name["match_phrase"]["system.process.name"]["query"] = self.services[service][
                "process_name"
            ]
            _cmdline["query_string"]["query"] = self.services[service]["cmdline"]

            query["query"]["bool"]["must"].extend([_proc_name, _cmdline])

            if self.services[service]["mode"] == "::":

                _term_procname_agg["aggs"][service]["terms"][
                    "field"
                ] = "system.process.cmdline.keyword"

        # search the process name only
        else:

            _proc_name = copy.deepcopy(self.proc_name_query_string)

            # checking if there's even a mode that is set and do a strict, trailing or leading match
            if self.services[service]["mode"]:

                if self.services[service]["mode"] == "strict":

                    _proc_name["query_string"]["query"] = self.services[service]["process_name"]

                elif self.services[service]["mode"] == "trailing":

                    _proc_name["query_string"]["query"] = "*{}".format(
                        self.services[service]["process_name"]
                    )

                elif self.services[service]["mode"] == "leading":

                    _proc_name["query_string"]["query"] = "{}*".format(
                        self.services[service]["process_name"]
                    )

                else:

                    _proc_name["query_string"]["query"] = "*{}*".format(
                        self.services[service]["process_name"]
                    )

            # absence of a mode will do a leading/trailing wildcard match *<name>*
            # good for finding all sorts of sub processes by the string
            else:

                _proc_name["query_string"]["query"] = "*{}*".format(
                    self.services[service]["process_name"]
                )

            query["query"]["bool"]["must"].append(_proc_name)

        # create to/from variables if there's a timesync offset

        if self.timesync_enable:

            timeoffset = datetime.datetime.utcnow() + self.time_delta

            _from = (timeoffset - datetime.timedelta(seconds=self.time_search)).isoformat()
            _start = timeoffset
            _to = timeoffset.isoformat()

        # otherwise create to/from variables based on now time
        else:

            _from = (
                datetime.datetime.utcnow() - datetime.timedelta(seconds=self.time_search)
            ).isoformat()
            _start = datetime.datetime.utcnow()
            _to = _start.isoformat()

        # load values into query range for @timestamp filter
        _range["range"]["@timestamp"]["from"] = _from
        _range["range"]["@timestamp"]["to"] = _to

        query["query"]["bool"]["filter"].append(_range)

        # drop micro seconds from time
        _start = _start - datetime.timedelta(microseconds=_start.microsecond)

        # drop all the seconds from time if less than 30 seconds, otherwise just subtract 30 seconds.
        # _start  =  _start - datetime.timedelta(seconds = _start.second) if _start.second < 30 else _start - datetime.timedelta(seconds = (_start.second - 30))

        number_of_buckets = 1
        # build 4x time range buckets at 30 seconds and append it to the query
        for x in range(number_of_buckets, 0, -1):

            key_range = {
                "from": (_start - datetime.timedelta(seconds=(self.query_window * x))).isoformat(),
                "to": (
                    _start - datetime.timedelta(seconds=(self.query_window * (x - 1)))
                ).isoformat(),
                "key": (_start - datetime.timedelta(seconds=(self.query_window * x))).isoformat(),
            }

            _time_agg["aggs"]["date_bucket"]["date_range"]["ranges"].append(key_range)

        # build top hit query and append it to the date bucket query
        _term_procname_agg["aggs"][service].update(_term_pid)
        _time_agg["aggs"]["date_bucket"].update(_term_procname_agg)

        # append aggregations to the full query
        query.update(_time_agg)

        return query, _to

    def fetch_proc(self, query):

        REQUEST_URL = "%s://%s:%s/%s/_search" % (
            self.proto,
            self.elastichost,
            self.elasticport,
            self.index,
        )

        HEADERS = {"Accept": "application/json"}

        try:

            resp = requests.get(REQUEST_URL, headers=HEADERS, data=json.dumps(query), timeout=6.0)

            resp.close()

            response = json.loads(resp.text)

        except Exception as e:

            return e

        return response

    def __init__(self, **kwargs):

        self.elastichost = None
        self.elasticport = "9200"
        self.beat = None
        self.verbose = None
        self.timesync_enable = None
        self.services = {}
        self.query_window = 60
        self.time_search = self.query_window * 10
        self.proto = "http"
        log_mode = "syslog"

        self.state_def = {
            "status_descr": "Not Running",
            "status": 0,
            "num_processes": 0,
            "failed": 1,
            "cpu_pct": 0,
            "memory_pct": 0,
            "memory_bytes": 0,
            "pid": None,
            "state": None,
            "start_time": None,
            "duration": None,
            "tested": None,
            "sub_services": [],
        }

        time_args = {
            "beat": None,
            "elastichost": None,
            "elasticport": None,
            "verbose": None,
            "sample_size": None,
            "elapse_time": None,
            "refresh": None,
        }

        for key, value in kwargs.items():

            if ("beat" in key) and (value):

                self.beat = value
                time_args["beat"] = value

            if ("elastichost" in key) and (value):

                self.elastichost = value
                time_args["elastichost"] = value

            if ("elasticport" in key) and (value):

                self.elasticport = value
                time_args["elasticport"] = value

            if ("verbose" in key) and (value):

                self.verbose = True
                time_args["verbose"] = value

            if ("sample_size" in key) and (value):
                time_args["sample_size"] = value

            if ("elapse_time" in key) and (value):
                time_args["elapse_time"] = value

            if ("refresh" in key) and (value):
                time_args["refresh"] = value

            if ("timesync_enable" in key) and (value):
                self.timesync_enable = True

            if ("query_window" in key) and (value):
                self.query_window = value

            if ("log_mode" in key) and (value):
                log_mode = value

            if ("services" in key) and (value):

                for service in value:

                    _proc_name = None
                    _service = None
                    cmdline = None
                    mode = None

                    # key that there's a cmdline field match
                    if "::" in service:

                        _proc_name, cmdline = service.split("::")
                        _service = cmdline
                        mode = "::"

                    # made up operator to not use leading/trailing wildcards
                    elif ">>" in service:

                        _proc_name, mode = service.split(">>")
                        _service = _proc_name

                    # made up operator to search cmdlne but not do an aggregate
                    elif "??" in service:
                        _proc_name, cmdline = service.split("??")
                        _service = cmdline

                    else:
                        _service, _proc_name = service, service

                    self.services[_service] = {
                        "process_name": _proc_name,
                        "cmdline": cmdline,
                        "buckets": [],
                        "procs": [],
                        "bucket_list": [],
                        "last_bucket": None,
                        "last_poll": None,
                        "changes": [],
                        "mode": mode,
                    }

        if self.timesync_enable:

            timesync.__init__(self, **time_args)

            # kick off a timesync
            self.time_delta

        logGenerator.__init__(self, self.elastichost, log_mode, self.beat)

        self.index = "log-systeminfo-*"

        self.proc_query = {
            "size": 0,
            "sort": {"@timestamp": "desc"},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"term": {"metricset.name": "process"}},
                        {"term": {"beat.name": self.beat}},
                    ],
                }
            },
        }

        self.proc_name_query_string = {
            "query_string": {"default_field": "system.process.name", "query": None}
        }

        self.proc_name_match_phrase = {"match_phrase": {"system.process.name": {"query": None}}}

        self.proc_cmdline_query = {
            "query_string": {
                "default_field": "system.process.cmdline",
                "query": None,
                "default_operator": "AND",
            }
        }

        self.proc_range_time = {"range": {"@timestamp": {"from": None, "to": None,}}}

        self.date_range_agg = {
            "aggs": {"date_bucket": {"date_range": {"field": "@timestamp", "ranges": []}}}
        }

        self.time_agg = {
            "aggs": {"date_bucket": {"date_histogram": {"field": "@timestamp", "interval": "30s"}}}
        }

        self.term_procname_agg = {
            "aggs": {
                "procname": {
                    "terms": {
                        "field": "system.process.name",
                        "size": 1000,
                        "order": {"_term": "desc"},
                    }
                }
            }
        }

        self.pid_agg = {
            "aggs": {
                "pid": {
                    "terms": {"field": "system.process.pid", "size": 1000},
                    "aggs": {
                        "cpu_pct": {"avg": {"field": "system.process.cpu.total.pct"}},
                        "memory_pct": {"avg": {"field": "system.process.memory.rss.pct"}},
                        "memory_bytes": {"avg": {"field": "system.process.memory.rss.bytes"}},
                        "state": {
                            "top_hits": {
                                "size": 1,
                                "docvalue_fields": [
                                    "system.process.state",
                                    "system.process.cpu.start_time",
                                ],
                                "_source": False,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                            }
                        },
                    },
                }
            }
        }

    def __del__(self):

        if self.timesync_enable:
            self.time_close()

    def close(self):

        if self.timesync_enable:
            self.time_close()


def main():

    parser = argparse.ArgumentParser(description="inSITE Service Availablity")

    sub = parser.add_subparsers(dest="manual or auto")
    sub.required = True

    sub_manual = sub.add_parser("manual", help="manual arguments")
    sub_manual.set_defaults(which="manual")
    sub_manual.add_argument(
        "-H",
        "--host",
        metavar="127.0.0.1",
        required=False,
        default="127.0.0.1",
        help="IP of the inSITE machine Elasticsearch. default (127.0.0.1)",
    )
    sub_manual.add_argument(
        "-B",
        "--beat",
        metavar="probe1",
        required=True,
        help="Beat name to query for of the probe reporting",
    )
    sub_manual.add_argument(
        "-L",
        "--log",
        metavar="stdout",
        required=False,
        default="stdout",
        help="Log Mode syslog or stdout. default (stdout)",
    )
    sub_manual.add_argument(
        "-W",
        "--window",
        metavar="90",
        required=False,
        default=90,
        help="The query window in seconds which to track processes. default (90)",
    )
    sub_manual.add_argument(
        "-T",
        "--timesync",
        required=False,
        default=False,
        action="store_true",
        help="Enable the timesync module to lock to the beat time source",
    )
    sub_manual.add_argument(
        "-R",
        "--refresh",
        metavar="300",
        required=False,
        default=300,
        help="Refresh the timesync in seconds. default (300)",
    )
    sub_manual.add_argument(
        "-v",
        "--verbose",
        required=False,
        default=True,
        action="store_false",
        help="Disable verbose information about the script and the timesync module",
    )
    sub_manual.add_argument(
        "-S",
        "--services",
        metavar="snmpd javaw.exe",
        nargs="+",
        required=False,
        help="Services to query for to check their health status",
    )

    sub_auto = sub.add_parser("auto", help="generate command automatically from file")
    sub_auto.set_defaults(which="auto")
    group = sub_auto.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-F",
        "--file",
        metavar="file",
        required=False,
        help="File containing parameter options (should be in json format)",
    )
    group.add_argument(
        "-D",
        "--dump",
        required=False,
        action="store_true",
        help="Dump a sample json file to use to test with",
    )
    group.add_argument(
        "-S",
        "--script",
        required=False,
        action="store_true",
        help="Use the dictionary in the script to feed the arguments",
    )

    args = parser.parse_args()

    if args.which == "manual":

        monitor = state_mon(
            beat=args.beat,
            elastichost=args.host,
            verbose=args.verbose,
            timesync_enable=args.timesync,
            log_mode=args.log,
            query_window=args.window,
            refresh=args.refresh,
            services=args.services,
        )

    elif args.which == "auto":

        if args.file:

            try:

                with open(os.getcwd() + "\\" + args.file, "r") as f:
                    mon_args = json.loads(f.read())

                monitor = state_mon(**mon_args)

            except Exception as e:
                print(e)

        if args.script:

            ## sample dictionary to use ##
            mon_args = {
                "beat": "DSS-FAT-MUX2",
                "elastichost": "10.9.1.63",
                "verbose": True,
                "timesync_enable": True,
                "log_mode": "stdout",
                "query_window": 90,
                "refresh": 300,
                "services": ["snmp", "rc.", "mysqld>>strict", "3480", "startpar"],
            }

            monitor = state_mon(**mon_args)

        if args.dump:

            json_file = {
                "beat": "IRM-M-FAT",
                "elastichost": "10.9.1.63",
                "verbose": True,
                "timesync_enable": False,
                "log_mode": "stdout",
                "query_window": 90,
                "refresh": 300,
                "services": ["mysqld.exe??mysqld", "javaw.exe??VistaLinkProServer"],
            }

            try:

                with open(os.getcwd() + "\\json_file.json", "w") as f:
                    f.write(json.dumps(json_file, indent=3))

            except Exception as e:
                print(e)

            quit()

    try:

        if monitor:

            inputQuit = False

            while inputQuit is not "q":

                for service in monitor.generate_state():
                    print(service)

                    for sub in service:
                        print("\t", sub)

                print("\n", monitor.summary)

                inputQuit = input("\nType q to quit or just hit enter: ")

            monitor.close()

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
