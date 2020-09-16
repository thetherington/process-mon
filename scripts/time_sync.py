import argparse
import concurrent.futures
import datetime
import json
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()


class timesync:
    @property
    def time_delta(self):

        if self.task_future.running():
            pass
            # print("task is running")

        elif (datetime.datetime.utcnow() - self.last_sync).total_seconds() > self.refresh:

            self.task_future = self.pool.submit(self.sync_time)

        return self.offset

    def fetch_sample(self):

        REQUEST_URL = "%s://%s:%s/%s/_search" % (
            self.proto,
            self.elastichost,
            self.elasticport,
            self.index,
        )

        HEADERS = {"Accept": "application/json"}

        try:

            resp = requests.get(
                REQUEST_URL, headers=HEADERS, data=json.dumps(self.cpu_query), timeout=3.0
            )

            resp.close()

            response = json.loads(resp.text)

        except Exception as e:

            return e

        return response

    def sync_time(self):

        time_db = []

        t_now = datetime.datetime.utcnow()

        def time_elapse():

            diff = datetime.datetime.utcnow() - t_now

            if diff.total_seconds() > self.elapse_time:
                return True

            return None

        # iterate while the db is less than samples and a new document is found in elapse_time.
        # exit if db has enough samples or time to find new document expires
        while len(time_db) < (self.sample_size + 2) and not time_elapse():

            if self.die:
                return None

            time.sleep(1)

            _data = self.fetch_sample()

            if isinstance(_data, dict):

                for hit in _data["hits"]["hits"]:

                    _time_set = {
                        "doc_id": hit["_id"],
                        "doc_time": hit["_source"]["@timestamp"],
                        "time_stamp": datetime.datetime.utcnow().isoformat()[:-3] + "Z",
                    }

                    update_db = None

                    # update the db if this is the first record
                    if len(time_db) == 0:
                        update_db = True

                    # if this is a new document found in the query not in the db
                    elif time_db[-1]["doc_id"] != hit["_id"]:
                        update_db = True

                    if update_db:

                        _d_time = datetime.datetime.strptime(
                            _time_set["doc_time"], "%Y-%m-%dT%H:%M:%S.%fZ"
                        )
                        _c_time = datetime.datetime.strptime(
                            _time_set["time_stamp"], "%Y-%m-%dT%H:%M:%S.%fZ"
                        )

                        delta = {"delta": _d_time - _c_time}

                        _time_set.update(delta)
                        time_db.append(_time_set)

                        # reset the wait time
                        t_now = datetime.datetime.utcnow()

                        if self.verbose:
                            print(_time_set)

        # process average and confidence if there's real samples than the invalid ones
        if len(time_db) > 2:

            # function is used to normalize the timedelta string with a simple negative string value
            # for consistent strptime parsing (ex -00:10:00)
            def timedelta_to_string(timedelta):
                total_seconds = timedelta.total_seconds()
                if total_seconds < 0:
                    timedelta_str = "-" + str(datetime.timedelta() - timedelta)
                else:
                    timedelta_str = str(timedelta)
                return timedelta_str

            sample_db = []

            # trim the first 2 inaccurate samples
            while len(time_db) > 2:
                sample_db.append(time_db.pop())

            # add all samples then divide by number of samples for avg
            self.offset = sum([doc["delta"] for doc in sample_db], datetime.timedelta()) / len(
                sample_db
            )

            # timedelta -> datetime - > datetime (minutes and seconds)
            _offset_datetime = datetime.datetime.strptime(
                timedelta_to_string(self.offset).strip("-"), "%H:%M:%S.%f"
            )

            _offset_ms = datetime.datetime.strptime(
                "%s.%s" % (_offset_datetime.minute, _offset_datetime.second), "%M.%S"
            )

            _percent = []
            for doc in sample_db:

                # timedelta -> datetime - > datetime (minutes and seconds)
                _delta_datetime = datetime.datetime.strptime(
                    timedelta_to_string(doc["delta"]).strip("-"), "%H:%M:%S.%f"
                )
                _delta_ms = datetime.datetime.strptime(
                    "%s.%s" % (_delta_datetime.minute, _delta_datetime.second), "%M.%S"
                )

                # (avg offset - sample delta) -> positive -> seconds -> percent of a minute -> percentage %
                _percent.append(int((abs(_offset_ms - _delta_ms).total_seconds() / 60) * 100))

            _confidence_compare = 100 - int(sum(_percent) / len(sample_db))
            _confidence_samples = 100 - int((len(sample_db) / self.sample_size) * 100)

            # sameples is not 0 then take 10th of number as percentage loss to the compare percentage
            self.confidence = (
                _confidence_compare
                if _confidence_samples == 0
                else _confidence_compare - (int(_confidence_samples / 10))
            )

            if self.verbose:
                print(
                    "percents",
                    _percent,
                    "confidence_compare",
                    _confidence_compare,
                    "confidence_samples",
                    _confidence_samples,
                )

            self.last_sync = datetime.datetime.utcnow()

            if self.verbose:

                for doc in sample_db:
                    print(doc["delta"])

                print("confidence", self.confidence)

        if self.verbose:

            print("average", self.offset)
            print(self.last_sync)

    def __init__(self, **kwargs):

        self.cpu_query = {
            "size": 1,
            "sort": {"@timestamp": "desc"},
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"metricset.name": {"query": "cpu"}}},
                        {"match_phrase": {"beat.name": {"query": None}}},
                    ]
                }
            },
        }

        self.index = "log-systeminfo-*"
        self.elastichost = None
        self.elasticport = "9200"
        self.proto = "http"
        self.offset = datetime.timedelta(seconds=0)
        self.confidence = None
        self.sample_size = 4
        self.elapse_time = 60
        self.die = None

        self.refresh = 200  # 86400
        self.last_sync = datetime.datetime.utcnow() - datetime.timedelta(seconds=self.refresh + 1)

        self.verbose = None

        self.pool = concurrent.futures.ThreadPoolExecutor()

        for key, value in kwargs.items():

            if ("beat" in key) and (value):
                self.cpu_query["query"]["bool"]["must"][-1]["match_phrase"]["beat.name"][
                    "query"
                ] = value

            if ("elastichost" in key) and (value):
                self.elastichost = value

            if ("elasticport" in key) and (value):
                self.elasticport = value

            if ("verbose" in key) and (value):
                self.verbose = True

            if ("sample_size" in key) and (value):
                self.sample_size = value

            if ("elapse_time" in key) and (value):
                self.elapse_time = value

        self.task_future = self.pool.submit(self.sync_time)

    def __del__(self):

        self.die = True
        self.pool.shutdown(wait=True)

    def time_close(self):

        self.die = True
        self.pool.shutdown(wait=True)


def main():

    parser = argparse.ArgumentParser(description="Time sync offset generator for inSITE probes")
    parser.add_argument(
        "-H", "--host", metavar="", required=False, help="Elasticsearch host to query against"
    )
    parser.add_argument("-P", "--port", metavar="", required=False, help="Elasticsearch port")
    parser.add_argument("-S", "--sample", metavar="", required=False, help="Sample size")
    parser.add_argument(
        "-T", "--elapse_time", metavar="", required=False, help="Time to timeout betwen samples"
    )
    parser.add_argument(
        "-B", "--beat", metavar="", required=True, help="Beatname to test data against"
    )

    args = parser.parse_args()

    sync = timesync(
        beat=args.beat,
        elastichost=args.host,
        elasticport=args.port,
        sample_size=args.sample,
        elapse_time=args.elapse_time,
        verbose=True,
    )

    inputQuit = False

    while inputQuit is not "q":

        print(sync.time_delta)

        inputQuit = input("\nType q to quit or just hit enter: ")

    sync.time_close()


if __name__ == "__main__":
    main()
