# inSITE Process Status Monitoring module

Process status monitoring module to provide status and information about a set of processes reported by the inSITE Probe.  

The process monitoring script has the below distinct ability and features:

1. Produce a Running or Not Running detection for each configured process.
2. CPU, Memory, Uptime information is collected for indexing indexed.
3. Auto detect and track sub processe.
4. Generate syslog for state changes for process status and changes.
5. Auto time synchronization to a probe local time.

## Minimum Requirements:

- inSITE Version 10.3 service pack 6
- Python3.7 (_already installed on inSITE machine_)
- Python3 Requests library (_already installed on inSITE machine_)

## Installation:

Installation of the status monitoring module requires copying two scripts into the poller modules folder:

1. Copy __process_monitor.py__ script to the poller python modules folder:
   ```
    cp scripts/process_monitor.py /opt/evertz/insite/parasite/applications/pll-1/data/python/modules
   ```
2. Copy __time_sync.py__ script to the poller python modules folder:
   ```
    cp scripts/time_sync.py /opt/evertz/insite/parasite/applications/pll-1/data/python/modules
   ```
3. Restart the poller application

## Configuration:

To configure a poller to use the module start a new python poller configuration outlined below

1. Click the create a custom poller from the poller application settings page
2. Enter a Name, Summary and Description information
3. Enter the host value in the _Hosts_ tab
4. From the _Input_ tab change the _Type_ to __Python__
5. From the _Input_ tab change the _Metric Set Name_ field to __procmonitor__
6. From the _Python_ tab select the _Advanced_ tab and enable the __CPython Bindings__ option
7. Select the _Script_ tab, then paste the contents of __scripts/poller_config.py__ into the script panel.

8. Locate the below section of the script for custom modifcations:
   ```
    mon_args = {
        "beat": host,
        "elastichost": "172.16.205.201",
        "timesync_enable": True,
        "refresh": 86400,
        "query_window": 90,
        "services": [
            "nginx",
            "mysqld>>strict",
            "python2.7::eventd",
            "python2.7::triton",
            "javaw.exe??VistaLinkProServer",
        ],
    }
    ```
    The process status monitoring module can be initialized with a custom set of parameters and processes to monitor.  
    
    Below are the required configuration options that need to be configured:

    - __elastichost__: IP address of the inSITE system containing the Elasticsearch instance.
    - __services__: A list of processes to test for.  Multiple processes can be listed in this array, and they can take on multiple formats to control how the processes are found and tracked.
      
      The following formats are supported and is explained using the above __"services": []__ examples:

      1. __nginx__: locates and tracks together and/or individually group of PIDs with process names containing the word "nginx". The service will be called "nginx" and can also have additional sub services named after their matched process names.

      2. __mysqld>>strict__: locates and tracks together a group of PIDs with a process name using the exact phrase "mysqld". The service will be named "mysqld"

      3. __python2.7::eventd__: locates and tracks __individually__ all PIDs with a process name having the exact phrase "python2.7" AND the cmdline arguments containing the word "eventd". The service will be named "eventd" and can contain sub services named after the full command line arguments.
      
      4. __javaw.exe??VistaLinkProServer__: locates and tracks together a group of PIDs with a process name having the exact phrase "javaw.exe" AND the cmdline arguments containing the word "VistaLinkProServer". The service will be named "VistaLinkProServer" and will not have any sub services.

    Below are optional configuration parameters which can be used to run the module:

    - __timesync_enable__: Set to _True_ to let the script detect what the local time is of the probe
    - __refresh__: Value in seconds to refresh the timesync feature to relock to the probe local time. 86400 = every 24 hours.
    - __query_window__: Time in seconds to detect when a process is no longer running from a running state.  This realistically cannot be less than 45 seconds based on how the probe reports data.

## Testing:

The process_monitor script can be ran manually from the shell using the following command
```
python process_monitor.py
```

Below is the _help_ output of the 

```
python process_monitor.py -h
```
```
usage: process_monitor.py [-h] {manual,auto} ...

inSITE Service Availablity

positional arguments:
  {manual,auto}
    manual       manual arguments
    auto         generate command automatically from file

optional arguments:
  -h, --help     show this help message and exit
```

The process_mon.py script supports two modes: __manual__ and __auto__.  

Below is the help output for using the command in __manual__ mode:

```
python process_monitor.py manual -h
```
```
usage: process_monitor.py manual [-h] [-H 127.0.0.1] -B probe1 [-L stdout]
                                 [-W 90] [-T] [-R 300] [-v]
                                 [-S snmpd javaw.exe [snmpd javaw.exe ...]]

optional arguments:
  -h, --help            show this help message and exit
  -H 127.0.0.1, --host 127.0.0.1
                        IP of the inSITE machine Elasticsearch. default
                        (127.0.0.1)
  -B probe1, --beat probe1
                        Beat name to query for of the probe reporting
  -L stdout, --log stdout
                        Log Mode syslog or stdout. default (stdout)
  -W 90, --window 90    The query window in seconds which to track processes.
                        default (90)
  -T, --timesync        Enable the timesync module to lock to the beat time
                        source
  -R 300, --refresh 300
                        Refresh the timesync in seconds. default (300)
  -v, --verbose         Disable verbose information about the script and the
                        timesync module
  -S snmpd javaw.exe [snmpd javaw.exe ...], --services snmpd javaw.exe [snmpd javaw.exe ...]
                        Services to query for to check their health status
```

Below is an example of running the command in manual mode to check processes (decoder and scaler) on a probe called "vue" with the timesync function enabled:

```
python process_monitor.py manual -H 10.9.1.63 -T -B vue -S decoder::decoder scaler::scaler
```

Output is shown as such:

```
decoder Status: Not Running (1), CPU: 0%, Memory: 0.0B, 0%, PIDs:  (0), Subs: 0, Duration: None
scaler Status: Not Running (1), CPU: 0%, Memory: 0.0B, 0%, PIDs:  (0), Subs: 0, Duration: None

 _summary_ Status: Not Running (2), CPU: 0%, Memory: 0.0B, 0%, PIDs:  (0), Subs: 2, Duration: None

Type q to quit or just hit enter: q
```

The auto mode has the ability to use an external json file to initialize the command. The _help_ output is below

```
python process_monitor.py auto -h
```
```
usage: process_monitor.py auto [-h] [-F file] [-D] [-S]

optional arguments:
  -h, --help            show this help message and exit
  -F file, --file file  File containing parameter options (should be in json
                        format)
  -D, --dump            Dump a sample json file to use to test with
  -S, --script          Use the dictionary in the script to feed the arguments
```

A sample json file can be generated with the -D command, and then can be used with the -F command.  

Below is the sample json file created:

```
{
   "beat": "IRM-M-FAT",
   "elastichost": "10.9.1.63",
   "verbose": true,
   "timesync_enable": false,
   "log_mode": "stdout",
   "query_window": 90,
   "refresh": 300,
   "services": [
      "mysqld.exe??mysqld",
      "javaw.exe??VistaLinkProServer"
   ]
}
```