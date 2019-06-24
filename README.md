
# Naemon and mklivestatus with Python.

## Background
Naemon is a network monitoring tool based on the Nagios 4 core. I've used it for work and personal project in the past. Unlike others, not everyone has the money or resource to buy/pay for expensive monitoring suites that exists. But we still need to somehow do our job. I had to monitor a lot of client servers and machines - at least ~10-15 servers that needed health check on almost real-time basis. Naemon was like a "poor man's monitoring system" for me. However, I was able to add/run ad-hoc monitoring scripts on any linux servers and monitor them using Naemon, and proved to be very valuable. I was monitoring CPU load check, memory, space, temperature, webapps stats, application stats, etc... and almost anything as long as I could write and come up with a script. My main scripting language were mostly Bash and Python. With such flexibility, naemon sometimes proved to be even better than some "other" paid system.
https://www.naemon.org/

With the amount of data from Naemon, there are lots of possiblity of looking at the data and analysing. I started creating this project so that I can query any Naemon instances directly using Python as long as the TCP ports are opened by the responding servers with the help of Livestatus query on Naemon.
https://www.naemon.org/documentation/usersguide/livestatus.html


## UPDATE
`nagios_status.py` is just a start. I truely regret not using a git as I lost some of the vital lines of code and files, and I cannot seem to find anything anywhere to recover it. Better late than never - I'm adding this on my GitHub so I can come back/look at this later. Having said that, this current version of file (`nagios_status.py`) still works as long as the settings are tweaked appropriately.

Also, it was written for Pyton **v2** intentionally.
