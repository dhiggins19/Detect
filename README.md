# Detect
Detect is host detection tool that I wrote to better understand Python threading, manual packet construction, and host enumeration. 
It sends a series of ICMP echo requests to all host addresses in a specified valid range.

# Usage
Automatically detecting the network range of the host running the program:
```
python detect.py -a
```

Manually specifying the range:
```
python detect.py -r 10.0.0.0/25
python detect.py -r 10.0.0.0/255.255.255.0
python detect.py -r 10.0.0.1-10.0.0.100
```

A command line reference is available with:
```
python detect.py -h
```