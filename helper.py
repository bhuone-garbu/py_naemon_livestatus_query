from datetime import datetime
import re

g_default_time_format = '%Y-%m-%d %H:%M:%S'


# borrowed
def unicode_clean(data):
    """
    This is to convert from unicode to str obj in python.!!!
    """
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [unicode_clean(item) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict):
        return {
            # CLEARFUl - data.iteritems() is not present in python v3
            unicode_clean(key): unicode_clean(value)
            for key, value in data.iteritems()
            }
    # if it's anything else, return it in its original form
    return data


def date_long_to_str(long_time, to_format=None):
    """
    function to parse a long time into a string format
    """
    format = g_default_time_format if to_format is None else to_format
    return datetime.fromtimestamp(long_time).strftime(format)


def date_from_str_to_long(str_time, from_format=None):
    """
    function to parse from time in string to seconds long
    """
    format = g_default_time_format if from_format is None else from_format
    return int(datetime.strptime(str_time, format).strftime("%s"))


def str_to_num(string):
    """
    Convert a numerical string represent into a number
    """
    try:
        return int(string)
    except ValueError:
        try:
            return float(string)
        except ValueError:
            return None


def contains_num(string):
    """
    check if a string contains some numbers
    """
    return bool(re.search(r'\d', string.strip()))