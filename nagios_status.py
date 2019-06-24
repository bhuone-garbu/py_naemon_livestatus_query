# library to query any naemon installed as long as the tcp connection is allowed

from mod_livestatus import Socket
from abc import ABCMeta
from ast import literal_eval
from pprint import pprint

import helper
import json
import re

'''Update here if we change the ports on central naemon'''
g_sites = {
    'offsite': 6558,
    'onsite': 6559,
    'local_server': 6556,
    'global': 6557
}

TAG_SEPARATOR = '_'

class Naemon(object):
    """An abstract struct for all the additional naemon monitoring server we have and
    as I keep adding more functionality
    """
    __metaclass__ = ABCMeta

    def __init__(self, port, site):
        self._address = '10.30.2.23'
        self._port = port
        self._site = site

    def __get_socket(self):
        # Just assigned a socket, does not connect yet ...
        return Socket((self._address, self._port))

    def get_monitored_hosts(self):
        """
        Get all the hosts that are currently monitored on this site.
        """
        # TODO: add ability request more custom column fields
        qs = self.__get_socket().hosts.columns('host_name', 'host_address')
        return qs.call()

    def get_configured_services_list(self):
        """
        Get all the name of the services that are currently configured to be recorded into eigen historian
        """
        qs = self.__get_socket().services.columns('description')
        qs.filter('custom_variables ~~ %s' % "TAGNAME ." )
        return list(set([item['description'] for item in qs.call()]))

    def get_monitored_services_on_hosts(self, hosts=[]):
        """
        Retrieve all the services that are being checked in this site per host
        """
        # TODO: add ability request more custom column fields
        qs = self.__get_socket().services.columns('host_name', 'host_address', 'description')

        if len(hosts) > 0:
            for name in hosts:
                qs.filter("host_name ~~ .*" + "%s" % name.strip() + "*")
            qs.or_num(len(hosts))

        return qs.call()

    def get_perf_data(self):
        qs = self.__get_socket().services.columns('perf_data')

        pprint( qs.call() )


    def get_current_plugin_state(self, service_name, convert_time_to_str, hosts=[]):
        """
        Retrieve the current state of a service. All hosts are selected unless specified
        """
        # TODO: add ability request more custom column fields
        qs = self.__get_socket().services.columns('host_name', 'description', 'plugin_output', 'state', 'last_check')
        qs.filter("service_description ~~ .*" + "%s" % service_name.strip() + '*')

        if len(hosts) > 0:
            for name in hosts:
                qs.filter("host_name ~~ .*" + "%s" % name.strip() + "*")
            qs.or_num(len(hosts))

        data = qs.call()

        # convert long time to string
        if convert_time_to_str:
            for item in data:
                item['last_check'] = helper.date_long_to_str(item['last_check'])

        # if need to print data then call
        return data

    def get_current_configured_eigen_tag_value(self, service_name):
        """
        MAKE SURE THAT THE 'service_name' THAT GETS PASSED IS CONFIGURED HAS 'custom_variables' so that
        request to retrieve the service information does not get wasted on unnecessary calls

        Retrieves the dictionary of custom variables and returns a map of meta and trend information for each tags
        This is where the configuration is done on how the write the values to historian (influx)
        """
        qs = self.__get_socket().services.columns('host_name', 'plugin_output', 'last_check', 'custom_variables')
        qs.filter("service_description =~ %s" % service_name.strip())

        # filter result when something is wrong with the plugin itself - greedy regex
        qs.filter("plugin_output !~~ ^.*?\b(plugin timed out|unknown)\b.*$")

        data = qs.call()

        # this what we return from this function
        eigen_tag_values = {
            'trend': {},
            'metainfo': {}
        }

        # ''' BLACK MAGIC 2 - THE UGLY WITCHCRAFT in its 4th design iteration, looking to wreck havoc on holy land
        for item in data:

            # only if there is custom variables
            if len(item['custom_variables']) is not 0:
                custom_vars = item['custom_variables']
                # more validations
                try:
                    # looks for suffix over tagvalueindex - throw error if misconfigured
                    meta_info = literal_eval(custom_vars['MORE_TAG_INFO'])
                    # for key in more_tag_info:
                    #    # info                          # unit                  #description
                    #    meta_info[key.lower().strip()] = [ more_tag_info[key][1], more_tag_info[key][2] ]

                except (ValueError, KeyError):
                    try:
                        value_index = custom_vars['TAG_VALUE_INDEX']
                        meta_info = [ custom_vars['TAG_UNIT'], custom_vars['TAG_DESCRIP'] ]
                    except KeyError:
                        # for some reason, not enough info is present to make eigen data tag meta info and data
                        # so skip to the next item in data
                        continue

                # lets build the bloddy tagname now and its meta info now - JeezzzC!!!
                host_name = item['host_name'].replace('-', ' ').lower()
                host_name = re.sub(r'\s+', '-', host_name).strip()

                # generate the first part of the tagname
                main_tag = self._site + TAG_SEPARATOR + host_name + TAG_SEPARATOR + custom_vars['TAGNAME']

                # capture all the numeric values from the plugin output string in a list, includes decimal
                nums = re.findall(r'[-+]?\d*\.\d+|\d+', item['plugin_output'])

                timestamp = item['last_check']
                if type(meta_info) == dict:
                    for suffix in meta_info:
                        gen_tag_name = main_tag + TAG_SEPARATOR + suffix.lower()
                        gen_tag_value_index = int(meta_info[suffix][0]) - 1
                        eigen_tag_values['trend'][gen_tag_name] =\
                            {
                                'status': 'OK', # Always OK ?
                                'timestamp': timestamp,
                                'value': float(nums[gen_tag_value_index])
                            }
                        eigen_tag_values['metainfo'][gen_tag_name] = \
                            {
                                'units': meta_info[suffix][1],
                                'descrip': meta_info[suffix][2]
                            }
                else:
                    eigen_tag_values['trend'][main_tag] = \
                        {
                            'status': 'OK', # Always OK?
                            'timestamp': timestamp,
                            'value': float(nums[int(value_index) - 1])
                        }
                    eigen_tag_values['metainfo'][main_tag] = \
                        {
                            'units': custom_vars['TAG_UNIT'],
                            'descrip': custom_vars['TAG_DESCRIP']
                        }
        # '''
        return eigen_tag_values


class NaemonInst(Naemon):
    '''CREATE the Naemon object instance FROM HERE
    Create new procedures or use/override inherited attributes'''

    def __init__(self, name, port):
        self._name = name

        # this way of overriding super is not supported in Python v3
        super(NaemonInst, self).__init__(port, name)

    def get_site_name(self):
        return self._name

    # Forgot what the UNIQUE function I was going to implement which was the main reason
    # for subclassing the Naemon object into here .. for now makes no sense


# -------------------
# utility methods for Naemon
# -------------------
def get_naemon_instance(name):
    try:
        site = g_sites[name.lower()]
        return NaemonInst(name, site)
    except KeyError:
        print ("No naemon instance exists called: '%s' in Eigen" % name)
        return


# TODO make a csv file generator - maybe borrow from the commented lines below
def dictionary_to_csv(dictionary, filename):
    pass






# all the functions below are deprecated --- too complex for no good reason
# will be a headache to maintain for others
# leaving it for here now until I am sure I don't want to borrow anything from here

########  ######## ########  ########  ########  ######     ###    ######## ######## ########
##     ## ##       ##     ## ##     ## ##       ##    ##   ## ##      ##    ##       ##     ##
##     ## ##       ##     ## ##     ## ##       ##        ##   ##     ##    ##       ##     ##
##     ## ######   ########  ########  ######   ##       ##     ##    ##    ######   ##     ##
##     ## ##       ##        ##   ##   ##       ##       #########    ##    ##       ##     ##
##     ## ##       ##        ##    ##  ##       ##    ## ##     ##    ##    ##       ##     ##
########  ######## ##        ##     ## ########  ######  ##     ##    ##    ######## ########


def check_tag_name_template(service_name, print_tag=False, to_upper=False):
    """
    Proof-of-concept
    Can be used to test.py/see how the tag name that gets generated will look like
    based on the service name configuration.
    Not the best way of doing it but for proof-of-concept
    """
    # a tuple to store initial tagname, suffix (if present) and index value: (str, str, num)

    info = {}

    with open('service_lookup.json', 'r') as service_file:
        # need to check on this object hook or report if misconfigured dictionary file
        config_lookup = json.load(service_file, object_hook=helper.unicode_clean)

        try:
            # removing black slashes or anything
            filtered_name = service_name.replace('\\', '').lower()
            strip = re.sub(r'\s+', '_', filtered_name).strip()
            # look all the keys if found, return this key immediately - expecting to be only one there
            found = [k for k in config_lookup['list'].keys() if k in strip][0]

            # check for suffix
            if config_lookup['list'][found] == "more":
                suffix_dict = config_lookup['suffix'][found]
                for suffix in suffix_dict:
                    __simplified_info(found, suffix, config_lookup, info)
            else:
                __simplified_info(found, '', config_lookup, info)

            if print_tag:
                print ("Tag template for service: '%s'" % service_name)
                print (__change_caps_list([tags for tags in info.keys()], to_upper))
            return info

        except IndexError:
            print ("Unable to retrieve parsing info for: '%s'" % service_name)
            print ("Please check 'service_lookup.json' config file. Tag name template cannot be generated!!!")
            return

    # TODO add a check and report an exception if service config file not present


def __simplified_info(lookup_key, suffix, config_lookup, into_here):
    # won't make sense if used as standalone function
    key = ".".join(filter(None,["<site>", "<host>", lookup_key, suffix]))
    parse_info = config_lookup["suffix"][lookup_key] if len(suffix) > 0 else config_lookup["list"][lookup_key]
    into_here[key] = parse_info


# might move some of these to the helper file
def __change_caps_list(str_list, to_upper):
    # won't make sense if used as standalone function
    return [t.upper() if to_upper else t for t in str_list]


def parse_plugin_output(service_name, plugin_output):
    """
    Proof of concept
    Now parse the plugin output
    """
    print ("\nParsing the output: '%s'" % plugin_output)

    if not helper.contains_num(plugin_output):
        print ("The plugin output does not have any numeric data")
        return

    info = check_tag_name_template(service_name)
    if info is None:
        # Error message should be generated from the check_tag_name_template function
        return

    # capture all the numeric values from the plugin output string in a list, includes decimal
    nums = re.findall(r'[-+]?\d*\.\d+|\d+', plugin_output)
    if len(nums) == 1:
        # TODO if there is only one number then no need to do a lookup
        pass

    parsed_info = {
        #tag: #parsed value
    }

    for k in info.keys():
        #tag = (('<site>', '<host>', '<service_key>', '<suffix>'), [<index>, '<unit>', '<description>'])

        index, unit, desc = info[k]
        value = helper.str_to_num(nums[index-1])
        parsed_info[k] = value

        #debug
        print ("Value: {0}{1} | Description: '{2}'".format(value,unit, desc))

    return parsed_info



# some of these broken ideas below might be used later in a refined way
'''
def test_script2(type):
	conn = get_channel_socket(type)
	
	qs = conn.services.columns('host_address','host_name', 'service_description')# \
		#.filter('host_name = BPAZIP21-3 service_description = CPU Load')
		#.filter('service_description = CPU Load')
	data = json.dumps(qs.call(), separators=(',',':'))
	dict = json.loads(data)

	# num_rows = 0	
	
	global g_write_header
	
	# open in write new or append mode
	if g_write_header is True:
		with open('unix_list.csv', 'wb') as csv_file:
			write_to_file(csv_file, dict, type)
	else:
		with open('unix_list.csv', 'ab') as csv_file:
			write_to_file(csv_file, dict, type)

def write_to_file(csv_file, dict, type):
	global g_write_header
	writer = csv.writer(csv_file, delimiter = ',', lineterminator='\n')

	if type == 'local':
		site = 'EigenInfra'
	elif type == 'onshore':
		site = 'ONSHOREPIN'
	else:
		site = 'OFFSHOREPIN'

	for item in dict:
		if g_write_header is True:
		#	if num_rows == 0:
			header = item.keys()
			
			header = ['Facility', 'Host_address', 'Host_name', 'Service_check', 'Usage']
			
			# rewriting the header
			#header.pop()
			#header = ['Facility'] + header + ['service_check', 'Usage', 'Sample output']
			writer.writerow(header)
			#	num_rows += 1

			# set back the header flag to never use write it again
			g_write_header = False
		
		values = item.values()
		check = values.pop()
		usage = get_unit(check)
		
		values = [site] + values + [check,usage]

		writer.writerow(values)
	
def get_unit(service_name):

	##getting unit of measurement finder/parser - currently very naive way of doing
	##due to rush

	if 'cpu' in service_name.lower() or \
		'disk' in service_name.lower() or \
		'load' in service_name.lower():
		return 'percentage (%)'
	elif 'drive' in service_name.lower():
		if 'root' in service_name.lower() or 'varlog' in service_name.lower() or 'builder' in service_name.lower():
			return 'megabyte (MB)'
		else:
			return 'percentage (%)'
	elif 'used' in service_name.lower():
		return 'megabyte (MB)'
	elif 'memory' in service_name.lower():
		return 'gigabyte(GB)/ megabyte(MB)'
	elif 'apc' in service_name.lower() and 'pdu' in service_name.lower():
		return 'amps'
	elif 'ping' in service_name.lower() or 'alive' in service_name.lower():
		return 'millisecond (ms)'
	elif 'procs' in service_name.lower() or 'processes' in service_name.lower():
		return 'count'
	elif 'apc' in service_name.lower() and 'ats' in service_name.lower():
		return 'humidity %'
	else:
		return 'unknown'
'''

# if __name__ == "__main__":

# test_script2('local')
# test_script2('onshore')
# test_script2('offshore')

# get_host('')
# get_host(['BPAZIP21-3'])
#	nagios_data = get_service_output()

# debug
#	print json.dumps(nagios_data, indent=3, separators=(',',':'))

# small subset test.py
#	for data in nagios_data:
#		subbed = re.sub(r'\s+', '_', data['description'].strip())
#		for k in np.g_service_lookup.keys():
#			if k in subbed.lower():
#				np.gather_data_from_service(data['description'],
#					data['plugin_output'])		

#	np.gather_data_from_service('something cpu load','4 CPU, average load 2.2% < 80% : OK')


#	np.build_json_body()
#	print len(np.g_meta_data), len(np.g_data_point)
