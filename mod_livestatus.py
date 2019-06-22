#!/usr/bin/env python
# -*- coding: utf-8 -*-

# modified from original mk livestatus
from __future__ import unicode_literals
from helper import unicode_clean
import socket
import json
import time


__all__ = ['Query', 'Socket']

WAIT_THROTTLE = 0.25

class Query(object):
    def __init__(self, conn, resource):
        self._conn = conn
        self._resource = resource
        self._columns = []
        self._filters = []
        self._ors = 0

    def call(self):
        try:
            data = bytes(str(self), 'utf-8')
        except TypeError:
            data = str(self)
        return self._conn.call(data)

    __call__ = call

    '''
    Might have to hardcore string query in future if this gets too ugly and hard to maintain
    :
        LQL1 = 'GET services\n' + \
        'Columns: host_name description state last_state_change plugin_output\n' + \
        'Filter: scheduled_downtime_depth = 0 \n'     + \
        'Filter: host_scheduled_downtime_depth = 0\n' + \
        'Filter: state    = 2 \n'
    '''

    def __str__(self):
        request = 'GET %s' % (self._resource)
        if self._columns and any(self._columns):
            request += '\nColumns: %s' % (' '.join(self._columns))
        if self._filters:
            for filter_line in self._filters:
                request += '\nFilter: %s' % (filter_line)
        if self._ors > 0:
            request += '\nOr: %s' % str(self._ors)
        request += '\nOutputFormat: json\nColumnHeaders: on\n'
        return request

    def columns(self, *args):
        self._columns = args
        return self

    def filter(self, filter_str):
        self._filters.append(filter_str)
        return self

    # TODO: this OR filter is a bit weird HAHA, needs a bit of work to add complex 'OR' filters if needed
    def or_num(self, num):
        self._ors = num
        return self



class Socket(object):
    def __init__(self, peer):
        self.peer = peer

    def __getattr__(self, name):
        return Query(self, name)

    def call(self, request):

        if len(self.peer) == 2:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # FIXME: Keep an eye on this on this while loop
        '''
        Need to see how the live status server is 'accept'ing the client
        Probably the socket accept is on the same main thread on server hence need to wait until the socket is also
        released from the server? Or there is a certain limit for client listen size?
        '''
        connected = False
        while not connected:
            try:
                s.connect(self.peer)
                connected = True
            except Exception:
                # try again
                time.sleep(WAIT_THROTTLE)

        s.sendall(request)
        s.shutdown(socket.SHUT_WR)
        raw_data = s.makefile().read()
        s.close()

        if not raw_data:
            return []

        data = unicode_clean(json.loads(raw_data))
        return [dict(zip(data[0], value)) for value in data[1:]]


