# Copyright (c) 2015-2016 Western Digital Corporation or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.
#
#   Author: Chaitanya Kulkarni <chaitanya.kulkarni@hgst.com>
#
"""
Logger for NVMe Test Framwwork:-

"""
import sys


class TestNVMeLogger(object):
    """ Represents Logger for NVMe Testframework.  """
    def __init__(self, log_file_path):
        """ Logger setup
            - Args:
                log_file_path : path to store the log.
        """
        self.terminal = sys.stdout
        self.log = open(log_file_path, "w")

    def write(self, log_message):
        """ Logger setup
            - Args:
                log_message: string to write in the log file.
            - Returns:
                None
        """
        self.terminal.write(log_message)
        self.log.write(log_message)

    def flush(self):
        """ This flush method is needed for python 3 compatibility.
            this handles the flush command by doing nothing.
            you might want to specify some extra behavior here.
        """
        pass
