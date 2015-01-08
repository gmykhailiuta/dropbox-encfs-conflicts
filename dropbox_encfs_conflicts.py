#!/usr/bin/python

# Copyright 2013 by x86dev.
# Copyright 2015 by Gennadiy Mykhailiuta - Updates, OOP refactoring.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributekhad in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import fnmatch
import getopt
import os
import re
import platform
import pprint
from cStringIO import StringIO
import subprocess
import sys
import uuid
import signal
#from Queue import Queue
#from threading import Thread

def print_help():
    print "Script for resolving synchronization conflicts of EncFS-encrypted files"
    print "within a Dropbox folder."
    print ""
    print "Usage: %s --encfs-enc-dir|-d <DIR>" % (os.path.basename(__file__),)
    print "       --encfs-mount-dir|-m <DIR> [--encfs-cmd <CMD>]"
    print "       [--encfs-password|-p <PASSWORD>] [--verbose|-v]"

    sys.exit(2)


# def do_stuff(q):
#   while True:
#     print q.get()
#     q.task_done()

# q = Queue(maxsize=0)
# num_threads = 4

# for i in range(num_threads):
#   worker = Thread(target=do_stuff, args=(q,))
#   worker.setDaemon(True)
#   worker.start()

# for x in range(100):
#   q.put(x)

# q.join()


class ConflictFilesRevealer:

    def __init__(self):
        self.aConflicts = []
        self.bVerbose = False
        self.sEncFsCmd = 'encfsctl'
        self.sEncFSPath = ''
        self.sEncFSMount = ''
        ## @todo: Add language detection for non-English Dropboxes
        #sConflictMsgRegEx = ' \(In Konflikt stehende Kopie von.*'
        self.sConflictMsgRegEx = ' \(.*conflicted copy.*'
        self.sConflictFileRegEx = '*conflicted*'


    def revealAll(self):
        for sRoot, aDirNames, aFilenames in os.walk(self.sEncFSPath):
            for sFilename in fnmatch.filter(aFilenames, self.sConflictFileRegEx):
                self.aConflicts.append(os.path.join(sRoot, sFilename))
        if len(self.aConflicts) == 0:
            print 'No conflicts found in "%s"' % (self.sEncFSPath,)
        else:
            iConflicts = len(self.aConflicts)
            for iCurConflict, sCurConflict in enumerate(self.aConflicts):
                print '\n=> Conflict %s/%s: "%s"' % (iCurConflict+1,iConflicts,sCurConflict)
                self.reveal(sCurConflict)

    def decode_path(self, sPathEnc):
        """
        Returns "" if decoding failed and real filepath otherwise
        """
        try:
            procEncFSCtl = subprocess.Popen([self.sEncFsCmd, "decode", \
                                             self.sEncFSPath, sPathEnc, \
                                             "--extpass=" + self.sEncFsPwd], \
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procEncFSCtlStdOut, procEncFSCtlStdErr = procEncFSCtl.communicate(input=self.sEncFsPwd + '\n')
            sFilename = procEncFSCtlStdOut.rstrip("\n")
            sStdErr = procEncFSCtlStdErr.rstrip("\n")
            if procEncFSCtl.returncode != 0 or sStdErr.find("err") > -1 or len(sFilename) == 0:
                raise Exception('Unable to extract decoded file name: "%s"' % (sStdErr,))
            
            return sFilename

        except OSError, e:
            print 'ERROR: %s' % (e,)
            return ""
        except Exception, e:
            print 'ERROR: %s' % (e,)
            return ""

    def reveal(self, sConflict):
        # Extract conflict message from encrypted file name.
        reConflictMsg = re.compile(self.sConflictMsgRegEx)
        aItems = reConflictMsg.findall(sConflict)
        if len(aItems) != 1:
            raise Exception("Unable to extract conflict message")
        sConflictMsg = aItems[0]
        # Cut off conflict message.
        aItems = re.split(self.sConflictMsgRegEx, sConflict)
        if len(aItems) != 2:
            raise Exception("Unable to separate conflict message from file name")
        # Cut off absolute path to get the relative one.
        aItems = aItems[0].split(self.sEncFSPath)
        if len(aItems) != 2:
            raise Exception("Unable to retrieve relative file path")
        sConflictFileEnc = aItems[1]
        sConflictPath = os.path.dirname(sConflictFileEnc)
        sConflictFileEnc.strip()
        # Decode the file using encfsctl.
        try:
            sConflictFileDec = ""
            bDecFailed = False
            while len(sConflictFileEnc) > 0 and len(sConflictFileDec) == 0:
                if self.bVerbose or bDecFailed:
                    print('Trying to decode path: "%s"' % (sConflictFileEnc,))
                sConflictFileDec = self.decode_path(sConflictFileEnc)
                if len(sConflictFileDec) > 0:
                    # decoding was successful
                    if self.bVerbose or bDecFailed:
                        print('Path decoded: "%s"' % (sConflictFileDec,))
                else:
                    # should try to decode parent path
                    print('Path decode failed: "%s"' % (sConflictFileEnc,))
                    bDecFailed = True
                    sConflictFileEnc = os.path.dirname(sConflictFileEnc)
            if bDecFailed:
                # path was not decoded. may be only parents found
                return
            sOrgFile = os.path.join(self.sEncFSMount, sConflictFileDec)
            print 'Original: "%s"' % (sOrgFile,)
            bOrgFileExists = os.path.isfile(sOrgFile)
            if bOrgFileExists:
                sOrgFileMine = sOrgFile + "." + str(uuid.uuid4());
                # Step 1: Rename the original file *directly* on the mount
                # (to not lose its contents thru eventual IV chaining). Use
                # a temporary name w/ an UUID.
                if self.bVerbose:
                    print 'mv "%s" -> "%s"' % (sOrgFile, sOrgFileMine)
                os.rename(sOrgFile, sOrgFileMine)
            # Append absolute path again.
            sConflictFileEnc = os.path.join(self.sEncFSPath, sConflictFileEnc)
            # Step 2: Rename the partly encoded conflict file directly
            # on the encrypted directory to match its original file name
            # before the conflict. This should re-enable reading its file
            # contents again.
            if self.bVerbose:
                print 'mv "%s" -> "%s"' % (sConflict, sConflictFileEnc)
            os.rename(sConflict, sConflictFileEnc)
            # Step 3: Rename the same file again, this time in the mounted
            # directory to reflect the conflicting state including the
            # original message.
            sOrgFileTheirs = sOrgFile + sConflictMsg
            if self.bVerbose:
                print 'mv "%s" -> "%s"' % (sOrgFile, sOrgFileTheirs)
            os.rename(sOrgFile, sOrgFileTheirs)
            if bOrgFileExists:
                # Step 4: Rename back my file to its original file name on
                # the mounted directory.
                if self.bVerbose:
                    print 'mv "%s" -> "%s"' % (sOrgFileMine, sOrgFile)
                os.rename(sOrgFileMine, sOrgFile)
        except OSError, e:
            print 'ERROR: %s' % (e,)
        except Exception, e:
            print 'ERROR: %s' % (e,)

    

def main():
    r = ConflictFilesRevealer()
    aOptions, aRemainder = getopt.getopt(sys.argv[1:], 'h:d:m:p:v', ['encfs-enc-dir=',
                                                                   'encfs-cmd=',
                                                                   'encfs-mount-dir=',
                                                                   'encfs-password=',
                                                                   'help',
                                                                   'verbose'
                                                                  ])
    for opt, arg in aOptions:
        if opt in ('-d', '--encfs-enc-dir'):
            r.sEncFSPath = arg
        elif opt in ('--encfs-cmd'):
            r.sEncFsCmd = arg
        elif opt in ('-m', '--encfs-mount-dir'):
            r.sEncFSMount = arg
        elif opt in ('-p', '--encfs-password'):
            r.sEncFsPwd = arg
        elif opt in ('-h', '-?', '--help'):
            print_help()
        elif opt in ('-v', '--verbose'):
            r.bVerbose = True
        else:
            print 'Unknown option "%s"' % (opt,)
            print_help

    if r.sEncFSPath == "":
        print "ERROR: Missing EncFS encrypted directory"
        print_help()
    elif r.sEncFSMount == "":
        print "ERROR: Missing mounted EncFS directory"
        print_help()

    ## @todo Offer an "--encfs-password-file" option!

    r.revealAll()

if __name__ == "__main__":
    main()

