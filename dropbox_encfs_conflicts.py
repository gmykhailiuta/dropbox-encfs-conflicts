#!/usr/bin/python

# Copyright 2013 by x86dev.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
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

def print_help():
    print "Script for resolving synchronization conflicts of EncFS-encrypted files"
    print "within a Dropbox folder."
    print ""
    print "Usage: %s --encfs-enc-dir|-d <DIR>" % (os.path.basename(__file__),)
    print "       --encfs-mount-dir|-m <DIR> [--encfs-cmd <CMD>]"
    print "       [--encfs-password|-p <PASSWORD>] [--verbose|-v]"

    sys.exit(2)

def main(argv):

    # Sensible defaults.
    fVerbose = False

    sSystem = platform.system()
    if sSystem == "Linux":
        sEncFsCmd  = 'encfsctl'
    elif sSystem == "Windows":
        sEncFsCmd  = 'encfsctl.exe'
    else:
        print 'WARNING: Unknown system "%s"' % (sSystem,)
        # Don't quit -- command can be overriden by "--encfs-cmd".

    sEncFSPath = ''
    sEncFSMount = ''

    aOptions, aRemainder = getopt.getopt(sys.argv[1:], 'h:d:m:p:v', ['encfs-enc-dir=',
                                                                   'encfs-cmd=',
                                                                   'encfs-mount-dir=',
                                                                   'encfs-password=',
                                                                   'help',
                                                                   'verbose'
                                                                  ])
    for opt, arg in aOptions:
        if opt in ('-d', '--encfs-enc-dir'):
            sEncFSPath = arg
        elif opt in ('--encfs-cmd'):
            sEncFsCmd = arg
        elif opt in ('-m', '--encfs-mount-dir'):
            sEncFSMount = arg
        elif opt in ('-p', '--encfs-password'):
            sEncFsPwd = arg
        elif opt in ('-h', '-?', '--help'):
            print_help()
        elif opt in ('-v', '--verbose'):
            fVerbose = True
        else:
            print 'Unknown option "%s"' % (opt,)
            print_help

    if sEncFSPath == "":
        print "ERROR: Missing EncFS encrypted directory"
        print_help()
    elif sEncFSMount == "":
        print "ERROR: Missing mounted EncFS directory"
        print_help()

    ## @todo Offer an "--encfs-password-file" option!

    ## @todo: Add language detection for non-English Dropboxes
    #sRegEx = ' \(In Konflikt stehende Kopie von.*'
    sRegEx = ' \(.*conflicted copy.*'

    ## @todo: Check existence of encrypted dir + mount.

    print 'Path: %s' % (sEncFSPath,)

    aConflicts = []
    for sRoot, aDirNames, aFilenames in os.walk(sEncFSPath):
      for sFilename in fnmatch.filter(aFilenames, '*conflicted*'):
          aConflicts.append(os.path.join(sRoot, sFilename))

    if len(aConflicts) == 0:
        print 'No conflicts found in "%s"' % (sEncFSPath,)
    else:
        for sCurConflict in aConflicts:
            try:
                print '\n=> Conflict file: "%s"' % (sCurConflict,)
                # Extract conflict message from encrypted file name.
                reConflictMsg = re.compile(sRegEx)
                aItems = reConflictMsg.findall(sCurConflict)
                if len(aItems) != 1:
                    raise Exception("Unable to extract conflict message")
                sConflictMsg = aItems[0]
                # Cut off conflict message.
                aItems = re.split(sRegEx, sCurConflict)
                if len(aItems) != 2:
                    raise Exception("Unable to separate conflict message from file name")
                # Cut off absolute path to get the relative one.
                aItems = aItems[0].split(sEncFSPath)
                if len(aItems) != 2:
                    raise Exception("Unable to retrieve relative file path")
                sConflictFileEnc = aItems[1]
                sConflictPath = os.path.dirname(sConflictFileEnc)
                sConflictFileEnc.strip() 
                # Decode the file using encfsctl.
                try:
                    procEncFSCtl = subprocess.Popen([sEncFsCmd, "decode", \
                                                     sEncFSPath, sConflictFileEnc, \
                                                     "--extpass=" + sEncFsPwd], \
                                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    procEncFSCtlStdOut, procEncFSCtlStdErr = procEncFSCtl.communicate(input=sEncFsPwd + '\n')
                    sConflictFileDec = procEncFSCtlStdOut.rstrip("\n")
                    if procEncFSCtl.returncode != 0 or procEncFSCtlStdOut.find("err") > -1 or len(sConflictFileDec) == 0:
                        raise Exception('Unable to extract decoded file name: "%s%s"' % (procEncFSCtlStdOut,procEncFSCtlStdErr))
                    sOrgFile = os.path.join(sEncFSMount, sConflictFileDec)
                    sOrgFileMine = sOrgFile + "." + str(uuid.uuid4());
                    print 'Original file: "%s"' % (sOrgFile,)
                    # Step 1: Rename the original file *directly* on the mount
                    # (to not lose its contents thru eventual IV chaining). Use
                    # a temporary name w/ an UUID.
                    print 'mv "%s" -> "%s"' % (sOrgFile, sOrgFileMine)
                    os.rename(sOrgFile, sOrgFileMine)
                    # Append absolute path again.
                    sConflictFileEnc = os.path.join(sEncFSPath, sConflictFileEnc)
                    # Step 2: Rename the partly encoded conflict file directly
                    # on the encrypted directory to match its original file name
                    # before the conflict. This should re-enable reading its file
                    # contents again.
                    print 'mv "%s" -> "%s"' % (sCurConflict, sConflictFileEnc)
                    os.rename(sCurConflict, sConflictFileEnc)
                    # Step 3: Rename the same file again, this time in the mounted
                    # directory to reflect the conflicting state including the
                    # original message.
                    sOrgFileTheirs = sOrgFile + sConflictMsg
                    print 'mv "%s" -> "%s"' % (sOrgFile, sOrgFileTheirs)
                    os.rename(sOrgFile, sOrgFileTheirs)
                    # Step 4: Rename back my file to its original file name on
                    # the mounted directory.
                    print 'mv "%s" -> "%s"' % (sOrgFileMine, sOrgFile)
                    os.rename(sOrgFileMine, sOrgFile)
                except OSError, e:
                    print 'ERROR: %s' % (e,)
                except Exception, e:
                    print 'ERROR: %s' % (e,)

                # Move file
            except AttributeError, e:
                print 'ERROR: %s' % (e,)

if __name__ == "__main__":
   main(sys.argv[1:])

