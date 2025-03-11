#!/usr/bin/python
#  Copyright (c) 2013, Intel Corporation. All rights reserved.

# using print() built infunction, disable print statement
from __future__ import print_function

#
# wxPython is not part of the standard Python distribution and has to be downloaded and installed separately.
# Tell the user that wxPython is required but has not been found
#
try:
  import wx
except ImportError:
  raise ImportError, "Please download the appropriate version of wxPython from www.wxpython.org"


import os
import shutil

from defines import DEFINES

#
# TXT Policy Generator Tool
#
class ElementGui( object ):

  CONST_TITLE = "Choose file"
  CONST_WILDCARD = "All Files (*.*)|*.*"

  def __init__( self ):
    pass


  # isElementType() compares the name argument to the class name and stored hash algorithm name
  # to find a matching element.
  # The name argument should have a format of <element name>-<hash alg name>
  def isElementType(self, name):
    result = False
    type = name.split('-')
    if len(type) != 2:
      result = False
    else:
      elementType, hashAlg = type
      if hashAlg == 'LEGACY':
        if elementType in self.__class__.__name__:
          result = True
      else:
        if elementType in self.__class__.__name__ and self.myHashAlg == DEFINES.TPM_ALG_HASH[hashAlg]:
          result = True
    return result


  def getHashAlgName(self):
    if 'Legacy' in self.__class__.__name__:
      name = 'SHA1-LEGACY'
    else:
      try:
        name = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == self.myHashAlg)).next()
      except StopIteration:
        name = None
    return name


  # getName() is intended to get the class name from the classes defined in pdef.py
  #
  #def getName(self):
  #  if 'Legacy' in self.__class__.__name__:
  #    hashname = 'LEGACY'
  #    name = self.__class__.__name__.split('Legacy')[0] + '-' + hashname
  #  else:
  #    try:
  #      hashname = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == self.myHashAlg)).next()
  #      name = self.__class__.__name__.split('_DEF')[0] + '-' + hashname
  #    except StopIteration:
  #      name = None
  #  return name

  def selectFile(self):
    """onAddButtonClick - This code is common to all elements to select a file
       and copy file into current working directory if the file doesn't exist """

    filepath = ''
    filename = ''
    workdir = self.pdef.WorkingDirectory

    dlg = wx.FileDialog(self.parent, self.CONST_TITLE, workdir, "", self.CONST_WILDCARD, wx.FD_OPEN)

    if dlg.ShowModal() == wx.ID_CANCEL :
      self.StatusBar.SetStatusText( "Add cancelled" )
    else:
      filename = dlg.GetFilename()
      filepath = dlg.GetDirectory()

    dlg.Destroy()
    # return null string indicate file select cancelled.
    return filepath, filename


  def copyFile(self, filepath, filename):
    workdir = self.pdef.WorkingDirectory

    if (filepath != workdir):
      if (os.path.exists(os.path.join(workdir, filename))) :
        dlg = wx.MessageDialog(self.parent, filename+" already exists in working directory\nOverwrite file in working directory?", "Confirm Copy", wx.OK|wx.CANCEL|wx.ICON_QUESTION)

        if (dlg.ShowModal() == wx.ID_OK):
          shutil.copyfile(os.path.join(filepath, filename), os.path.join(workdir, filename))
          self.StatusBar.SetStatusText( "File copied" )
        else:
          self.StatusBar.SetStatusText( "File copy aborted" )

        dlg.Destroy()
      else:
        shutil.copyfile(os.path.join(filepath, filename), os.path.join(workdir, filename))

        
  def setListModified(self):
    """setListModified - if list not modified yet, increment its rev cnt and set it to modified"""

    currentList = self.pdef.getCurrentListObject()

    #print("PCONF setListModified - ListModified was %s" % (currentList.ListModified))  # DBGDBG
    if(currentList.ListModified == False):
      currentList.RevocationCounter += 1
      self.listPanel.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))   # update the GUI
      currentList.ListModified = True
    self.pdef.Modified = True


  def showV20Gui(self, enable):
    if enable:
      self.overridePsPolicy.Show()
    else:
      self.overridePsPolicy.Hide()


  def enableDisableOverridePsPolicy(self, value):
    """enableDisableOverridePsPolicy widget"""

    self.overridePsPolicy.Enable(value)
