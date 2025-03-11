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

try:
  import os
  import shutil
except ImportError:
  raise ImportError, "import OS failed"

from defines import DEFINES
from pdef import MLELEGACY_DEF
from ElementGui import *

from util import UTILS
utilities = UTILS()

try:
    import cPickle as pickle
except ImportError:
    import pickle         # fall back on Python version

# TXT Policy Generator Tool
# MLE Class - Policy Definition File Lists
#
class MLELegacy( ElementGui ):

  CONST_TITLE = "Choose Hash File"
  CONST_WILDCARD = "Hash file (*.hash)|*.hash|" \
                   "All Files (*.*)|*.*"

  """__init__() - MLE class constructor"""
  def __init__( self ):
    self.mlePanelWidgets = []
    self.panelCreated = False

  #
  # create the MLE Panel
  #
  def createOrShowPanel(self, wx, listPanel, parent, pdef, statusBar):
    """createMlePanel - create the List Panel"""

    #print("createOrShowPanel panelCreated == %s" % (self.panelCreated))    # DBGDBG
    # 1st time, create the panel
    # nth time, show the panel
    if(self.panelCreated == True):
      self.showPanel()
      return

    self.pdef = pdef
    self.parent = parent
    self.listPanel = listPanel
    self.StatusBar = statusBar
    parentSizer = parent.GetSizer()

    currentList = self.pdef.getCurrentListObject()
    self.myIndex = len(currentList.ElementDefData)-1    # Just added the element, the last one should be the one.

    # create the Mle Panel sizers
    #self.mlePanelSizer = wx.BoxSizer(wx.VERTICAL)
    self.mleGridSizer= wx.GridBagSizer(hgap=5, vgap=5)
    #self.mleHorizSizer = wx.BoxSizer(wx.HORIZONTAL)

    self.mlePanel = wx.Panel(parent, -1)
    self.mlePanel.SetSizer(self.mleGridSizer)

    mleLabelText1 = "MLE"
    mleLabelText2 = "Element"
    mleLabel1 = wx.StaticText(self.mlePanel, -1, mleLabelText1)
    mleLabel2 = wx.StaticText(self.mlePanel, -1, mleLabelText2)
    font = wx.Font( 18, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    mleLabel1.SetFont( font )
    self.mleGridSizer.Add( mleLabel1, pos=(0, 3))
    self.mlePanelWidgets.append(mleLabel1)
    mleLabel2.SetFont( font )
    self.mleGridSizer.Add( mleLabel2, pos=(0, 4))
    self.mlePanelWidgets.append(mleLabel2)

    typeLabel = wx.StaticText(self.mlePanel, label="Type")
    self.mleGridSizer.Add( typeLabel, pos=(1,3))
    self.mlePanelWidgets.append(typeLabel)
    typeEdit  = wx.TextCtrl( self.mlePanel, value="MLE", size=(40, -1))
    typeEdit.Enable( False )
    self.mleGridSizer.Add( typeEdit,  pos=(1,4))
    self.mlePanelWidgets.append(typeEdit)

    contolOptionsLabel = wx.StaticText(self.mlePanel, -1, "Control")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    contolOptionsLabel.SetFont( font )

    # override PS policy bit is applicable only if PO policy rules
    self.overridePsPolicy = wx.CheckBox(self.mlePanel, label="Override PS Policy")

    if(self.pdef.Rules == DEFINES.PoRules):
      self.overridePsPolicy.Enable( True )
    else:
      self.overridePsPolicy.Enable( False )

    self.mleGridSizer.Add(contolOptionsLabel, pos=(0,9), span=(1,2), flag=wx.BOTTOM, border=5)
    self.mleGridSizer.Add(self.overridePsPolicy,   pos=(1,9), span=(1,2), flag=wx.BOTTOM, border=5)
    self.overridePsPolicy.Bind(wx.EVT_CHECKBOX, self.onOverridePsPolicy)
    self.mlePanelWidgets.append(contolOptionsLabel)
    self.mlePanelWidgets.append(self.overridePsPolicy)

    # STPM is required bit ElementPolicyControl[1]
    #self.stmIsRequired = wx.CheckBox(self.mlePanel, label="STM is required")
    #self.mleGridSizer.Add(self.stmIsRequired, pos=(2,9), span=(1,2), flag=wx.BOTTOM, border=5)
    #self.stmIsRequired.Bind(wx.EVT_CHECKBOX, self.onOverridePsPolicy)  # TODO: add function to handle event.
    #self.mlePanelWidgets.append(self.stmIsRequired)
    
    hashList = ['SHA1']
    hashAlgLabel = wx.StaticText(self.mlePanel, label="Hash Algorithm")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    hashAlgLabel.SetFont( font )
    self.mleGridSizer.Add(hashAlgLabel, pos=(0,20))
    self.mlePanelWidgets.append(hashAlgLabel)

    hashAlgEdit = wx.ComboBox( self.mlePanel, size=(75, -1), value="SHA1", choices=hashList, style=wx.CB_DROPDOWN )
    self.mleGridSizer.Add(hashAlgEdit, pos=(1,20))
    self.mlePanelWidgets.append(hashAlgEdit)

    minSinitVersionLabel = wx.StaticText(self.mlePanel, label="Min SINIT Version: ")
    self.mleGridSizer.Add(minSinitVersionLabel, pos=(2,4))
    self.mlePanelWidgets.append(minSinitVersionLabel)
    minSinitVersion = pdef.SinitMinVersion                               # get current value
    currentList.ElementDefData[self.myIndex].SinitMinVersion = minSinitVersion

    self.minSinitVersionEdit  = wx.TextCtrl( self.mlePanel, value=str(minSinitVersion), size=(30, -1))
    self.mleGridSizer.Add( self.minSinitVersionEdit,  pos=(2,5))
    self.minSinitVersionEdit.Bind(wx.EVT_TEXT, self.onMinSinitVersion)
    self.mlePanelWidgets.append(self.minSinitVersionEdit)

    self.addButton = wx.Button( self.mlePanel, -1,      label="    Add   ")
    self.mleGridSizer.Add( self.addButton, pos=(4,3))
    self.mlePanelWidgets.append(self.addButton)
    self.addButton.Bind(wx.EVT_BUTTON, self.onAddButtonClick)
    self.mlePanelWidgets.append(self.addButton)

    self.removeButton = wx.Button( self.mlePanel, -1,      label="  Remove  ")
    self.mleGridSizer.Add( self.removeButton, pos=(4,5))
    self.mlePanelWidgets.append(self.removeButton)
    self.removeButton.Bind(wx.EVT_BUTTON, self.onRemoveButtonClick)
    self.mlePanelWidgets.append(self.removeButton)

    self.hashListLabel = wx.StaticText(self.mlePanel, label="      Hash File List")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.hashListLabel.SetFont( font )
    self.mleGridSizer.Add( self.hashListLabel, pos=(3,4))
    self.mlePanelWidgets.append(self.hashListLabel)

    self.fileCntLabel = wx.StaticText(self.mlePanel, label="Number of Files")
    self.mleGridSizer.Add( self.fileCntLabel, pos=(5,3))
    self.mlePanelWidgets.append(self.fileCntLabel)
    self.fileCntEdit  = wx.TextCtrl( self.mlePanel, value="0", size=(40, -1))
    self.fileCntEdit.Enable( False )
    self.mleGridSizer.Add( self.fileCntEdit,  pos=(5,4))
    self.mlePanelWidgets.append(self.fileCntEdit)

    hashFileList = ['']

    self.hashListBox = wx.TextCtrl( self.mlePanel, value="", size=(150, 120), style = wx.TE_MULTILINE)  # Note: add |wx.HSCROLL to get a horiz scroll bar
    # hashListBox must be enabled so can select items to remove
    self.hashListBox.Bind(wx.EVT_TEXT, self.onHashListBoxEdit)
    self.hashListBox.SetInsertionPoint(0)
    self.mleGridSizer.Add( self.hashListBox, pos=(4,4))
    self.mlePanelWidgets.append(self.hashListBox)

    self.mlePanelWidgets.append(self.mlePanel)

    #self.mleHorizSizer.Add(self.mleGridSizer,  0, wx.ALL, 5)
    #self.mlePanelSizer.Add(self.mleHorizSizer, 0, wx.ALL, 5)
    #parent.SetSizerAndFit(self.mlePanelSizer)
    parentSizer.Add(self.mlePanel)
    w,h = parentSizer.GetMinSize()
    parent.SetVirtualSize((w,h))
    print("parent sizer type = %s  size = %d, %d" %(type(parentSizer).__name__, w, h))
    parent.Layout()
    # call restorePanel to sync data to GUI
    self.restorePanel(currentList, pdef.MaxHashes)
    self.panelCreated = True

  def hidePanel(self):
    """hidePanel - hide the Mle panel"""

    for i in self.mlePanelWidgets:
      i.Hide()


  def showPanel(self):
    """showPanel - show the mle panel"""

    if self.panelCreated:
      for i in self.mlePanelWidgets:
          i.Show()
      parentSizer = self.parent.GetSizer()
      w,h = parentSizer.GetMinSize()
      self.parent.SetVirtualSize((w,h))


  def setElementToDefaults(self):
    """setElementToDefaults - MLE"""

    currentList = self.pdef.getCurrentListObject()
    currentList.ElementDefData[self.myIndex].IncludeInList = False
    currentList.ElementDefData[self.myIndex].HashAlg = 0
    currentList.ElementDefData[self.myIndex].SinitMinVersion = 0
    currentList.ElementDefData[self.myIndex].HashAlg = 0
    currentList.ElementDefData[self.myIndex].Control = 0
    currentList.ElementDefData[self.myIndex].NumbHashes = 0
    currentList.ElementDefData[self.myIndex].CurrentView = 0
    currentList.ElementDefData[self.myIndex].HashFiles = []

  def onOverridePsPolicy(self, event):
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    # set/clear bit 0 per MLE Dev Guide PolEltControl def
    if(event.Checked() == True):
      currentList.MleLegacyDefData[self.myIndex].Control = 1
    else:
      currentList.MleLegacyDefData[self.myIndex].Control = 0

  def onMinSinitVersion(self, event):
    value = event.GetString()
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    currentList.ElementDefData[self.myIndex].SinitMinVersion = int(value)
    #print("MLE::onMinSinitVersion - SinitMinVersion = %d" % (currentList.ElementDefData[self.myIndex].SinitMinVersion))  # DBGDBG

  # only supports adding files with the add button, not entering the names directly
  def onHashListBoxEdit(self, event):
    """onHashListBoxEdit"""
    #print("in MLE::onHashListBoxEdit")       # DBGDBG

    # tell the user to add button and clear the field
    self.StatusBar.SetStatusText("Please clear the entry, then use the Add button to add hash files to the list")
    #self.hashListBox.Undo()
    #TODO: wxPython: onHashListBoxEdit - Clear() and Undo() both generate an event causing: RuntimeError: maximum recursion depth exceeded

  def onAddButtonClick(self, event):
    """onAddButtonClick - add a hash file to the list"""

    workdir = self.pdef.WorkingDirectory
    filepath, filename = self.selectFile()
    
    if (filename == ''):
      # selectFile() operation has been cancelled.
      return
      
    # validate that the specified hash file is properly formatted
    currentList = self.pdef.getCurrentListObject()
    result = utilities.verifyHashFile(os.path.join(filepath, filename), currentList.ElementDefData[self.myIndex].HashAlg)
    # Note: verifyHashFile() returns [FileValid, FileType], but only FileValid is used here
    if( result[0] == False):
      return

    self.copyFile(filepath, filename)
    self.StatusBar.SetStatusText("Validated file %s." % (filename))

    # update the file count and enable the remove button
    lineCnt = currentList.ElementDefData[self.myIndex].NumbHashes
    #print("onAddButtonClick: was %i lines" % (lineCnt))   # DBGDBG
    lineCnt += 1

    # MaxHashes = 0 means there is no limit on the number of hash files allowed
    if(self.pdef.MaxHashes != 0):
      if(lineCnt > self.pdef.MaxHashes):
        self.StatusBar.SetStatusText("Only %d files can be added." % (self.pdef.MaxHashes))
        return

    #print("onAddButtonClick: now %i lines" % (lineCnt))   # DBGDBG
    self.fileCntEdit.ChangeValue(str(lineCnt))
    self.removeButton.Enable(True)

    hashFileList = currentList.ElementDefData[self.myIndex].HashFiles
    hashFileList.append(filename)
    #print("new hashFileList = %s" % (hashFileList))   # DBGDBG

    # insert the new file into mle.HashFiles
    self.setListModified()
    currentList.ElementDefData[self.myIndex].HashFiles = hashFileList
    currentList.ElementDefData[self.myIndex].NumbHashes = lineCnt
    #print("MleLegacyDefData.NumbHashes=%i, HashFiles = %s" % (currentList.MleLegacyDefData[DEFINES.DEFDATA_INDEX['SHA1']].NumbHashes, currentList.MleLegacyDefData[DEFINES.DEFDATA_INDEX['SHA1']].HashFiles))   # DBGDBG

    # since hashListBox.AppendText() generates an event to onHashListBoxEdit()
    # and since hashListBoxEdit has to be enabled so text can be selected for Remove
    # and direct text entry by the user into hashListBoxEdit is not supported due the complexity of validating it ...
    #
    # hashListBox.ChangeValue() doesn't generate an event but only takes a string, not a hashFileList which is a list ie '[]'
    # so form a single string containing everything in hashFileList and update hashListBox using ChangeValue(hashFileString)
    hashFileString = ''
    index = 0
    for eachString in hashFileList:
      if(index != 0):               # if not the 1st entry, need a LF before the new entry
        hashFileString += "\n"
      hashFileString += eachString
      index += 1
      #print("thisString=%s, hashFileString=%s" % (eachString, hashFileString))

    self.hashListBox.ChangeValue(hashFileString)

  def onRemoveButtonClick(self, event):
    """onRemoveButtonClick - remove the selected entry from the hash file list"""

    # confirm the remove
    dlg = wx.MessageDialog(None, "Confirm removal of selected file?", 'Confirm Remove', wx.YES_NO | wx.ICON_QUESTION)
    response = dlg.ShowModal()
    dlg.Destroy()

    if(response == wx.ID_NO):
      self.StatusBar.SetStatusText( "Remove cancelled" )
      return

    selection = self.hashListBox.GetStringSelection()
    self.StatusBar.SetStatusText("Removed selection %s" % (selection))

    # selection may not be a full line ... See if the selection is contianed in any of hashFileList's entries
    currentList = self.pdef.getCurrentListObject()
    hashFileList = currentList.ElementDefData[self.myIndex].HashFiles
    for entry in hashFileList:
      #print("entry=%s" % (entry))       # DBGDBG
      start = entry.find(selection)
      if(start != -1):          # -1 means not found, else find returns the starting index of selection
        #print("Found: %s at %i" % (selection, start))   # DBGDBG
        # entry was found, but was it a partial selection?
        if(selection not in hashFileList):   # is selection on the GUI in PDEF's hashFileList?
          # partial selection
          #print("Partial selection %s not found in %s." % (selection, hashFileList))    # DBGDBG
          self.StatusBar.SetStatusText("Please select the entire line")
          break
        else:
          # Full selection, so remove that entry
          # decr mle.NumbHashes & update NumberOfFiles widget
          fileCnt = int(self.fileCntEdit.GetValue())
          fileCnt -= 1
          self.fileCntEdit.ChangeValue(str(fileCnt))
          currentList.ElementDefData[self.myIndex].NumbHashes = fileCnt

          hashFileList.remove(selection)          # remove the selection from the PDEF object
          #print("hashFileList=%s" % (hashFileList))        # DBGDBG

          if(fileCnt == 0):                       # disable REMOVE if no more files left
            self.removeButton.Enable(False)
            self.hashListBox.ChangeValue('')
          else:
            # rebuild the content of hashFileEdit from hashFileList and update the screen with ChangeValue
            # to avoid generating an event and to clear the previous LF
            hashFileString = ''
            index = 0
            for eachString in hashFileList:
              if(index != 0):               # if not the 1st entry, need a LF before the new entry
                hashFileString += "\n"
              hashFileString += eachString
              index += 1
              #print("thisString=%s, hashFileString=%s" % (eachString, hashFileString))    # DBGDBG

            self.hashListBox.ChangeValue(hashFileString)

          #print("hashListBox=%s" % (self.hashListBox.GetValue())) # DBGDBG
          self.setListModified()
          currentList.ElementDefData[self.myIndex].HashFiles = hashFileList
          break
    else:
      self.StatusBar.SetStatusText("Selection %s not found. Please select only a single line" % (selection))    # DBGDBG

  def writeMleDef(self, mleDefData, f):
    """writeMleDef - write the Mle Def to the specified file"""

    #print("writeMleDef dump")  # DBGDBG
    pickle.dump(mleDefData, f)       # write out the mleDefData object

  def setPanelToDefaults(self):
    """setPanelToDefaults - restore defaults to mle panel widgets"""

    self.minSinitVersionEdit.ChangeValue("0")
    self.addButton.Enable(True)
    self.removeButton.Enable(False)
    self.fileCntEdit.ChangeValue("0")
    self.hashListBox.ChangeValue("")


  def restorePanel(self, currentList, maxHashes):
    """restorePanel - restore the MLE element panel from the specified PLIST_DEF"""

    print("restorePanel - MLE")   # DBGDBG
    # update Override PS Policy checkbox
    self.overridePsPolicy.SetValue(currentList.ElementDefData[self.myIndex].Control)
    listversion = str(currentList.ListVersionMajor)+'.'+str(currentList.ListVersionMinor)
    if listversion == '2.0':
      self.showV20Gui(True)
    else:
      self.showV20Gui(False)
    self.minSinitVersionEdit.ChangeValue(str(currentList.ElementDefData[self.myIndex].SinitMinVersion))

    # If MaxHashes not 0, Only enable Add if < MaxHashes files
    numbHashes = currentList.ElementDefData[self.myIndex].NumbHashes
    flag = True
    if(maxHashes != 0):
      if(numbHashes >= maxHashes):
        flag = False                              # don't enable add
    self.addButton.Enable(flag)

    # enable remove if >0 hashes
    flag = True
    if(numbHashes > 0):
      flag = False
    self.removeButton.Enable(flag)
    self.fileCntEdit.ChangeValue(str(numbHashes))

    # form a string from hashFileList and update hashListBox
    string = utilities.formStringFromListOfStrings(currentList.ElementDefData[self.myIndex].HashFiles)
    self.hashListBox.ChangeValue(string)

  #def setListModified(self):
  #  """setListModified - if list not modified yet, increment its rev cnt and set it to modified"""
  #
  #  currentList = self.pdef.getCurrentListObject()
  #  #print("Mle setListModified - ListModified was %s" % (currentList.ListModified))  # DBGDBG
  #  if(currentList.ListModified == False):
  #    currentList.RevocationCounter += 1
  #    self.listPanel.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))   # update the GUI
  #    currentList.ListModified = True

