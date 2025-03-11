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
from pdef import SBIOSLEGACY_DEF
from ElementGui import *

from util import UTILS
utilities = UTILS()

try:
    import cPickle as pickle
except ImportError:
    import pickle         # fall back on Python version

# TXT Policy Generator Tool
# SBIOS Class - Policy Definition File Lists
#
class SBIOSLegacy( ElementGui ):

  CONST_TITLE = "Choose Hash File"
  CONST_WILDCARD = "Hash file (*.hash)|*.hash|" \
                   "All Files (*.*)|*.*"

  """__init__() - SBIOS class constructor"""
  def __init__( self ):
    self.sbiosPanelWidgets = []
    self.panelCreated = False

  #
  # create the SBIOS Panel
  #
  def createOrShowPanel(self, wx, listPanel, parent, pdef, statusBar):
    """createSbiosPanel - create the SBIOS Panel"""

    #print("createOrShowSbiosPanel panelCreated == %s" % (self.panelCreated))    # DBGDBG
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

    # Get the list corresponds to this element.
    currentList = self.pdef.getCurrentListObject()
    self.myIndex = len(currentList.ElementDefData)-1    # Just added the element, the last one should be the one.

    # create the Sbios Panel sizers
    #self.sbiosPanelSizer = wx.BoxSizer(wx.VERTICAL)
    sbiosGridSizer= wx.GridBagSizer(hgap=5, vgap=5)
    #sbiosHorizSizer = wx.BoxSizer(wx.HORIZONTAL)

    self.sbiosPanel = wx.Panel(parent, -1)
    self.sbiosPanel.SetSizer(sbiosGridSizer)

    sbiosLabelText1 = "SBIOS"
    sbiosLabelText2 = "Element"
    sbiosLabel1 = wx.StaticText(self.sbiosPanel, -1, sbiosLabelText1)
    sbiosLabel2 = wx.StaticText(self.sbiosPanel, -1, sbiosLabelText2)
    font = wx.Font( 18, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    sbiosLabel1.SetFont( font )
    sbiosGridSizer.Add( sbiosLabel1, pos=(0, 3))
    self.sbiosPanelWidgets.append(sbiosLabel1)
    sbiosLabel2.SetFont( font )
    sbiosGridSizer.Add( sbiosLabel2, pos=(0, 4))
    self.sbiosPanelWidgets.append(sbiosLabel2)

    self.typeLabel = wx.StaticText(self.sbiosPanel, label="Type")
    sbiosGridSizer.Add( self.typeLabel, pos=(1,3))
    self.sbiosPanelWidgets.append(self.typeLabel)
    self.typeEdit  = wx.TextCtrl( self.sbiosPanel, value="SBIOS", size=(40, -1))
    self.typeEdit.Enable( False )
    sbiosGridSizer.Add( self.typeEdit,  pos=(1,4))
    self.sbiosPanelWidgets.append(self.typeEdit)

    self.contolOptionsLabel = wx.StaticText(self.sbiosPanel, -1, "Control")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.contolOptionsLabel.SetFont( font )

    self.overridePsPolicy = wx.CheckBox(self.sbiosPanel, label="Override PS Policy")
    self.overridePsPolicy.Enable( False )

    #Note:  overridePsPolicy - control always disabled since there are no SBIOS specific controls - p12

    sbiosGridSizer.Add(self.contolOptionsLabel, pos=(0,14), span=(1,2), flag=wx.BOTTOM, border=5)
    sbiosGridSizer.Add(self.overridePsPolicy,   pos=(1,14), span=(1,2), flag=wx.BOTTOM, border=5)
    self.overridePsPolicy.Bind(wx.EVT_CHECKBOX, self.onOverridePsPolicy)
    self.sbiosPanelWidgets.append(self.contolOptionsLabel)
    self.sbiosPanelWidgets.append(self.overridePsPolicy)

    hashList = ['SHA1']
    self.hashAlgLabel = wx.StaticText(self.sbiosPanel, label="Hash Algorithm")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.NORMAL)
    self.hashAlgLabel.SetFont( font )
    sbiosGridSizer.Add(self.hashAlgLabel, pos=(0,20))
    self.sbiosPanelWidgets.append(self.hashAlgLabel)

    hashAlgEdit = wx.ComboBox( self.sbiosPanel, size=(75, -1), value="SHA1", choices=hashList, style=wx.CB_DROPDOWN )
    sbiosGridSizer.Add(hashAlgEdit, pos=(1,20))
    self.sbiosPanelWidgets.append(hashAlgEdit)

    self.fallbackFileLabel = wx.StaticText(self.sbiosPanel, label="Fallback\nHash")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.NORMAL)
    self.fallbackFileLabel.SetFont( font )
    sbiosGridSizer.Add( self.fallbackFileLabel, pos=(2,3))
    self.sbiosPanelWidgets.append(self.fallbackFileLabel)

    self.fallbackFileEdit  = wx.TextCtrl( self.sbiosPanel, value="", size=(150, -1))
    self.fallbackFileEdit.Enable(False)               # must use BROWSE to locate the fallback file
    fallbackFile = currentList.ElementDefData[self.myIndex].FallBackHashFile
    if (fallbackFile == "" or fallbackFile == None):
      fallbackFile = "Fallback.hash"
    self.fallbackFileEdit.AppendText(fallbackFile)
    sbiosGridSizer.Add( self.fallbackFileEdit,  pos=(2,4))
    self.sbiosPanelWidgets.append(self.fallbackFileEdit)
    currentList.ElementDefData[self.myIndex].FallBackHashFile = fallbackFile

    self.browseButton = wx.Button( self.sbiosPanel, -1, label="Browse")
    sbiosGridSizer.Add( self.browseButton, pos=(2,5))
    self.sbiosPanelWidgets.append(self.browseButton)
    self.browseButton.Bind(wx.EVT_BUTTON, self.onBrowseButtonClick)

    self.fallbackRemoveButton = wx.Button( self.sbiosPanel, -1, label="Remove")
    sbiosGridSizer.Add( self.fallbackRemoveButton, pos=(1,5))
    self.sbiosPanelWidgets.append(self.fallbackRemoveButton)
    self.fallbackRemoveButton.Bind(wx.EVT_BUTTON, self.onFallbackRemoveButtonClick)
    self.fallbackRemoveButton.Enable(True)

    self.addButton = wx.Button( self.sbiosPanel, -1,      label="    Add   ")
    sbiosGridSizer.Add( self.addButton, pos=(4,3))
    self.sbiosPanelWidgets.append(self.addButton)
    self.addButton.Bind(wx.EVT_BUTTON, self.onAddButtonClick)
    self.sbiosPanelWidgets.append(self.addButton)

    self.removeButton = wx.Button( self.sbiosPanel, -1,      label="  Remove  ")
    self.removeButton.Enable(False)                                           # disable since nothing to remove yet
    sbiosGridSizer.Add( self.removeButton, pos=(4,5))
    self.sbiosPanelWidgets.append(self.removeButton)
    self.removeButton.Bind(wx.EVT_BUTTON, self.onRemoveButtonClick)
    self.sbiosPanelWidgets.append(self.removeButton)

    self.hashListLabel = wx.StaticText(self.sbiosPanel, label="      Hash File List")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    self.hashListLabel.SetFont( font )
    sbiosGridSizer.Add( self.hashListLabel, pos=(3,4))
    self.sbiosPanelWidgets.append(self.hashListLabel)

    self.fileCntLabel = wx.StaticText(self.sbiosPanel, label="Number of Files")
    sbiosGridSizer.Add( self.fileCntLabel, pos=(5,3))
    self.sbiosPanelWidgets.append(self.fileCntLabel)
    self.fileCntEdit  = wx.TextCtrl( self.sbiosPanel, value="0", size=(40, -1))
    self.fileCntEdit.Enable( False )
    sbiosGridSizer.Add( self.fileCntEdit,  pos=(5,4))
    self.sbiosPanelWidgets.append(self.fileCntEdit)

    self.hashListBox = wx.TextCtrl( self.sbiosPanel, value="", size=(150, 120), style = wx.TE_MULTILINE)  # Note: add |wx.HSCROLL to get a horiz scroll bar
    # hashListBox must be enabled so can select items to remove
    self.hashListBox.Bind(wx.EVT_TEXT, self.onHashListBoxEdit)
    self.hashListBox.SetInsertionPoint(0)
    sbiosGridSizer.Add( self.hashListBox, pos=(4,4))
    self.sbiosPanelWidgets.append(self.hashListBox)

    self.sbiosPanelWidgets.append(self.sbiosPanel)
    #sbiosHorizSizer.Add(sbiosGridSizer,  0, wx.ALL, 5)
    #self.sbiosPanelSizer.Add(sbiosHorizSizer, 0, wx.ALL, 5)
    #parent.SetSizerAndFit(self.sbiosPanelSizer)
    parentSizer.Add(self.sbiosPanel)
    w,h = parentSizer.GetMinSize()
    parent.SetVirtualSize((w,h))
    parent.Layout()
    # call restorePanel to sync data to GUI
    self.restorePanel(currentList, pdef.MaxHashes)
    self.panelCreated = True

  def hidePanel(self):
    """hidePanel - hide the sbios panel"""

    for i in self.sbiosPanelWidgets:
      i.Hide()

  def showPanel(self):
    """showSbiosPanel - show the sbios panel"""

    if self.panelCreated:
      for i in self.sbiosPanelWidgets:
        i.Show()
      parentSizer = self.parent.GetSizer()
      w,h = parentSizer.GetMinSize()
      self.parent.SetVirtualSize((w,h))


  def setElementToDefaults(self):
    """setElementToDefaults - SBIOS_DEF"""

    currentList = self.pdef.getCurrentListObject()
    currentList.ElementDefData[self.myIndex].IncludeInList = False
    currentList.ElementDefData[self.myIndex].HashAlg      = 0
    currentList.ElementDefData[self.myIndex].Control      = 0
    currentList.ElementDefData[self.myIndex].NumbHashes   = 0
    currentList.ElementDefData[self.myIndex].CurrentView  = 0
    currentList.ElementDefData[self.myIndex].FallBackHashFile = ""
    currentList.ElementDefData[self.myIndex].SbiosFiles = []

  def onBrowseButtonClick(self, event):
    """onBrowseButtonClick - browse to a fallback hash file"""
    #self.StatusBar.SetStatusText("You clicked the Browse button")

    fileName = ''
    workdir = self.pdef.WorkingDirectory
    wildcard = "Hash file (*.hash)|*.hash|" \
               "All Files (*.*)|*.*"
    dlg = wx.FileDialog(self.parent, "Choose the fallback hash file", workdir, "", wildcard, wx.OPEN)

    abortFlag = False     # Set to True if Add dialogue doidn't complete successfully
    if dlg.ShowModal() == wx.ID_OK:
      filename = dlg.GetFilename()
      dirname  = dlg.GetDirectory()
    else:
      abortFlag = True    # abort after destroying the dialogue

    if(filename != ''):
      # validate that the specified hash file is properly formatted
      currentList = self.pdef.getCurrentListObject()
      result = utilities.verifyHashFile(os.path.join(dirname, filename), currentList.ElementDefData[self.myIndex].HashAlg)
      # Note: verifyHashFile() returns [FileValid, FileType], but only FileValid is used here
      if( result[0] == True):
        # Copy file into working directory
        if (dirname != workdir):
          if (os.path.exists(os.path.join(workdir, filename))) :
            cdlg = wx.MessageDialog(self.parent, filename+" already exists in working directory\nOverwrite file in working directory?", "Confirm Copy", wx.OK|wx.CANCEL|wx.ICON_QUESTION)
            if (cdlg.ShowModal() == wx.ID_OK):
              shutil.copyfile(os.path.join(dirname, filename), os.path.join(workdir, filename))
            else:
              self.StatusBar.SetStatusText( "Add cancelled" )
            cdlg.Destroy()
          else:
            shutil.copyfile(os.path.join(dirname, filename), os.path.join(workdir, filename))
        self.StatusBar.SetStatusText("Validated file %s." % (filename))
        self.fallbackFileEdit.ChangeValue(filename)
        currentList.ElementDefData[self.myIndex].FallBackHashFile = filename
        self.setListModified()
        self.fallbackRemoveButton.Enable(True)

    dlg.Destroy()

  def onFallbackRemoveButtonClick(self, event):
    """onFallbackRemoveButtonClick - delete the fallback hash file"""

    self.StatusBar.SetStatusText("Fallback hash file %s removed." % (self.fallbackFileEdit.GetValue()))
    self.fallbackFileEdit.ChangeValue("")
    currentList = self.pdef.getCurrentListObject()
    currentList.ElementDefData[self.myIndex].FallBackHashFile = ""
    self.setListModified()
    self.fallbackRemoveButton.Enable(False)

  # only supports adding files with the add button, not entering the names directly
  def onHashListBoxEdit(self, event):
    """onHashListBoxEdit"""
    print("in SBIOS::onHashListBoxEdit")       # DBGDBG

    # tell the user to add button and clear the field
    self.StatusBar.SetStatusText("Please clear the entry, then use the Add button to add hash files to the list")
    #self.hashListBox.Undo()
    #TODO: wxPython: onHashListBoxEdit - Clear() and Undo() both generate an event causing: RuntimeError: maximum recursion depth exceeded

  def onAddButtonClick(self, event):
    """onAddButtonClick - add a hash file to the list"""

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

    hashFileList = currentList.ElementDefData[self.myIndex].SbiosFiles
    hashFileList.append(filename)
    #print("new hashFileList = %s" % (hashFileList))   # DBGDBG

    # insert the new file into sbios.SbiosFiles
    self.setListModified()
    currentList.ElementDefData[self.myIndex].SbiosFiles = hashFileList
    currentList.ElementDefData[self.myIndex].NumbHashes = lineCnt
    #print("ElementDefData[self.myIndex].NumbHashes=%i, SbiosFiles = %s" % (currentList.ElementDefData[self.myIndex].NumbHashes, currentList.ElementDefData[self.myIndex].SbiosFiles))   # DBGDBG

    # since hashListBox.AppendText() generates an event to onHashListBoxEdit()
    # and since hashListBoxEdit has to be enabled so text can be selected for Remove
    # and direct text entry by the user into hashListBoxEdit is not supported due the complexity of validating it ...
    #
    # hashListBox.ChangeValue() doesn't generate an event but only takes a string, not a hashFileList which is a list ie '[]'
    # so form a single string containing everything in hashFileList and update hashListBox using ChangeValue(hashFileString)
    string = utilities.formStringFromListOfStrings(hashFileList)
    self.hashListBox.ChangeValue(string)

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
    hashFileList = currentList.ElementDefData[self.myIndex].SbiosFiles
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
          # decr sbios.NumbHashes & update NumberOfFiles widget
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
          currentList.ElementDefData[self.myIndex].SbiosFiles = hashFileList
          break
    else:
      self.StatusBar.SetStatusText("Selection %s not found. Please select only a single line" % (selection))    # DBGDBG

  def onOverridePsPolicy(self, event):
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    if(event.Checked() == True):
      currentList.ElementDefData[self.myIndex].Control = 1
    else:
      currentList.ElementDefData[self.myIndex].Control = 0

  def writeSbiosDef(self, sbiosDefData, f):
    """writeSbiosDef - write the Sbios Def to the specified file"""

    #print("writeSbiosLegacyDef dump")  # DBGDBG
    pickle.dump(sbiosDefData, f)       # write out the sbiosDefData object

  def setPanelToDefaults(self):
    """setPanelToDefaults - restore defaults to sbios panel widgets"""

    self.fallbackFileEdit.ChangeValue("")
    self.addButton.Enable(True)
    self.removeButton.Enable(False)
    self.fileCntEdit.ChangeValue("0")
    self.hashListBox.ChangeValue("")

  def restorePanel(self, currentList, maxHashes):
    """restorePanel - restore the SBIOS element panel from the specified PLIST_DEF"""

    print("restorePanel - SBIOS")       # DBGDBG
    # update Override PS Policy checkbox
    self.overridePsPolicy.SetValue(currentList.ElementDefData[self.myIndex].Control)
    listversion = str(currentList.ListVersionMajor)+'.'+str(currentList.ListVersionMinor)
    if listversion == '2.0':
      self.showV20Gui(True)
    else:
      self.showV20Gui(False)
    self.fallbackFileEdit.ChangeValue(currentList.ElementDefData[self.myIndex].FallBackHashFile)

    # If MaxHashes not 0, Only enable Add if < MaxHashes files
    numbHashes = currentList.ElementDefData[self.myIndex].NumbHashes
    flag = True
    if(maxHashes != 0):
      if(numbHashes >= maxHashes):
        flag = False                              # don't enable add
    self.addButton.Enable(flag)

    # enable remove if >0 hashes
    if(numbHashes > 0):
      self.removeButton.Enable(False)
    self.fileCntEdit.ChangeValue(str(numbHashes))

    # form a string from hashFileList and update hashListBox
    string = utilities.formStringFromListOfStrings(currentList.ElementDefData[self.myIndex].SbiosFiles)
    self.hashListBox.ChangeValue(string)

  #def setListModified(self):
  #  """setListModified - if list not modified yet, increment its rev cnt and set it to modified"""
  #
  #  currentList = self.pdef.getCurrentListObject()
  #  #print("Sbios setListModified - ListModified was %s" % (currentList.ListModified))  # DBGDBG
  #  if(currentList.ListModified == False):
  #    currentList.RevocationCounter += 1
  #    self.listPanel.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))   # update the GUI
  #    currentList.ListModified = True

