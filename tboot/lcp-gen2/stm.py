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
from pdef import STM_DEF
from ElementGui import *

from util import UTILS
utilities = UTILS()

try:
    import cPickle as pickle
except ImportError:
    import pickle         # fall back on Python version

# TXT Policy Generator Tool
# STM Class - Policy Definition File Lists
#
class STM( ElementGui ):

  CONST_TITLE = "Choose Hash File"
  CONST_WILDCARD = "Hash file (*.hash)|*.hash|" \
                   "All Files (*.*)|*.*"

  """__init__() - STM class constructor"""
  def __init__( self, hashAlg):
    self.stmPanelWidgets = []
    self.panelCreated = False

    try:
      # reverse lookup of the hash algorithm name(key) for the given HashAlg value
      hashAlgName = (key for key,val in DEFINES.TPM_ALG_HASH.items() if (val == hashAlg)).next()
    except StopIteration:
      print("STM::__init__ - invalid hashAlg=%d" % (hashAlg))
      return

    self.myIndex = DEFINES.DEFDATA_INDEX[hashAlgName]

    #if( hashAlg == DEFINES.TPM_ALG_HASH['SHA256']):
    #  self.myIndex = DEFINES.DEFDATA_INDEX_SHA256
    #elif( hashAlg == DEFINES.TPM_ALG_HASH['SHA1']):
    #  self.myIndex = DEFINES.DEFDATA_INDEX_SHA1
    #else:
    #  print("STM::__init__ - invalid hashAlg=%d" % (hashAlg))

    self.myHashAlg = hashAlg

  #
  # create the STM Panel
  #
  def createOrShowPanel(self, wx, listPanel, parent, pdef, statusBar):
    """createPanel - create the List Panel"""

    #print("createOrShowStmPanel hashAlg=%d, panelCreated == %s" % (self.myHashAlg, self.panelCreated))    # DBGDBG
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

    # create the Stm Panel sizers
    #self.stmPanelSizer = wx.BoxSizer(wx.VERTICAL)
    self.stmGridSizer= wx.GridBagSizer(hgap=5, vgap=5)
    #self.stmHorizSizer = wx.BoxSizer(wx.HORIZONTAL)

    self.stmPanel = wx.Panel(parent, -1)
    self.stmPanel.SetSizer(self.stmGridSizer)

    stmLabelText1 = "STM"
    stmLabelText2 = "Element"
    stmLabel1 = wx.StaticText(self.stmPanel, -1, stmLabelText1)
    stmLabel2 = wx.StaticText(self.stmPanel, -1, stmLabelText2)
    font = wx.Font( 18, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    stmLabel1.SetFont( font )
    self.stmGridSizer.Add( stmLabel1, pos=(0, 3))
    self.stmPanelWidgets.append(stmLabel1)
    stmLabel2.SetFont( font )
    self.stmGridSizer.Add( stmLabel2, pos=(0, 4))
    self.stmPanelWidgets.append(stmLabel2)

    typeLabel = wx.StaticText(self.stmPanel, label="Type")
    self.stmGridSizer.Add( typeLabel, pos=(1,3))
    self.stmPanelWidgets.append(typeLabel)
    typeEdit  = wx.TextCtrl( self.stmPanel, value="STM", size=(40, -1))
    typeEdit.Enable( False )
    self.stmGridSizer.Add( typeEdit,  pos=(1,4))
    self.stmPanelWidgets.append(typeEdit)

    contolOptionsLabel = wx.StaticText(self.stmPanel, -1, "Control")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    contolOptionsLabel.SetFont( font )

    # override PS policy bit is applicable only if PO policy rules
    self.overridePsPolicy = wx.CheckBox(self.stmPanel, label="Override PS Policy")

    if(self.pdef.Rules == DEFINES.PoRules):
      self.overridePsPolicy.Enable( True )
    else:
      self.overridePsPolicy.Enable( False )

    self.stmGridSizer.Add(contolOptionsLabel, pos=(0,9), span=(1,2), flag=wx.BOTTOM, border=5)
    self.stmGridSizer.Add(self.overridePsPolicy,   pos=(1,9), span=(1,2), flag=wx.BOTTOM, border=5)
    self.overridePsPolicy.Bind(wx.EVT_CHECKBOX, self.onOverridePsPolicy)
    self.stmPanelWidgets.append(contolOptionsLabel)
    self.stmPanelWidgets.append(self.overridePsPolicy)

    hashAlgStr = self.getHashAlgName()
    if hashAlgStr == None:
      print("createOrShowStmPanel - invalid myHashAlg=%d" % (self.myHashAlg))

    hashAlgLabel = wx.StaticText(self.stmPanel, label="Hash Algorithm")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    hashAlgLabel.SetFont( font )
    self.stmGridSizer.Add(hashAlgLabel, pos=(0,20))
    self.stmPanelWidgets.append(hashAlgLabel)

    hashAlgEdit = wx.TextCtrl( self.stmPanel, size=(75, -1), value=hashAlgStr )
    hashAlgEdit.Enable(False)
    self.stmGridSizer.Add(hashAlgEdit, pos=(1,20))
    self.stmPanelWidgets.append(hashAlgEdit)

    self.addButton = wx.Button( self.stmPanel, -1,      label="    Add   ")
    self.stmGridSizer.Add( self.addButton, pos=(4,3))
    self.stmPanelWidgets.append(self.addButton)
    self.addButton.Bind(wx.EVT_BUTTON, self.onAddButtonClick)

    self.removeButton = wx.Button( self.stmPanel, -1,      label="  Remove  ")
    self.removeButton.Enable(False)
    self.stmGridSizer.Add( self.removeButton, pos=(4,5))
    self.stmPanelWidgets.append(self.removeButton)
    self.removeButton.Bind(wx.EVT_BUTTON, self.onRemoveButtonClick)

    hashListLabel = wx.StaticText(self.stmPanel, label="      Hash File List")
    font = wx.Font( 10, wx.FONTFAMILY_DEFAULT, wx.NORMAL, wx.BOLD)
    hashListLabel.SetFont( font )
    self.stmGridSizer.Add( hashListLabel, pos=(3,4))
    self.stmPanelWidgets.append(hashListLabel)

    fileCntLabel = wx.StaticText(self.stmPanel, label="Number of Files")
    self.stmGridSizer.Add( fileCntLabel, pos=(5,3))
    self.stmPanelWidgets.append(fileCntLabel)
    self.fileCntEdit  = wx.TextCtrl( self.stmPanel, value="0", size=(40, -1))
    self.fileCntEdit.Enable( False )
    self.stmGridSizer.Add( self.fileCntEdit,  pos=(5,4))
    self.stmPanelWidgets.append(self.fileCntEdit)
    hashFileList = ['']

    self.hashListBox = wx.TextCtrl( self.stmPanel, value="", size=(150, 120), style = wx.TE_MULTILINE)  # Note: add |wx.HSCROLL to get a horiz scroll bar
    # hashListBox must be enabled so can select items to remove
    self.hashListBox.Bind(wx.EVT_TEXT, self.onHashListBoxEdit)
    self.hashListBox.SetInsertionPoint(0)
    self.stmGridSizer.Add( self.hashListBox, pos=(4,4))
    self.stmPanelWidgets.append(self.hashListBox)

    self.stmPanelWidgets.append(self.stmPanel)

    #print("STM createPanel - len(Widgets)=%d" % (len(self.stmPanelWidgets)))  #DBGDBG
    #self.stmHorizSizer.Add(self.stmGridSizer,  0, wx.ALL, 5)
    #self.stmPanelSizer.Add(self.stmHorizSizer, 0, wx.ALL, 5)
    #parent.SetSizerAndFit(self.stmPanelSizer)
    parentSizer.Add(self.stmPanel)
    w,h = parentSizer.GetMinSize()
    parent.SetVirtualSize((w,h))
    parent.Layout()
    # call restorePanel to sync data to GUI
    self.restorePanel(currentList, pdef.MaxHashes)
    self.panelCreated = True

  def hidePanel(self):
    """hidePanel - hide the Stm panel"""
    #print("STM hidePanel - hashAlg=%d, len(Widgets)=%d" % (self.myHashAlg, len(self.stmPanelWidgets)))  #DBGDBG
    for i in self.stmPanelWidgets:
      i.Hide()

  def showPanel(self):
    """showPanel - show the stm panel"""
    #print("STM showPanel - hashAlg=%d, len(Widgets)=%d" % (self.myHashAlg, len(self.stmPanelWidgets)))  #DBGDBG
    if self.panelCreated:
      for i in self.stmPanelWidgets:
        i.Show()
      parentSizer = self.parent.GetSizer()
      w,h = parentSizer.GetMinSize()
      self.parent.SetVirtualSize((w,h))


  def setElementToDefaults(self):
    """setElementToDefaults - STM"""

    currentList = self.pdef.getCurrentListObject()
    currentList.ElementDefData[self.myIndex].IncludeInList = False
    currentList.ElementDefData[self.myIndex].HashAlg = self.myHashAlg
    currentList.ElementDefData[self.myIndex].Control = 0
    currentList.ElementDefData[self.myIndex].NumbHashes = 0
    currentList.ElementDefData[self.myIndex].CurrentView = 0
    currentList.ElementDefData[self.myIndex].HashFiles = []

  def onOverridePsPolicy(self, event):
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()
    # set/clear bit 0 per STM Dev Guide PolEltControl def
    if(event.Checked() == True):
      currentList.ElementDefData[self.myIndex].Control = 1
    else:
      currentList.ElementDefData[self.myIndex].Control = 0

  def onMinSinitVersion(self, event):
    value = event.GetString()
    currentList = self.pdef.getCurrentListObject()
    self.setListModified()

  # only supports adding files with the add button, not entering the names directly
  def onHashListBoxEdit(self, event):
    """onHashListBoxEdit"""
    #print("in STM::onHashListBoxEdit")       # DBGDBG

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

    hashFileList = currentList.ElementDefData[self.myIndex].HashFiles
    hashFileList.append(filename)
    #print("new hashFileList = %s" % (hashFileList))   # DBGDBG

    # insert the new file into stm.HashFiles
    self.setListModified()
    currentList.ElementDefData[self.myIndex].HashFiles = hashFileList
    currentList.ElementDefData[self.myIndex].NumbHashes = lineCnt
    #print("StmDefData[self.myIndex].NumbHashes=%i, HashFiles = %s" %
    # (currentList.ElementDefData[self.myIndex].NumbHashes, currentList.ElementDefData[self.myIndex].HashFiles))   # DBGDBG

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
          # decr stm.NumbHashes & update NumberOfFiles widget
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


  def writeStmDef(self, stmDefData, f):
    """writeStmDef - write the Stm Def to the specified file"""

    print("writeStmDef dump, hashAlg=%d" % (self.myHashAlg))  # DBGDBG
    pickle.dump(stmDefData, f)       # write out the stmDefData object

  def setPanelToDefaults(self):
    """setPanelToDefaults - restore defaults to stm panel widgets"""

    self.addButton.Enable(True)
    self.removeButton.Enable(False)
    self.fileCntEdit.ChangeValue("0")
    self.hashListBox.ChangeValue("")

  def restorePanel(self, currentList, maxHashes):
    """restorePanel - restore the STM element panel from the specified PLIST_DEF"""

    print("restorePanel - STM")   # DBGDBG
    # update Override PS Policy checkbox
    self.overridePsPolicy.SetValue(currentList.ElementDefData[self.myIndex].Control)
    listversion = str(currentList.ListVersionMajor)+'.'+str(currentList.ListVersionMinor)
    if listversion == '2.0':
      self.showV20Gui(True)
    else:
      self.showV20Gui(False)

    # If MaxHashes not 0, Only enable Add if < MaxHashes files
    numbHashes = currentList.ElementDefData[self.myIndex].NumbHashes
    flag = True
    if(maxHashes != 0):
      if(numbHashes >= maxHashes):
        flag = False                              # don't enable add
    self.addButton.Enable(flag)

    # enable remove if >0 hashes
    flag = False
    if(numbHashes > 0):
      flag = True
    self.removeButton.Enable(flag)
    self.fileCntEdit.ChangeValue(str(numbHashes))

    # form a string from hashFileList and update hashListBox
    string = utilities.formStringFromListOfStrings(currentList.ElementDefData[self.myIndex].HashFiles)
    self.hashListBox.ChangeValue(string)

  #def setListModified(self):
  #  """setListModified - if list not modified yet, increment its rev cnt and set it to modified"""
  #
  #  currentList = self.pdef.getCurrentListObject()
  #  #print("Stm setListModified - ListModified was %s" % (currentList.ListModified))  # DBGDBG
  #  if(currentList.ListModified == False):
  #    currentList.RevocationCounter += 1
  #    self.listPanel.revocationCountEdit.ChangeValue(str(currentList.RevocationCounter))   # update the GUI
  #    currentList.ListModified = True


  # the last function in the file doesn't show up in the scope list in Understand for some reason!
  def stub(self):
    pass
